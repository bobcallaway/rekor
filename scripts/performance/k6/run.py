#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Run one isolated k6 comparison point and capture matching pprof artifacts."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request

p = argparse.ArgumentParser()
p.add_argument('name')
p.add_argument('--cache', choices=['true','false'], default='true')
p.add_argument('--checkpoints', default='128')
p.add_argument('--rate', default='100')
p.add_argument('--duration', type=int, default=30)
p.add_argument('--mode', default='mixed')
p.add_argument('--vus', default='300')
p.add_argument('--proof-concurrency', default='32')
p.add_argument('--poll-interval', default='100ms')
a = p.parse_args()
if a.duration < 20:
    p.error('--duration must be at least 20 seconds for a steady-state profile')
root = Path(__file__).resolve().parent
out = root/'results'/a.name
out.mkdir(parents=True, exist_ok=False)
env = dict(os.environ, PERF_DIR=str(root), CACHE_STH=a.cache, CHECKPOINT_ENTRIES=a.checkpoints, PROOF_CONCURRENCY=a.proof_concurrency, POLL_INTERVAL=a.poll_interval)
compose = ['docker','compose','-p','rekorperf','-f',str(root/'compose.yaml')]
def run(args, **kw):
    return subprocess.run(args, env=env, check=True, **kw)
def fetch(url, path, timeout=30):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        path.write_bytes(response.read())

run(compose+['up','-d','mysql','trillian','signer'])
# Otherwise every fresh tree remains ACTIVE and adds signer/DB background work
# to later runs, confounding comparisons even though requests use a fresh tree.
run(['docker','run','--rm','--network','rekorperf_default','-v',str(root)+':/bench:ro',
     '--entrypoint','/bench/freeze-trees','rekor-rekor-server:latest'])
run(compose+['up','-d','--force-recreate','rekor'])
deadline = time.monotonic()+120
while True:
    try:
        with urllib.request.urlopen('http://localhost:13000/api/v1/log',timeout=2) as response:
            json.loads(response.read())
        break
    except Exception:
        if time.monotonic()>deadline: raise
        time.sleep(1)

metadata = dict(vars(a), timestamp=time.time())
metadata['binary_sha256'] = hashlib.sha256((root/'rekor-server').read_bytes()).hexdigest()
metadata['docker_info'] = run(['docker','info','--format','{{.NCPU}} CPUs, {{.MemTotal}} bytes RAM'],capture_output=True,text=True).stdout.strip()
metadata['go_version'] = run(['go','version'],capture_output=True,text=True).stdout.strip()
metadata['images'] = run(['docker','inspect','rekor-rekor-server:latest','rekor-trillian-log-server:latest','rekor-trillian-log-signer:latest','gcr.io/trillian-opensource-ci/db_server:v1.4.0','grafana/k6:1.0.0','--format','{{json .RepoTags}} {{.Id}}'],capture_output=True,text=True).stdout.splitlines()
(out/'metadata.json').write_text(json.dumps(metadata,indent=2))
fetch('http://localhost:12112/metrics',out/'metrics-before.txt')
backend_metrics = ['docker','exec','rekorperf-trillian-1','curl','-fsS','http://localhost:8091/metrics']
(out/'trillian-before.txt').write_text(run(backend_metrics,capture_output=True,text=True).stdout)
fetch('http://localhost:16060/debug/pprof/allocs',out/'allocs-before.pb.gz')
k6 = ['docker','run','--rm','--name','rekorperf-k6','--network','host',
      '--user',f'{os.getuid()}:{os.getgid()}',
      '-v',str(root)+':/bench:ro','-v',str(out)+':/results:rw',
      '-e','RATE='+a.rate,'-e',f'DURATION={a.duration}s','-e','MODE='+a.mode,'-e','VUS='+a.vus,
      'grafana/k6:1.0.0','run','--quiet','--summary-export=/results/summary-raw.json','/bench/workload.js']
with (out/'k6.log').open('w') as log:
    proc = subprocess.Popen(k6,env=env,stdout=log,stderr=subprocess.STDOUT)
    # Wait for fixture loading and setup to finish, then warm up under load.
    deadline = time.monotonic()+90
    while 'REKOR_BENCHMARK_READY' not in (out/'k6.log').read_text():
        if proc.poll() is not None:
            raise RuntimeError('k6 failed during setup; see '+str(out/'k6.log'))
        if time.monotonic()>deadline:
            proc.terminate()
            raise TimeoutError('k6 setup did not finish within 90 seconds')
        time.sleep(0.2)
    time.sleep(5)
    fetch('http://localhost:12112/metrics',out/'metrics-steady-before.txt')
    seconds = min(15,a.duration-10)
    with concurrent.futures.ThreadPoolExecutor() as executor:
        sample = executor.submit(fetch,f'http://localhost:16060/debug/pprof/profile?seconds={seconds}',out/'cpu.pb.gz',seconds+10)
        def backend_profile():
            response = run(['docker','exec','rekorperf-trillian-1','curl','-fsS','--max-time',str(seconds+10),f'http://localhost:8091/debug/pprof/profile?seconds={seconds}'],capture_output=True)
            (out/'trillian-cpu.pb.gz').write_bytes(response.stdout)
        backend_sample = executor.submit(backend_profile)
        time.sleep(2)
        stats = run(['docker','stats','--no-stream','--format','{{json .}}','rekorperf-rekor-1','rekorperf-mysql-1','rekorperf-trillian-1','rekorperf-signer-1','rekorperf-k6'],capture_output=True,text=True)
        (out/'docker-stats.jsonl').write_text(stats.stdout)
        fetch('http://localhost:16060/debug/pprof/goroutine?debug=2',out/'goroutines-during.txt')
        sample.result()
        backend_sample.result()
    status = proc.wait()
fetch('http://localhost:12112/metrics',out/'metrics-after.txt')
(out/'trillian-after.txt').write_text(run(backend_metrics,capture_output=True,text=True).stdout)
fetch('http://localhost:16060/debug/pprof/heap?gc=1',out/'heap.pb.gz')
fetch('http://localhost:16060/debug/pprof/allocs',out/'allocs-after.pb.gz')
fetch('http://localhost:16060/debug/pprof/goroutine?debug=1',out/'goroutines.txt')
for suffix,args in [('cpu-top',['-top']),('cpu-cum',['-top','-cum']),('allocs',['-top','-alloc_space','-base',str(out/'allocs-before.pb.gz')])]:
    source = out/('allocs-after.pb.gz' if suffix=='allocs' else 'cpu.pb.gz')
    with (out/(suffix+'.txt')).open('w') as f:
        run(['go','tool','pprof',*args,str(root/'rekor-server'),str(source)],stdout=f,stderr=subprocess.STDOUT)
with (out/'trillian-cpu-top.txt').open('w') as f:
    run(['go','tool','pprof','-top',str(out/'trillian-cpu.pb.gz')],stdout=f,stderr=subprocess.STDOUT)
print(out, 'k6 exit:',status)
metadata['k6_exit_code'] = status
(out/'metadata.json').write_text(json.dumps(metadata,indent=2))
summary = json.loads((out/'summary-raw.json').read_text())
(out/'summary.json').write_text(json.dumps(summary['metrics'],indent=2))
print((out/'cpu-top.txt').read_text()[:3200])
print((out/'allocs.txt').read_text()[:2400])
print((out/'k6.log').read_text())
raise SystemExit(status)
