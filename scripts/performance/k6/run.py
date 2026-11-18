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
p.add_argument('--cache', choices=['true', 'false'], default='true')
p.add_argument('--checkpoints', default='128')
p.add_argument('--checkpoint-signing-concurrency', default='32')
p.add_argument('--checkpoint-signing-timeout', default='0s')
p.add_argument('--rate', default='100')
p.add_argument('--burst-rate', default='250')
p.add_argument('--read-rate', default='100')
p.add_argument('--duration', type=int, default=30)
p.add_argument('--mode', choices=['mixed', 'classic', 'read', 'write', 'write_burst', 'sharded', 'read_after_write'], default='mixed')
p.add_argument('--vus', default='300')
p.add_argument('--seed-count', type=int, default=100)
p.add_argument('--proof-concurrency', default='32')
p.add_argument('--max-proof-waiters', default='32')
p.add_argument('--max-pending', default='1024')
p.add_argument('--poll-interval', default='100ms')
p.add_argument('--root-timeout', default='3s')
p.add_argument('--max-root-age', default='0s')
p.add_argument('--with-inactive', action='store_true', help='seed and freeze an inactive shard before creating the active tree')
p.add_argument('--inactive-count', type=int, default=50, help='number of entries to seed into the inactive shard')
p.add_argument('--multi-replica', action='store_true', help='run a second Rekor container (rekor2) for cross-instance read-after-write')
p.add_argument('--disallow-overload', action='store_true', help='fail k6 thresholds on any HTTP 503 overload response')
a = p.parse_args()

if a.duration < 20:
    p.error('--duration must be at least 20 seconds for a steady-state profile')

root = Path(__file__).resolve().parent
for binary in ('rekor-server', 'freeze-trees'):
    bin_path = root / binary
    if not bin_path.exists():
        raise SystemExit(f'missing {bin_path}; build Linux binaries first (see scripts/performance/k6/README.md)')
    if bin_path.read_bytes()[:4] != b'\x7fELF':
        raise SystemExit(f'{bin_path} is not a Linux ELF binary; rebuild with GOOS=linux CGO_ENABLED=0')
if not (root / 'fixtures.json').exists():
    raise SystemExit(f'missing {root / "fixtures.json"}; generate fixtures first (see scripts/performance/k6/README.md)')

out = root / 'results' / a.name
out.mkdir(parents=True, exist_ok=False)

env = dict(
    os.environ,
    PERF_DIR=str(root),
    CACHE_STH=a.cache,
    CHECKPOINT_ENTRIES=a.checkpoints,
    CHECKPOINT_SIGNING_CONCURRENCY=a.checkpoint_signing_concurrency,
    CHECKPOINT_SIGNING_TIMEOUT=a.checkpoint_signing_timeout,
    PROOF_CONCURRENCY=a.proof_concurrency,
    MAX_PROOF_WAITERS=a.max_proof_waiters,
    MAX_PENDING=a.max_pending,
    POLL_INTERVAL=a.poll_interval,
    ROOT_TIMEOUT=a.root_timeout,
    MAX_ROOT_AGE=a.max_root_age,
    ACTIVE_TREE_ID='0',
    SHARDING_CONFIG='',
)
compose = ['docker', 'compose', '-p', 'rekorperf', '-f', str(root / 'compose.yaml')]


def run(args, env_override=None, **kw):
    return subprocess.run(args, env=env_override or env, check=True, **kw)


def fetch(url, path, timeout=30):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        path.write_bytes(response.read())


def wait_for_rekor(url, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                return json.loads(response.read())
        except Exception:
            if time.monotonic() > deadline:
                raise
            time.sleep(1)


def freeze_active_trees():
    run([
        'docker', 'run', '--rm', '--network', 'rekorperf_default',
        '-v', f'{root}:/bench:ro', '--entrypoint', '/bench/freeze-trees',
        'rekor-rekor-server:latest',
    ])


def seed_inactive_shard(count):
    """Create a temporary active tree, seed entries via Rekor, freeze it, and emit sharding config."""
    run(compose + ['up', '-d', '--force-recreate', 'rekor'])
    info = wait_for_rekor('http://localhost:13000/api/v1/log')
    inactive_tree_id = int(info['treeID'])
    fixtures = json.loads((root / 'fixtures.json').read_text())
    if len(fixtures) < count:
        raise RuntimeError(f'need at least {count} fixtures to seed inactive shard')

    seeded = []
    for i in range(count):
        req = urllib.request.Request(
            'http://localhost:13000/api/v1/log/entries',
            data=json.dumps(fixtures[i]).encode(),
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            if resp.status != 201:
                raise RuntimeError(f'inactive seed failed at {i}: HTTP {resp.status}')
            body = json.loads(resp.read())
            entry_id = next(iter(body))
            seeded.append({
                'entryID': entry_id,
                'uuid': entry_id[16:] if len(entry_id) == 80 else entry_id,
                'logIndex': body[entry_id]['logIndex'],
            })

    run(compose + ['stop', 'rekor'])
    freeze_active_trees()

    sharding_path = out / 'sharding-config.yaml'
    sharding_path.write_text(f'- treeID: {inactive_tree_id}\n  treeLength: {count}\n')
    inactive_ids_path = out / 'inactive-ids.json'
    inactive_ids_path.write_text(json.dumps(seeded, indent=2))
    return f'/bench/results/{a.name}/sharding-config.yaml', f'/results/inactive-ids.json', count


# Ensure any previous rekor2 replica is stopped before starting a fresh run.
run(compose + ['--profile', 'multi', 'stop', 'rekor2'])
run(compose + ['up', '-d', 'mysql', 'trillian', 'signer'])
freeze_active_trees()

inactive_file = ''
fixture_offset = 0
if a.with_inactive:
    sharding_cfg, inactive_file, fixture_offset = seed_inactive_shard(a.inactive_count)
    env['SHARDING_CONFIG'] = sharding_cfg

run(compose + ['up', '-d', '--force-recreate', 'rekor'])
active_info = wait_for_rekor('http://localhost:13000/api/v1/log')
active_tree_id = str(active_info['treeID'])

read_base_url = 'http://rekor:3000'
if a.multi_replica:
    env['ACTIVE_TREE_ID'] = active_tree_id
    run(compose + ['--profile', 'multi', 'up', '-d', '--force-recreate', 'rekor2'])
    wait_for_rekor('http://localhost:13001/api/v1/log')
    read_base_url = 'http://rekor2:3000'

metadata = dict(vars(a), timestamp=time.time(), active_tree_id=active_tree_id)
metadata['binary_sha256'] = hashlib.sha256((root / 'rekor-server').read_bytes()).hexdigest()
metadata['docker_info'] = run(['docker', 'info', '--format', '{{.NCPU}} CPUs, {{.MemTotal}} bytes RAM'], capture_output=True, text=True).stdout.strip()
metadata['go_version'] = run(['go', 'version'], capture_output=True, text=True).stdout.strip()
metadata['images'] = run([
    'docker', 'inspect',
    'rekor-rekor-server:latest', 'rekor-trillian-log-server:latest',
    'rekor-trillian-log-signer:latest', 'gcr.io/trillian-opensource-ci/db_server:v1.4.0',
    'grafana/k6:1.0.0', '--format', '{{json .RepoTags}} {{.Id}}',
], capture_output=True, text=True).stdout.splitlines()
(out / 'metadata.json').write_text(json.dumps(metadata, indent=2))

fetch('http://localhost:12112/metrics', out / 'metrics-before.txt')
if a.multi_replica:
    fetch('http://localhost:12113/metrics', out / 'metrics-rekor2-before.txt')
backend_metrics = ['docker', 'exec', 'rekorperf-trillian-1', 'curl', '-fsS', 'http://localhost:8091/metrics']
(out / 'trillian-before.txt').write_text(run(backend_metrics, capture_output=True, text=True).stdout)
fetch('http://localhost:16060/debug/pprof/allocs', out / 'allocs-before.pb.gz')

k6 = [
    'docker', 'run', '--rm', '--name', 'rekorperf-k6', '--network', 'rekorperf_default',
    '--user', f'{os.getuid()}:{os.getgid()}',
    '-v', f'{root}:/bench:ro', '-v', f'{out}:/results:rw',
    '-e', 'BASE_URL=http://rekor:3000',
    '-e', f'READ_BASE_URL={read_base_url}',
    '-e', f'RATE={a.rate}',
    '-e', f'BURST_RATE={a.burst_rate}',
    '-e', f'READ_RATE={a.read_rate}',
    '-e', f'DURATION_SEC={a.duration}',
    '-e', f'MODE={a.mode}',
    '-e', f'VUS={a.vus}',
    '-e', f'SEED_COUNT={a.seed_count}',
    '-e', f'FIXTURE_OFFSET={fixture_offset}',
    '-e', f'INACTIVE_FILE={inactive_file}',
    '-e', f'ALLOW_OVERLOAD={"false" if a.disallow_overload else "true"}',
    'grafana/k6:1.0.0', 'run', '--quiet', '--summary-export=/results/summary-raw.json', '/bench/workload.js',
]

stat_containers = ['rekorperf-rekor-1', 'rekorperf-mysql-1', 'rekorperf-trillian-1', 'rekorperf-signer-1', 'rekorperf-k6']
if a.multi_replica:
    stat_containers.insert(1, 'rekorperf-rekor2-1')

with (out / 'k6.log').open('w') as log:
    proc = subprocess.Popen(k6, env=env, stdout=log, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 120
    while 'REKOR_BENCHMARK_READY' not in (out / 'k6.log').read_text():
        if proc.poll() is not None:
            raise RuntimeError('k6 failed during setup; see ' + str(out / 'k6.log'))
        if time.monotonic() > deadline:
            proc.terminate()
            raise TimeoutError('k6 setup did not finish within 120 seconds')
        time.sleep(0.2)
    time.sleep(5)
    fetch('http://localhost:12112/metrics', out / 'metrics-steady-before.txt')
    if a.multi_replica:
        fetch('http://localhost:12113/metrics', out / 'metrics-rekor2-steady-before.txt')
    seconds = min(15, a.duration - 10)
    with concurrent.futures.ThreadPoolExecutor() as executor:
        sample = executor.submit(fetch, f'http://localhost:16060/debug/pprof/profile?seconds={seconds}', out / 'cpu.pb.gz', seconds + 10)

        def backend_profile():
            response = run(['docker', 'exec', 'rekorperf-trillian-1', 'curl', '-fsS', '--max-time', str(seconds + 10), f'http://localhost:8091/debug/pprof/profile?seconds={seconds}'], capture_output=True)
            (out / 'trillian-cpu.pb.gz').write_bytes(response.stdout)

        backend_sample = executor.submit(backend_profile)
        time.sleep(2)
        stats = run(['docker', 'stats', '--no-stream', '--format', '{{json .}}', *stat_containers], capture_output=True, text=True)
        (out / 'docker-stats.jsonl').write_text(stats.stdout)
        fetch('http://localhost:16060/debug/pprof/goroutine?debug=2', out / 'goroutines-during.txt')
        sample.result()
        backend_sample.result()
    status = proc.wait()

fetch('http://localhost:12112/metrics', out / 'metrics-after.txt')
if a.multi_replica:
    fetch('http://localhost:12113/metrics', out / 'metrics-rekor2-after.txt')
(out / 'trillian-after.txt').write_text(run(backend_metrics, capture_output=True, text=True).stdout)
fetch('http://localhost:16060/debug/pprof/heap?gc=1', out / 'heap.pb.gz')
fetch('http://localhost:16060/debug/pprof/allocs', out / 'allocs-after.pb.gz')
fetch('http://localhost:16060/debug/pprof/goroutine?debug=1', out / 'goroutines.txt')

for suffix, args in [
    ('cpu-top', ['-top']),
    ('cpu-cum', ['-top', '-cum']),
    ('allocs', ['-top', '-alloc_space', '-base', str(out / 'allocs-before.pb.gz')]),
]:
    source = out / ('allocs-after.pb.gz' if suffix == 'allocs' else 'cpu.pb.gz')
    with (out / (suffix + '.txt')).open('w') as f:
        run(['go', 'tool', 'pprof', *args, str(root / 'rekor-server'), str(source)], stdout=f, stderr=subprocess.STDOUT)
with (out / 'trillian-cpu-top.txt').open('w') as f:
    run(['go', 'tool', 'pprof', '-top', str(out / 'trillian-cpu.pb.gz')], stdout=f, stderr=subprocess.STDOUT)

print(out, 'k6 exit:', status)
metadata['k6_exit_code'] = status
(out / 'metadata.json').write_text(json.dumps(metadata, indent=2))
summary = json.loads((out / 'summary-raw.json').read_text())
(out / 'summary.json').write_text(json.dumps(summary['metrics'], indent=2))
print((out / 'cpu-top.txt').read_text()[:3200])
print((out / 'allocs.txt').read_text()[:2400])
print((out / 'k6.log').read_text())
raise SystemExit(status)
