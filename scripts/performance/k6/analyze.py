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

import json
from pathlib import Path
import re

root = Path(__file__).resolve().parent
def sample(path, name):
    for line in path.read_text().splitlines():
        if line.startswith(name+' '): return float(line.split()[-1])
    return 0

def request_count(path):
    return sum(float(line.split()[-1]) for line in path.read_text().splitlines()
               if line.startswith('rekor_api_latency_count{'))

def polls(path):
    return sum(float(line.split()[-1]) for line in path.read_text().splitlines()
               if line.startswith('rekor_trillian_root_polls_total{'))

def rpc_counts(path):
    counts = {}
    if not path.exists(): return counts
    for line in path.read_text().splitlines():
        match = re.match(r'log_rpc_(?:success|error)_latency_count\{method="/trillian.TrillianLog/(\w+)"\} (\S+)',line)
        if match:
            method, value = match.groups()
            counts[method] = counts.get(method,0)+float(value)
    return counts

rows = []
for folder in sorted((root/'results').iterdir()):
    if not (folder/'metrics-after.txt').exists(): continue
    if (folder/'summary.json').exists():
        metrics = json.loads((folder/'summary.json').read_text())
    else:
        text = (folder/'k6.log').read_text()
        start = text.find('{\n')
        if start<0: continue
        metrics = json.JSONDecoder().raw_decode(text[start:])[0]['metrics']
    meta = json.loads((folder/'metadata.json').read_text())
    before, after = folder/'metrics-before.txt', folder/'metrics-after.txt'
    requests = metrics['http_reqs']['count']
    row = {
      'name': folder.name,
      'iterations': metrics['iterations']['count'],
      'offered_rate': int(meta['rate']),
      'iterations_per_scheduled_second': metrics['iterations']['count']/meta['duration'],
      'k6_reported_iteration_rate': metrics['iterations']['rate'],
      'dropped': metrics.get('dropped_iterations',{}).get('count',0),
      'errors': metrics.get('unexpected_response',{}).get('value',0),
      'overload': metrics.get('overload_responses',{}).get('count',0),
      'cpu_ms_per_http': 1000*(sample(after,'process_cpu_seconds_total')-sample(before,'process_cpu_seconds_total'))/requests,
      'allocated_bytes_per_http': (sample(after,'go_memstats_alloc_bytes_total')-sample(before,'go_memstats_alloc_bytes_total'))/requests,
      'p95_ms': {key.split('name:')[1].rstrip('}'):value['p(95)'] for key,value in metrics.items() if key.startswith('http_req_duration{name:')},
    }
    rpc_before, rpc_after = rpc_counts(folder/'trillian-before.txt'), rpc_counts(folder/'trillian-after.txt')
    row['backend_rpcs'] = {key:int(value-rpc_before.get(key,0)) for key,value in rpc_after.items()}
    steady = folder/'metrics-steady-before.txt'
    if steady.exists():
        completed = request_count(after)-request_count(steady)
        row['steady_http_requests'] = int(completed)
        row['steady_allocated_bytes_per_http'] = (sample(after,'go_memstats_alloc_bytes_total')-sample(steady,'go_memstats_alloc_bytes_total'))/completed
        row['steady_cpu_ms_per_http'] = 1000*(sample(after,'process_cpu_seconds_total')-sample(steady,'process_cpu_seconds_total'))/completed
        row['steady_root_polls'] = int(polls(after)-polls(steady))
    rows.append(row)
    print(json.dumps(row))
(root/'comparison.json').write_text(json.dumps(rows,indent=2))
