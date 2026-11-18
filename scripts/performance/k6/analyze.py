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
        if line.startswith(name + ' '):
            return float(line.split()[-1])
    return 0.0


def sum_metric(path, prefix):
    return sum(
        float(line.split()[-1])
        for line in path.read_text().splitlines()
        if line.startswith(prefix)
    )


def labeled_counts(path, metric_name, label_name):
    counts = {}
    pattern = re.compile(rf'^{re.escape(metric_name)}\{{[^}}]*{re.escape(label_name)}="([^"]+)"[^}}]*\}} (\S+)$')
    for line in path.read_text().splitlines():
        match = pattern.match(line)
        if match:
            label, value = match.groups()
            counts[label] = counts.get(label, 0.0) + float(value)
    return counts


def delta_map(before, after):
    keys = set(before) | set(after)
    return {k: int(round(after.get(k, 0.0) - before.get(k, 0.0))) for k in sorted(keys)}


def request_count(path):
    return sum_metric(path, 'rekor_api_latency_count{')


def rpc_counts(path):
    counts = {}
    if not path.exists():
        return counts
    for line in path.read_text().splitlines():
        match = re.match(r'log_rpc_(?:success|error)_latency_count\{method="/trillian.TrillianLog/(\w+)"\} (\S+)', line)
        if match:
            method, value = match.groups()
            counts[method] = counts.get(method, 0.0) + float(value)
    return counts


rows = []
results_dir = root / 'results'
if not results_dir.exists():
    raise SystemExit('no results/ directory found')

for folder in sorted(results_dir.iterdir()):
    if not (folder / 'metrics-after.txt').exists():
        continue
    if (folder / 'summary.json').exists():
        metrics = json.loads((folder / 'summary.json').read_text())
    else:
        text = (folder / 'k6.log').read_text()
        start = text.find('{\n')
        if start < 0:
            continue
        metrics = json.JSONDecoder().raw_decode(text[start:])[0]['metrics']
    meta = json.loads((folder / 'metadata.json').read_text())
    before, after = folder / 'metrics-before.txt', folder / 'metrics-after.txt'
    requests = metrics['http_reqs']['count']

    cp_before = labeled_counts(before, 'rekor_checkpoint_cache_requests_total', 'outcome')
    cp_after = labeled_counts(after, 'rekor_checkpoint_cache_requests_total', 'outcome')
    cp_delta = delta_map(cp_before, cp_after)
    cp_total = cp_delta.get('hit', 0) + cp_delta.get('miss', 0)

    polls_before = labeled_counts(before, 'rekor_trillian_root_polls_total', 'outcome')
    polls_after = labeled_counts(after, 'rekor_trillian_root_polls_total', 'outcome')
    polls_delta = delta_map(polls_before, polls_after)

    proof_wait_count = sum_metric(after, 'rekor_trillian_proof_wait_duration_seconds_count{') - sum_metric(before, 'rekor_trillian_proof_wait_duration_seconds_count{')
    proof_wait_sum = sum_metric(after, 'rekor_trillian_proof_wait_duration_seconds_sum{') - sum_metric(before, 'rekor_trillian_proof_wait_duration_seconds_sum{')

    row = {
        'name': folder.name,
        'mode': meta.get('mode', 'mixed'),
        'cache_sth': meta.get('cache', 'unknown'),
        'multi_replica': meta.get('multi_replica', False),
        'with_inactive': meta.get('with_inactive', False),
        'k6_exit_code': meta.get('k6_exit_code'),
        'iterations': metrics['iterations']['count'],
        'offered_rate': int(meta['rate']),
        'iterations_per_scheduled_second': metrics['iterations']['count'] / meta['duration'],
        'k6_reported_iteration_rate': metrics['iterations']['rate'],
        'dropped': metrics.get('dropped_iterations', {}).get('count', 0),
        'errors': metrics.get('unexpected_response', {}).get('value', 0),
        'read_after_write_404': metrics.get('read_after_write_404', {}).get('count', 0),
        'created_entries': metrics.get('created_entries', {}).get('count', 0),
        'overload': metrics.get('overload_responses', {}).get('count', 0),
        'overload_writes': metrics.get('overload_write_responses', {}).get('count', 0),
        'overload_reads': metrics.get('overload_read_responses', {}).get('count', 0),
        'cpu_ms_per_http': 1000 * (sample(after, 'process_cpu_seconds_total') - sample(before, 'process_cpu_seconds_total')) / requests,
        'allocated_bytes_per_http': (sample(after, 'go_memstats_alloc_bytes_total') - sample(before, 'go_memstats_alloc_bytes_total')) / requests,
        'p50_ms': {key.split('name:')[1].rstrip('}'): round(value['med'], 2) for key, value in metrics.items() if key.startswith('http_req_duration{name:')},
        'p95_ms': {key.split('name:')[1].rstrip('}'): round(value['p(95)'], 2) for key, value in metrics.items() if key.startswith('http_req_duration{name:')},
        'p99_ms': {key.split('name:')[1].rstrip('}'): round(value['p(99)'], 2) for key, value in metrics.items() if key.startswith('http_req_duration{name:')},
        'root_polls': polls_delta,
        'writes_rejected': int(round(sum_metric(after, 'rekor_trillian_writes_rejected_total{') - sum_metric(before, 'rekor_trillian_writes_rejected_total{'))),
        'proofs_rejected': int(round(sum_metric(after, 'rekor_trillian_proofs_rejected_total{') - sum_metric(before, 'rekor_trillian_proofs_rejected_total{'))),
        'proof_wait_count': int(round(proof_wait_count)),
        'proof_wait_avg_ms': round(1000 * proof_wait_sum / proof_wait_count, 3) if proof_wait_count > 0 else 0.0,
        'checkpoint_cache': cp_delta,
        'checkpoint_cache_hit_rate': round(cp_delta.get('hit', 0) / cp_total, 4) if cp_total > 0 else None,
    }
    rpc_before, rpc_after = rpc_counts(folder / 'trillian-before.txt'), rpc_counts(folder / 'trillian-after.txt')
    row['backend_rpcs'] = {key: int(round(value - rpc_before.get(key, 0.0))) for key, value in sorted(rpc_after.items())}

    steady = folder / 'metrics-steady-before.txt'
    if steady.exists():
        completed = request_count(after) - request_count(steady)
        if completed > 0:
            row['steady_http_requests'] = int(completed)
            row['steady_allocated_bytes_per_http'] = (sample(after, 'go_memstats_alloc_bytes_total') - sample(steady, 'go_memstats_alloc_bytes_total')) / completed
            row['steady_cpu_ms_per_http'] = 1000 * (sample(after, 'process_cpu_seconds_total') - sample(steady, 'process_cpu_seconds_total')) / completed
            row['steady_root_polls'] = int(round(sum_metric(after, 'rekor_trillian_root_polls_total{') - sum_metric(steady, 'rekor_trillian_root_polls_total{')))

    r2_before, r2_after = folder / 'metrics-rekor2-before.txt', folder / 'metrics-rekor2-after.txt'
    if r2_before.exists() and r2_after.exists():
        r2_cp = delta_map(
            labeled_counts(r2_before, 'rekor_checkpoint_cache_requests_total', 'outcome'),
            labeled_counts(r2_after, 'rekor_checkpoint_cache_requests_total', 'outcome'),
        )
        r2_cp_total = r2_cp.get('hit', 0) + r2_cp.get('miss', 0)
        row['rekor2'] = {
            'root_polls': delta_map(
                labeled_counts(r2_before, 'rekor_trillian_root_polls_total', 'outcome'),
                labeled_counts(r2_after, 'rekor_trillian_root_polls_total', 'outcome'),
            ),
            'proofs_rejected': int(round(sum_metric(r2_after, 'rekor_trillian_proofs_rejected_total{') - sum_metric(r2_before, 'rekor_trillian_proofs_rejected_total{'))),
            'checkpoint_cache': r2_cp,
            'checkpoint_cache_hit_rate': round(r2_cp.get('hit', 0) / r2_cp_total, 4) if r2_cp_total > 0 else None,
        }
    rows.append(row)
    print(json.dumps(row))

(root / 'comparison.json').write_text(json.dumps(rows, indent=2))
