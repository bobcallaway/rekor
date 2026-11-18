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

"""Run the full direct-vs-cached A/B verification matrix and analyze results."""
import argparse
from pathlib import Path
import subprocess
import sys

p = argparse.ArgumentParser(description='Run the full cached-STH / checkpoint-cache A/B verification suite.')
p.add_argument('--prefix', default='suite', help='prefix for named result directories')
p.add_argument('--duration', type=int, default=30, help='duration per scenario in seconds (minimum 20)')
p.add_argument('--rate', type=int, default=100, help='base arrival rate for steady scenarios')
p.add_argument('--burst-rate', type=int, default=200, help='peak write rate for write_burst scenario')
p.add_argument('--read-rate', type=int, default=100, help='background read rate for write_burst scenario')
p.add_argument('--continue-on-failure', action='store_true', help='run remaining scenarios if one fails k6 thresholds')
a = p.parse_args()

root = Path(__file__).resolve().parent
scenarios = [
    # 1. Classic 20/40/30/10 steady comparison (apples-to-apples baseline).
    ('classic-direct', ['--cache', 'false', '--mode', 'classic', '--rate', str(a.rate), '--duration', str(a.duration)]),
    ('classic-cached', ['--cache', 'true', '--mode', 'classic', '--rate', str(a.rate), '--duration', str(a.duration)]),
    # 2. Full mixed workload with an inactive frozen shard, SearchLogQuery, 404s, and read-after-write.
    ('mixed-sharded-direct', ['--cache', 'false', '--mode', 'mixed', '--with-inactive', '--rate', str(a.rate), '--duration', str(a.duration)]),
    ('mixed-sharded-cached', ['--cache', 'true', '--mode', 'mixed', '--with-inactive', '--rate', str(a.rate), '--duration', str(a.duration)]),
    # 3. Sharded heavy-miss & SearchLogQuery batch workload (exercises two-pass inactive lookup & coalesced WaitForRefresh).
    ('sharded-direct', ['--cache', 'false', '--mode', 'sharded', '--with-inactive', '--rate', str(a.rate), '--duration', str(a.duration)]),
    ('sharded-cached', ['--cache', 'true', '--mode', 'sharded', '--with-inactive', '--rate', str(a.rate), '--duration', str(a.duration)]),
    # 4. Write burst + concurrent reads (exercises decoupled write proof waits vs read proof shedding).
    ('burst-cached', [
        '--cache', 'true', '--mode', 'write_burst',
        '--rate', str(a.rate), '--burst-rate', str(a.burst_rate), '--read-rate', str(a.read_rate),
        '--duration', str(a.duration),
    ]),
    # 5. Cross-replica read-after-write consistency (write to rekor1, immediate GET on rekor2).
    ('raw-multi-cached', [
        '--cache', 'true', '--mode', 'read_after_write', '--multi-replica',
        '--rate', str(max(20, a.rate // 2)), '--duration', str(a.duration), '--disallow-overload',
    ]),
]

failures = []
for name, extra in scenarios:
    run_name = f'{a.prefix}-{name}'
    cmd = [sys.executable, str(root / 'run.py'), run_name, *extra]
    print(f'=== Running {run_name}: {" ".join(extra)} ===', flush=True)
    res = subprocess.run(cmd)
    if res.returncode != 0:
        failures.append((run_name, res.returncode))
        if not a.continue_on_failure:
            break

subprocess.run([sys.executable, str(root / 'analyze.py')], check=True)
if failures:
    print('Suite failures:', failures, file=sys.stderr)
    raise SystemExit(1)
