# Cached-root performance evaluation — 2026-10-17

The cached-root client reduces backend root traffic and application work. The
remaining capacity limit in this local stack is backend proof processing, rather
than the root coordinator. No production defaults were changed.

## Controlled comparison

These runs use commit `0299816c`, Go 1.27.1, a 4-vCPU/15.62-GiB Linux Docker
host, and a two-CPU limit on Rekor. Trillian and MySQL are real processes;
Rekor uses an in-memory signer and MySQL indexing. Checkpoint caching is enabled
with 128 completed entries in both modes. The 30-second workload is 20% writes,
40% UUID reads, 30% index reads, and 10% log-info reads, with 100 seeded entries.

The final comparisons freeze previous benchmark trees before creating a fresh
tree. Earlier calibration runs accumulated active trees and signer background
work; their timing numbers are excluded here. The ordinary development stack
was not modified. Other local containers share the same host, so these are
local diagnostic measurements, not isolated production capacity guarantees.

At 100 scheduled iterations/second, both modes complete the workload without
unexpected responses, overload responses, or dropped iterations:

| Measurement | Direct roots | Cached roots |
|---|---:|---:|
| Create p95 | 282 ms | 219 ms |
| UUID lookup p95 | 66 ms | 36 ms |
| Index lookup p95 | 49 ms | 27 ms |
| Log-info p95 | 22 ms | 3.5 ms |
| Steady-state Rekor CPU per HTTP request | 3.50 ms | 2.82 ms |
| Steady-state allocated bytes per HTTP request | 76,122 | 65,059 |
| Backend root RPCs over the measured run, including setup | 5,562 | 343 |

That is about 94% fewer root RPCs, 19% less application CPU per request, and
15% fewer allocated bytes per request. CPU/allocation normalization uses process
counter deltas and completed API request counts after five seconds of warmup.
Latency submetrics exclude fixture seeding. Counts differ by one iteration
because of scheduling at the end of the 30-second window.

## Tuning experiments

With the original binary at 100 iterations/second, reducing polling from 100 ms
to 50 ms lowers create p95 from 219 ms to 169 ms in this sample. Steady-state
root polls increase from 251 to 503, while application CPU per request changes
from 2.82 ms to 2.86 ms. Both runs have zero unexpected responses and drops.
This is an available latency/backend-load tradeoff; the default remains 100 ms.

At 500 scheduled iterations/second with 1,000 preallocated VUs, neither proof
limit delivers the requested workload:

| Proof concurrency | Completed iterations | Dropped iterations | k6 reported iteration rate |
|---|---:|---:|---:|
| 32 | 7,486 | 7,515 | 216.8/s |
| 64 | 7,574 | 7,428 | 217.6/s |

The k6 rate includes setup and drain time; the completed count also includes
requests finishing during the grace period. These rows demonstrate saturation,
not a clean 500/s result. UUID read p95 exceeds four seconds and write p95
exceeds eight seconds. Raising proof concurrency produces no meaningful
improvement in these runs, so the default stays at 32.

At the higher load, Rekor samples about 6 CPU-seconds per 15-second profile;
Trillian samples 16.57 CPU-seconds. Trillian's cumulative profile attributes
about 22% to tree metadata retrieval and 19% to subtree population, with
additional SQL/network and allocation work. Those cumulative percentages overlap
and must not be summed. The next backend investigation should focus on that
work rather than increasing the number of waiting client requests.

## Independent logger optimization

The logger change is isolated on `perf/request-context-logger`, commit
`1e601123`, based on `main`. For the A/B runs, only its logger changes are applied
to the cached-root binary so dependency and feature differences remain fixed.

The focused benchmark (one request context and four disabled debug calls)
changes from approximately 16.8 microseconds, 5,841 bytes, and 37 allocations to
2.0 microseconds, 1,584 bytes, and 13 allocations per operation. In the corrected
100/s mixed workload, steady-state allocation falls from 65,059 to 60,968 bytes
per request (6.3%). CPU remains effectively unchanged at 2.82 ms per request.
There is no demonstrated end-to-end latency or CPU win to claim for this change.

Request ID overrides, trace fields, derived logger field isolation, and the
standalone middleware build pass validation with the race detector.

## Reproduction and limits

See [README.md](README.md) for the harness and [measurements.json](measurements.json)
for counters, configuration, executable hashes, and image IDs from the final
runs. This session's raw profiles remain under `/tmp/rekor-perf/results/clean-*`;
the matching executables are `/tmp/rekor-perf/rekor-server-baseline` and
`/tmp/rekor-perf/rekor-server-candidate`.

These are short local runs against small, fresh trees and a hot read set. They
do not cover remote KMS signing latency, artificial slow RPCs, a large production
tree, or distributed deployments. Repeat longer alternating comparisons on a
dedicated host with the intended signer before choosing production limits.


## Review-fix performance rerun

The three review fixes add expiry to pending size waiters, recheck root freshness
after proof admission, and cap distinct shared checkpoint signatures at 32.
The fixed binary contains these changes on top of `0299816c`; the independent
logger optimization is absent from both compared binaries. The source diff is
retained at `/tmp/rekor-perf/review-fixes.patch` and the fixed executable at
`/tmp/rekor-perf/rekor-server-review-fixes`.

Two 30-second cached-root runs per binary at 100 scheduled requests/second used
the same workload, images, and limits as above. Runs were grouped before/before,
then fixed/fixed, so small latency or CPU differences are not evidence of a
speedup. All four runs completed with zero unexpected responses, overload
responses, or dropped iterations.

| Measurement | Before fixes (two runs) | With fixes (two runs) |
|---|---:|---:|
| Steady-state CPU per HTTP request | 2.76–2.79 ms | 2.72–2.73 ms |
| Steady-state allocated bytes per HTTP request | 65,204–65,315 | 64,931–65,399 |
| Create p95 | 195–213 ms | 163–184 ms |
| UUID lookup p95 | 29–38 ms | 26–31 ms |
| Index lookup p95 | 22.5–23.9 ms | 17.5–20.9 ms |
| Log-info p95 | 3.8–3.9 ms | 3.5–3.6 ms |

There is no meaningful performance regression evident in these samples.
At 500 scheduled requests/second with 1,000 VUs, the before/fixed runs completed
7,687/7,792 iterations and dropped 7,314/7,209 respectively. Both failed the
zero-dropped-iterations threshold (k6 exit 99), with no unexpected HTTP errors
or overload responses. Create p95 was 8.62/8.64 seconds and UUID lookup p95 was
4.65/4.69 seconds. The fixes do not remove the backend saturation limit.

The saturation CPU profiles contain 6.14/6.20 CPU-seconds of Rekor work over
15 seconds. The fixed run's Trillian profile contains 16.33 CPU-seconds over
15 seconds, consistent with the earlier backend bottleneck diagnosis.

See [review-measurements.json](review-measurements.json) for per-run counters,
binary hashes, and metadata. Raw profiles are under
`/tmp/rekor-perf/results/review-*`. The second baseline run was initially named
`review-after-100-a` after an attempted executable replacement failed; its hash
confirmed that it was still the baseline. Its directory is now
`review-before-100-b`, and metadata preserves the original name and explanation.

These runs use memory signing: they measure normal-path overhead and backend
saturation, not production KMS capacity. Regression tests separately exercise
blocked signing admission, shared-call coalescing at capacity, timeout cleanup,
waiter expiry after invalid root proofs, and stale queued proof reads.
