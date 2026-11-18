# Rekor k6 and pprof harness

This harness creates a separate `rekorperf` Compose project, database, and set of
localhost ports. It does not reuse the ordinary development stack. Each run
recreates Rekor, which creates a fresh Trillian tree; the generated fixtures can
therefore be reused without turning writes into duplicate-entry requests.
Previous trees in this isolated database are frozen before each run so the
signer's background work does not accumulate. Never point the admin helper at
a development or production Trillian instance.

## Prerequisites and setup

Use Docker Compose and locally built `rekor-rekor-server:latest`,
`rekor-trillian-log-server:latest`, and `rekor-trillian-log-signer:latest` images
from the repository's Dockerfiles. The Rekor image supplies a runtime environment;
the actual server executable is the locally compiled Linux binary mounted at
`/bench`. The other images are `gcr.io/trillian-opensource-ci/db_server:v1.4.0`
and `grafana/k6:1.0.0`.

From the repository root (note `GOOS=linux CGO_ENABLED=0` so this works on both
Linux and macOS hosts):

```sh
GOOS=linux CGO_ENABLED=0 go build -o scripts/performance/k6/rekor-server ./cmd/rekor-server
GOOS=linux CGO_ENABLED=0 go build -o scripts/performance/k6/freeze-trees ./scripts/performance/k6/admin
go run scripts/performance/k6/fixtures.go \
  -output scripts/performance/k6/fixtures.json -count 50000
```

Run a single comparison pair or the full verification matrix:

```sh
# Single pair
python3 scripts/performance/k6/run.py direct-100 --cache false --mode mixed --with-inactive --rate 100 --vus 300
python3 scripts/performance/k6/run.py cached-100 --cache true --mode mixed --with-inactive --rate 100 --vus 300
python3 scripts/performance/k6/analyze.py

# Full direct-vs-cached A/B suite (classic, mixed+inactive, sharded, write_burst, cross-replica read-after-write)
python3 scripts/performance/k6/suite.py --prefix predeploy
```

k6 runs on the isolated Compose network (`rekorperf_default`, targeting
`http://rekor:3000` and optionally `http://rekor2:3000` for `--multi-replica`),
so host networking is not required. Localhost ports are 13000/13001 (API),
12112/12113 (Prometheus), and 16060/16061 (pprof). Each Rekor container has a
two-CPU limit. Do not run builds or other load tests during a measurement.

## Workload modes

Fixtures are distinct, valid ECDSA P-256 hashedrekord entries generated offline.
Increase the fixture count when `rate * duration + seed_count + inactive_count`
would exceed the number of fixtures.

| Mode (`--mode`) | What it exercises |
|---|---|
| `mixed` *(default)* | Balanced production-like mix: writes, immediate read-after-write (UUID & index), active 80-char EntryID lookups, inactive plain-UUID lookups (when `--with-inactive`), index lookups, multi-item `SearchLogQuery` batches (with misses), 404 probes, consistency proofs, and `GET /api/v1/log`. |
| `classic` | Original 20% create / 40% UUID / 30% index / 10% log-info mix for apples-to-apples comparisons against older runs. |
| `write_burst` | `ramping-arrival-rate` write burst (`--burst-rate`, default 250/s) alongside steady concurrent reads (`--read-rate`, default 100/s) and recovery. Validates that committed writes drain cleanly through `proof_concurrency` without post-commit 503s while excess reads shed cleanly on `max_proof_waiters`. |
| `sharded` | Heavy mix of plain-UUID inactive-shard lookups (`--with-inactive`), multi-miss `SearchLogQuery` batches, 404 probes, and read-after-write checks. Validates two-pass inactive shard lookup and single coalesced `WaitForRefresh` per batch. |
| `read_after_write` | Continuous `POST /api/v1/log/entries` followed immediately by `GET` (plain UUID or logIndex). Combined with `--multi-replica`, writes go to `rekor` and immediate reads go to `rekor2`, verifying `read_after_write_404 == 0` across independent STH caches. |
| `read` / `write` | Pure read or pure write workload. |

## Flags and thresholds

`run.py` exposes all cached-STH and checkpoint-cache tuning flags:

- `--cache true|false`, `--poll-interval 100ms`, `--root-timeout 3s`, `--max-root-age 0s`
- `--max-pending 1024`, `--proof-concurrency 32`, `--max-proof-waiters 32`
- `--checkpoints 128`, `--checkpoint-signing-concurrency 32`, `--checkpoint-signing-timeout 0s`
- `--with-inactive` (`--inactive-count 50`), `--multi-replica`, `--seed-count 100`
- `--disallow-overload` (fail thresholds on any HTTP 503)

There are no automatic HTTP retries in `workload.js`. HTTP 503 responses are
accepted on any endpoint (unless `--disallow-overload` is set), counted
separately as `overload_write_responses` and `overload_read_responses`, and
verified to include `Retry-After: 1`. Any `read_after_write_404 > 0`,
`unexpected_response > 0`, failed check, or `dropped_iterations > 0` fails the
k6 thresholds.

## Artifacts and interpretation

Every named run writes `results/<name>/` with the k6 summary, raw log, binary
SHA-256, Go version, host capacity, Rekor/Trillian Prometheus snapshots (plus
`rekor2` when `--multi-replica`), container resource usage, and
CPU/allocation/heap/goroutine profiles.

`analyze.py` aggregates all runs into `comparison.json`, including:

- per-operation `p50`, `p95`, `p99` latencies (`create`, `lookup_uuid`, `lookup_inactive_uuid`, `lookup_index`, `lookup_miss`, `search_query`, `log_info`, `log_proof`, `raw_lookup`),
- `overload_writes`, `overload_reads`, `read_after_write_404`, and `dropped` counts,
- steady-state CPU ms/req and allocated bytes/req,
- Trillian RPC counts by method,
- `root_polls` (`success` / `failure` / `regressed`), `writes_rejected`, `proofs_rejected`, `proof_wait_count`, `proof_wait_avg_ms`, and `checkpoint_cache` (`hit` / `miss` / `rejected` / `sign_error` + hit rate).

```sh
go tool pprof -http=127.0.0.1:8080 \
  scripts/performance/k6/rekor-server \
  scripts/performance/k6/results/predeploy-mixed-sharded-cached/cpu.pb.gz
```

Note that this local stack still uses `--rekor_server.signer=memory` and a
small MySQL tree; run a staging soak with your real KMS signer (GCP KMS / Vault)
and production-scale tree depth before finalizing production limits.

Stop the isolated stack when finished:

```sh
docker compose -p rekorperf -f scripts/performance/k6/compose.yaml --profile multi down
```
