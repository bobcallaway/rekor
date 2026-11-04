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
the actual server executable is the locally compiled binary mounted at `/bench`.
The other images are `gcr.io/trillian-opensource-ci/db_server:v1.4.0` and
`grafana/k6:1.0.0`. Docker may pull those images if they are not already present.

From the repository root:

```sh
go build -o scripts/performance/k6/rekor-server ./cmd/rekor-server
go build -o scripts/performance/k6/freeze-trees ./scripts/performance/k6/admin
go run scripts/performance/k6/fixtures.go \
  -output scripts/performance/k6/fixtures.json -count 50000
python3 scripts/performance/k6/run.py direct-100 --cache false --rate 100 --vus 300
python3 scripts/performance/k6/run.py cached-100 --cache true --rate 100 --vus 300
python3 scripts/performance/k6/analyze.py
```

Linux host networking is used for k6. The localhost ports are 13000 (API),
12112 (Prometheus), and 16060 (pprof). Rekor has a two-CPU limit. k6, Trillian,
the signer, and MySQL share the host's remaining resources; capture their CPU
usage and do not run builds or other load tests during a measurement.

## Workload and comparisons

Fixtures are distinct, valid ECDSA P-256 hashedrekord entries generated offline.
The default workload is 20% create, 40% UUID lookup, 30% index lookup, and 10%
log-info requests. Reads use a hot set of 100 seeded entries. `--mode read` or
`--mode write` selects a single workload class. Increase the fixture count when
`rate * duration + 100` would exceed the number of fixtures.

The workload uses k6's [constant-arrival-rate executor](https://grafana.com/docs/k6/latest/using-k6/scenarios/executors/constant-arrival-rate/).
`--vus` sets the preallocated and maximum VU budget. A run with dropped iterations
did not deliver its intended offered load; retain it as a saturation observation,
not as a clean comparison at the requested rate. The reported k6 iteration rate
includes setup and shutdown in its denominator. Use completed and dropped
iteration counts to inspect workload delivery; do not treat completed iterations
divided by scheduled duration as steady-state throughput when requests finish
during the grace period.

There are no automatic HTTP retries in this workload. A local overload response
is counted separately and must include `Retry-After: 1`. Unexpected responses,
failed checks, and dropped iterations fail the k6 thresholds. A 503 is not a
successful write, so compare `created_entries` and `overload_responses` as well
as HTTP latency. Existing duplicate responses are unexpected: each run must use
a fresh tree and enough fixtures.
Use the per-operation latency submetrics; the aggregate HTTP latency also
includes fixture-seeding requests.

Options include `--checkpoints 0` to disable checkpoint retention,
`--proof-concurrency N` to vary the proof limit, `--poll-interval 50ms` to vary
root polling, and `--duration N` for a longer
run (minimum 20 seconds). Defaults remain the server defaults unless overridden
in Compose. The signer is an in-memory key, attestation storage and publishing
are disabled, and MySQL indexing is enabled. These results do not characterize
KMS latency, a large production tree, or a distributed deployment.

## Artifacts and interpretation

Every named run creates `results/<name>/` with the k6 summary, raw log, binary
SHA-256, Go version, host capacity, process/Trillian metrics, container resource
usage, and CPU/allocation/heap/goroutine profiles. CPU collection starts after
seeding and five seconds of workload warmup. Trillian's CPU profile is captured
at the same time as Rekor's, through its internal HTTP endpoint.
Allocation deltas include the
100-entry seeding step; `metrics-steady-before.txt` additionally permits
steady-state process-counter comparisons.

```sh
go tool pprof -http=127.0.0.1:8080 \
  scripts/performance/k6/rekor-server \
  scripts/performance/k6/results/cached-100/cpu.pb.gz
```

Keep the matching executable when comparing different binaries. Change one
factor at a time, repeat in alternating order, and distinguish CPU/allocation
improvements from backend queueing and run-to-run latency variation. Treat the
included limits as experiment inputs rather than production recommendations.

Stop the isolated stack when finished; this removes only its containers and
network, including its disposable database:

```sh
docker compose -p rekorperf -f scripts/performance/k6/compose.yaml down
```
