# Rekor v1 Load Test

A [k6](https://k6.io) script that exercises both the write and read paths of a
Rekor v1 server using `hashedrekord` v0.0.1 entries.

Adapted from the [rekor-tiles load test](https://github.com/sigstore/rekor-tiles/tree/main/tests/loadtest),
which targets the v2 API and a different request schema.

## Prerequisites

- k6 v1.0 or later (the script uses the global WebCrypto API and async
  scenario functions).
- A running Rekor v1 instance. From the repository root:

  ```sh
  docker compose up -d --wait
  ```

## Running

```sh
k6 run tests/loadtest/k6_rekor_load_test.js
```

### Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `REKOR_URL` | `http://localhost:3000` | Base URL of the Rekor server (no `/api/v1` suffix) |
| `WRITE_RATE` | `300` | Target `POST /api/v1/log/entries` per second |
| `READ_RATE` | `200` | Hard cap on `GET /api/v1/log/entries?logIndex=` per second |
| `DURATION_SEC` | `300` | Total test duration |
| `READ_START_SEC` | `10` | Delay before reads begin, so writes build a backlog |

```sh
k6 run -e REKOR_URL=https://rekor.example.dev -e WRITE_RATE=150 tests/loadtest/k6_rekor_load_test.js
```

## How it works

`setup()` runs once and:

1. Health-checks `GET /api/v1/log`.
2. Generates a **single** ECDSA P-256 keypair, shared by every VU for the whole
   run. The private key is passed to VUs as a JWK and imported once per VU.
3. Submits one probe entry and uses the returned `logIndex` to establish the
   first index this run owns. This is more reliable than deriving a starting
   point from `treeSize`, which reports only the active shard.

Two `constant-arrival-rate` scenarios then run concurrently. Arrival-rate
executors hold the request rate constant regardless of server latency, adding
VUs as needed, so the configured rates are true rate targets and the read cap
is a real cap.

**Write scenario** (300/s for 5m). Each iteration builds a unique artifact
string, takes its SHA-256, and signs the artifact with ECDSA/SHA-256. Because
WebCrypto hashes the message itself, the resulting signature is over exactly
the digest submitted in `data.hash.value`, which is what `hashedrekord`
verifies. Uniqueness matters: Rekor rejects duplicate entries with 409, so each
digest is salted with a per-run nonce and the scenario's global iteration
number.

Two format conversions are required and are easy to get wrong:

- WebCrypto emits IEEE P1363 signatures (`r||s`); sigstore verifies ASN.1 DER.
- `pkg/pki/x509.NewPublicKey` only accepts a PEM-wrapped `PUBLIC KEY` block,
  not bare SPKI DER.

**Read scenario** (200/s, starting at 10s). Reads walk log indices
sequentially from the starting index, one per iteration, using
`exec.scenario.iterationInTest` as the cursor. That counter is unique and
monotonic across all VUs in the scenario, which gives a coordinated cursor
without shared state — k6 VUs run in isolated runtimes and cannot share a
queue. Since the reader runs slower than the writer (200/s vs 300/s) and starts
later, the cursor always trails committed entries. Each response is checked to
confirm the returned `logIndex` matches the one requested.

## Metrics and thresholds

| Metric | Threshold | Meaning |
| --- | --- | --- |
| `write_errors` | `rate<0.01` | Non-201 responses to entry creation |
| `read_errors` | `rate<0.01` | Non-200 responses, or a `logIndex` mismatch |
| `read_misses` | `rate<0.01` | 404s, i.e. the reader outran the writer |
| `write_latency` | `p(95)<2000` | Entry creation latency |
| `read_latency` | `p(95)<1000` | Entry retrieval latency |
| `dropped_iterations` | `count<100` | Non-zero means k6 could not sustain the configured rate within `maxVUs` |

`read_misses` and `dropped_iterations` are the two to watch when interpreting a
run. A rising `read_misses` rate means writes fell behind far enough that the
read cursor caught up, so read results are no longer measuring hits. Non-zero
`dropped_iterations` means the load generator, not the server, was the
constraint.

## Note on local runs

The default 300/200 QPS targets are meant for a representative deployment, not
a laptop. A single-host `docker compose` stack will not sustain them: write
latency is already around 190ms at 50 QPS, so k6 keeps allocating VUs as
latency degrades, and the run collapses.

For local smoke tests, drop the rates. This is a known-good configuration:

```sh
k6 run -e WRITE_RATE=50 -e READ_RATE=33 -e DURATION_SEC=60 -e READ_START_SEC=10 \
  tests/loadtest/k6_rekor_load_test.js
```

Before running locally, make sure no other `docker compose` projects are
competing for the container runtime. Stacks with `restart: always` come back
automatically after a runtime restart, and a second MySQL plus Trillian will
both contend for resources and collide on Trillian's ports (8090/8091). Check
with `docker compose ls -a`.
