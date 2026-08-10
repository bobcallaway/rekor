//
// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package trillianclient

import (
	"bytes"
	"container/heap"
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/transparency-dev/merkle/rfc6962"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/client/backoff"
	"github.com/google/trillian/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	internalclient "github.com/sigstore/rekor/internal/trillianclient"
	"github.com/sigstore/rekor/pkg/log"
)

// DefaultRootRPCTimeout bounds any single GetLatestSignedLogRoot RPC issued by
// this package: initialization, each background updater poll, and each on-demand
// refresh. The updater is sequential, so one stuck RPC blocks every subsequent
// poll until it returns or its deadline expires; expiry is treated as an updater
// error and feeds the exponential backoff.
const DefaultRootRPCTimeout = 3 * time.Second

// DefaultPollInterval is the steady cadence at which the background updater
// fetches the latest root. Lower values keep the cache fresher (lower read
// staleness and write latency) at the cost of more Trillian RPCs per shard per
// rekor-server pod. It doubles as the floor between on-demand refreshes and
// between init attempts; see refreshRoot and joinInitFetch.
//
// The default matches Trillian's own --sequencer_interval default. A leaf is
// not integrated until the sequencer runs, so inclusion wait is two quantizers
// in series and mean wait is roughly sequencer_interval/2 + PollInterval/2.
// Polling faster than the sequencer grinds against that floor: measured mean
// inclusion wait improves only marginally below 100ms while root RPCs, and the
// checkpoint signatures they trigger, keep doubling.
const DefaultPollInterval = 100 * time.Millisecond

// MinPollInterval is the floor a configured PollInterval is clamped to. The
// cost of polling is linear in 1/PollInterval and permanent — it continues at
// full rate on an idle log — while the benefit bottoms out at the sequencer
// interval. A misconfigured 1ms would bill roughly 1000 root RPCs/sec/shard,
// each triggering a checkpoint signature, and buy nothing.
const MinPollInterval = 10 * time.Millisecond

// successfulRootFetchMaxPollIntervals is how many consecutive missed polls a
// derived MaxSTHStaleness tolerates before reads stop trusting the cache and
// pay for a synchronous refresh. Only used when MaxSTHStaleness is left unset;
// see newCachedTrillianClient.
//
// This is a deliberate availability-for-correctness trade, and it is a tight
// one: at the default PollInterval the derived bound is roughly 3*100ms + 3s,
// so a Trillian brownout that outlasts a few seconds turns every cached read
// into a 503 rather than serving a root nobody can vouch for. A transparency
// log's guarantee is what it signs, so failing is the correct default — but
// operators who would rather serve a slightly older root during a brownout
// should raise MaxSTHStaleness explicitly rather than widen PollInterval,
// which would degrade steady-state freshness too.
const successfulRootFetchMaxPollIntervals = 3

// Bounded exponential backoff applied to failed updater polls. updaterBackoffMax
// also sets the worst-case fetch-gate wait a reader can observe, since a gate
// closes only at the end of a cycle and a brownout stretches cycles out to the
// backoff ceiling.
const (
	updaterBackoffMin    = 100 * time.Millisecond
	updaterBackoffMax    = 10 * time.Second
	updaterBackoffFactor = 2.0
)

var (
	metricUpdaterErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rekor_trillian_updater_errors_total",
			Help: "Total background updater errors: a failed root RPC or a root that would not unmarshal.",
		},
		[]string{"tree"},
	)
	metricLatestTreeSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rekor_trillian_latest_tree_size",
			Help: "Latest observed tree size per tree.",
		},
		[]string{"tree"},
	)
	metricInclusionWait = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "rekor_trillian_inclusion_wait_seconds",
			Help:    "Time to obtain an inclusion proof.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 12),
		},
		[]string{"tree", "success"},
	)
	metricRootIntegrityAnomaly = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rekor_trillian_root_integrity_anomaly_total",
			Help: "Trillian returned a different root hash at an already-observed tree size. Should alert.",
		},
		[]string{"tree"},
	)
	metricHashReadGateWait = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "rekor_trillian_hash_read_gate_wait_seconds",
			Help:    "Time a hash-lookup miss spent waiting for the next updater fetch to complete before retrying.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 12),
		},
		[]string{"tree", "success"},
	)
	metricLastSuccessfulRootFetch = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rekor_trillian_sth_last_successful_root_fetch_timestamp_seconds",
			Help: "Unix timestamp of the last successfully validated active-tree STH fetch.",
		},
		[]string{"tree"},
	)
	// Counts RPCs, not callers: GetLatest callers that coalesce onto an existing
	// refresh or that hit the throttle issue no RPC and are not counted here, so
	// the rate reflects cost rather than request volume. Any nonzero rate means
	// the updater is not keeping the cache fresh on its own, which
	// metricLastSuccessfulRootFetch can no longer reveal by itself now that
	// refreshes also stamp it.
	metricRootRefresh = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rekor_trillian_sth_refresh_total",
			Help: "Synchronous STH refreshes issued because the cached root exceeded MaxSTHStaleness. Outcome is success, error (the RPC failed), or rejected (the RPC succeeded but the root could not be corroborated).",
		},
		[]string{"tree", "outcome"},
	)
)

// cachedTrillianClient provides a cached STH wrapper around the Trillian client
// with background root updates. Read-your-writes across pods is approximated
// via a fetch-gate primitive coordinated with the updater: on a hash-lookup
// stale miss, the reader waits for the next updater cycle whose RPC was sent
// strictly after the reader's miss, then retries once. See the updater and
// GetLeafAndProofByHash for the temporal-correctness argument.
type cachedTrillianClient struct {
	client    trillian.TrillianLogClient
	logID     int64
	treeIDStr string // strconv.FormatInt(logID, 10), used as the "tree" metric label
	config    Options
	frozen    bool // when true, the tree is frozen; no updater is started

	// v is set once by the constructor and never reassigned. LogVerifier is
	// stateless (it holds only the hasher), so it is safe for concurrent use
	// and needs no coordination with started.
	v  *client.LogVerifier
	mu sync.Mutex
	// waitersHeap is a min-heap of *waiterItem ordered by target tree size.
	// notifyWaiters pops from the top while top.size <= newSize, giving
	// O(k_satisfied · log n) fan-out instead of O(n) on every advance.
	waitersHeap waiterHeap
	wg          sync.WaitGroup

	// cached root snapshot (atomic for read-heavy paths)
	snapshot atomic.Value // stores rootSnapshot

	// lastRootFetch is the unix-nano time of the most recent root fetch whose
	// result we were able to corroborate, which is what the staleness check
	// reads. It is deliberately separate from the snapshot: a fetch can succeed
	// without publishing — an idle log returns the same size and hash on every
	// poll — and that is still evidence the log is alive.
	lastRootFetch atomic.Int64

	// nextGate is the fetch-gate representing the NEXT updater fetch that will
	// be issued. Its `done` channel is closed by the updater at the END of
	// that fetch's cycle. Readers capture nextGate AFTER their stale miss and
	// wait on `done`; by construction, the completing fetch's RPC was sent
	// strictly after the reader's Load. See updater doc for the timing argument.
	nextGate atomic.Pointer[fetchGate]

	// lifecycle. started is atomic to allow ensureStarted's hot path to skip
	// t.mu once initialization has succeeded; t.mu is still contended by the
	// updater's notify loop and waiter registration, so keeping the fast path
	// lock-free matters under high request load against an actively advancing tree.
	started atomic.Bool
	stopCh  chan struct{}

	// launchMu gates every background-work launch (init, on-demand refresh, and
	// the updater init spawns). Any t.wg.Go for background work happens under
	// launchMu after a shuttingDown check. Close sets shuttingDown = true under
	// launchMu BEFORE t.wg.Wait, so a new Add cannot race Wait's return. Held for
	// the brief moment it takes to observe/publish state — never across an RPC.
	launchMu        sync.Mutex
	shuttingDown    bool
	initInFlight    *rootFetch
	refreshInFlight *rootFetch
	// lastRefreshAttempt and lastInitAttempt are when the most recent on-demand
	// refresh and init attempt finished. Both guarded by launchMu; see
	// refreshRoot and joinInitFetch for why they exist.
	lastRefreshAttempt time.Time
	lastInitAttempt    time.Time

	// bgCtx is canceled on Close to interrupt any in-flight init or updater RPC.
	bgCtx    context.Context
	bgCancel context.CancelFunc
}

// rootFetch carries the outcome of one in-flight root fetch, whether an
// initialization or a staleness refresh. done is closed by the runner goroutine
// when it exits (success or failure); err is set before done is closed. Waiters
// read err after observing done.
type rootFetch struct {
	done chan struct{}
	err  error
}

type rootSnapshot struct {
	root   types.LogRootV1
	signed *trillian.SignedLogRoot
}

// stampRootFetch marks the log as corroborated as of now, resetting the window
// GetLatest's staleness check measures.
func (t *cachedTrillianClient) stampRootFetch() {
	now := time.Now()
	t.lastRootFetch.Store(now.UnixNano())
	if t.frozen {
		return
	}
	metricLastSuccessfulRootFetch.WithLabelValues(t.treeIDStr).Set(float64(now.UnixNano()) / 1e9)
}

func (t *cachedTrillianClient) storeSnapshot(root types.LogRootV1, signed *trillian.SignedLogRoot) {
	t.snapshot.Store(rootSnapshot{root: root, signed: signed})
	t.stampRootFetch()
}

// isStale reports whether the cached root has gone too long without
// corroboration. Frozen trees are immutable after initialization and are
// therefore exempt.
func (t *cachedTrillianClient) isStale() bool {
	return !t.frozen && t.rootAge() > t.config.MaxSTHStaleness
}

func (t *cachedTrillianClient) rootAge() time.Duration {
	return time.Since(time.Unix(0, t.lastRootFetch.Load()))
}

// fetchGate carries the completion signal for one specific upcoming updater
// fetch cycle. The updater installs a fresh gate at the START of each cycle
// (via atomic Swap on nextGate) and closes the PREVIOUS gate's `done` at the
// END of that cycle. A reader who captures a gate via t.nextGate.Load() and
// waits on `done` observes the completion of a fetch whose RPC was sent
// strictly after the reader's Load — the linearization point that lets us
// approximate read-your-writes off the updater's cadence alone, without each
// reader issuing its own root RPC.
//
// The gate is closed on every completed cycle (advance, no-advance, or RPC
// error), so a stuck-then-recovered Trillian doesn't strand readers forever.
// The wait is bounded by updaterBackoffMax + RootRPCTimeout, not by
// PollInterval: while Trillian is failing, consecutive cycles back off before
// closing their gates.
//
// The one exception is shutdown: if the updater exits via bgCtx cancellation,
// it does NOT close the current gate — readers select on bgCtx.Done() and take
// that branch, which returns Canceled directly rather than falling through to
// attempt a hash RPC against a shutting-down connection.
type fetchGate struct {
	done chan struct{}
}

// newCachedTrillianClient creates a cachedTrillianClient with the given Trillian client, log/tree ID, and config.
// If the tree ID appears in config.FrozenTreeIDs, the client fetches the root once during
// initialization and never starts the background updater, avoiding wasted RPCs on trees
// that will never advance.
func newCachedTrillianClient(logClient trillian.TrillianLogClient, logID int64, config Options) *cachedTrillianClient {
	if config.PollInterval <= 0 {
		config.PollInterval = DefaultPollInterval
	} else if config.PollInterval < MinPollInterval {
		log.Logger.Warnf("trillian sth_poll_interval %s is below the %s minimum; clamping. Polling faster than Trillian's sequencer cannot lower inclusion latency, it only multiplies root RPCs and checkpoint signatures.",
			config.PollInterval, MinPollInterval)
		config.PollInterval = MinPollInterval
	}
	if config.RootRPCTimeout <= 0 {
		config.RootRPCTimeout = DefaultRootRPCTimeout
	}
	if config.MaxSTHStaleness <= 0 {
		config.MaxSTHStaleness = successfulRootFetchMaxPollIntervals*config.PollInterval + config.RootRPCTimeout
	}
	_, frozen := config.FrozenTreeIDs[logID]
	t := &cachedTrillianClient{
		client:    logClient,
		logID:     logID,
		treeIDStr: strconv.FormatInt(logID, 10),
		config:    config,
		frozen:    frozen,
		stopCh:    make(chan struct{}),
		v:         client.NewLogVerifier(rfc6962.DefaultHasher),
	}
	t.bgCtx, t.bgCancel = context.WithCancel(context.Background())
	t.initErrorMetrics()
	// initialize atomic snapshot with zero value
	t.snapshot.Store(rootSnapshot{})
	// The updater's first cycle Swaps this out and closes it. Installed even for
	// frozen trees, which never start an updater, so the pointer is never nil and
	// a future caller that skips the frozen short-circuit cannot nil-deref.
	t.nextGate.Store(&fetchGate{done: make(chan struct{})})
	return t
}

// initErrorMetrics creates the zero-valued series that alerting reads, for this
// tree, at construction.
//
// A CounterVec has no series for a label set until something observes it, so on
// a healthy process these counters do not exist: `rate(...) > 0` evaluates
// against an empty vector and can never fire, and an `absent()` liveness guard
// cannot distinguish a healthy process from a broken scrape or a shard that was
// never wired up. Creating them at zero makes "no errors" an assertion the
// process actually publishes rather than the absence of one.
//
// Only the error-signalling series are pre-created. Success counters and the
// latency histograms are populated by ordinary traffic and carry no such
// alerting dependency.
func (t *cachedTrillianClient) initErrorMetrics() {
	metricUpdaterErrors.WithLabelValues(t.treeIDStr)
	metricRootIntegrityAnomaly.WithLabelValues(t.treeIDStr)
	for _, outcome := range []string{"error", "rejected"} {
		metricRootRefresh.WithLabelValues(t.treeIDStr, outcome)
	}
}

// waiterItem is one caller waiting for the cached tree size to reach `size`.
// index is the item's position in waitersHeap, kept current by the heap's Swap;
// it is set to -1 once the item leaves the heap, which is what makes
// removeWaiter idempotent for a waiter that was already notified or drained.
type waiterItem struct {
	ch    chan struct{}
	size  uint64
	index int
}

// waiterHeap is a min-heap of *waiterItem ordered by target size. Implements
// container/heap.Interface. Not safe for concurrent use; the caller must hold
// t.mu across any operation that mutates the heap.
type waiterHeap []*waiterItem

func (h waiterHeap) Len() int           { return len(h) }
func (h waiterHeap) Less(i, j int) bool { return h[i].size < h[j].size }
func (h waiterHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *waiterHeap) Push(x any) {
	it := x.(*waiterItem)
	it.index = len(*h)
	*h = append(*h, it)
}

func (h *waiterHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	old[n-1] = nil // avoid retaining a stale pointer for GC
	it.index = -1
	*h = old[:n-1]
	return it
}

// registerWaiter adds a new waiter for the given tree size. Must be called with
// t.mu held.
func (t *cachedTrillianClient) registerWaiter(size uint64) *waiterItem {
	it := &waiterItem{ch: make(chan struct{}), size: size}
	heap.Push(&t.waitersHeap, it)
	return it
}

// removeWaiter drops a waiter that gave up before being notified. Must be called
// with t.mu held. No-op once the item has left the heap (index -1), which is what
// makes the races against notifyWaiters and Close's drain safe.
func (t *cachedTrillianClient) removeWaiter(it *waiterItem) {
	if it.index < 0 {
		return
	}
	heap.Remove(&t.waitersHeap, it.index)
}

// notifyWaiters closes the channels of all waiters whose requested size is
// satisfied by newSize, in O(k_satisfied · log n) rather than O(n). Must be
// called with t.mu held.
//
// Correctness of the "pop while top ≤ newSize" loop rests on the min-heap
// invariant: if the smallest unsatisfied target is > newSize, no larger target
// can be satisfied either, so we can stop.
func (t *cachedTrillianClient) notifyWaiters(newSize uint64) {
	for len(t.waitersHeap) > 0 && t.waitersHeap[0].size <= newSize {
		it := heap.Pop(&t.waitersHeap).(*waiterItem)
		close(it.ch)
	}
}

// ensureStarted initializes the shared verifier and starts the updater once.
// The fast path (successful prior init) is lock-free via t.started.
//
// On the slow path, the init RPC runs in a background goroutine coalesced
// through t.initInFlight — concurrent first-callers share one RPC. Each caller
// selects on {initDone, ctx.Done(), bgCtx.Done()}, so a caller that gave up on
// its own deadline returns immediately without waiting RootRPCTimeout, and
// Close can cancel bgCtx without acquiring any init-related lock.
//
// The init goroutine uses t.bgCtx with RootRPCTimeout, not any caller's ctx,
// so a canceling first caller does not abort init for everyone. It runs under
// t.wg so Close's wg.Wait synchronizes with its exit.
//
// On failure t.initInFlight is cleared so the next caller triggers a fresh
// attempt; t.started stays false. On success t.started.Store(true) is the last
// write in the init critical section: any fast-path reader that observes
// Load()==true also observes the fully-initialized t.v, t.snapshot, and
// running updater goroutine.
func (t *cachedTrillianClient) ensureStarted(ctx context.Context) error {
	if t.started.Load() {
		return nil
	}
	s, err := t.joinInitFetch()
	if s == nil {
		return err
	}
	return t.awaitFetch(ctx, s)
}

// joinInitFetch returns the shared init fetch to wait on, spawning it if this
// caller is the first. A nil fetch with a nil error means there is nothing to
// wait for because init already succeeded.
//
// Init is bounded the same two ways refreshRoot is, and for the same reasons:
// initInFlight coalesces concurrent first-callers onto one RPC (bounding a slow
// Trillian), and lastInitAttempt enforces a PollInterval floor between attempts
// (bounding a fast-failing one, where each attempt clears initInFlight before
// the next request arrives and the RPC rate would otherwise track the request
// rate). Startup against a down Trillian is exactly when every request in
// flight is a first-caller, so the unthrottled shape is a stampede.
//
// Unlike refreshRoot, a throttled init returns an error rather than nil. There
// is no cached root to fall back on: reporting success here would let callers
// read the zero-value snapshot and serve tree size 0 as though it were real.
//
// Returning the fetch instead of waiting on it here is what lets launchMu be
// released by defer: the lock's lifetime is bounded by this function and cannot
// leak into the caller's blocking select.
func (t *cachedTrillianClient) joinInitFetch() (*rootFetch, error) {
	t.launchMu.Lock()
	defer t.launchMu.Unlock()

	// Re-check under the lock. runInit stores started=true and then clears
	// initInFlight in a separate later critical section, so a caller that read
	// started==false before the commit and reaches here after the clear would
	// otherwise see initInFlight==nil and launch a second init: a second
	// permanent updater goroutine, a storeSnapshot that bypasses publishRoot's
	// advance-only check, and a publish that never notifies waiters.
	if t.started.Load() {
		return nil, nil
	}
	if t.shuttingDown {
		return nil, status.Error(codes.Canceled, "client closed")
	}
	if s := t.initInFlight; s != nil {
		return s, nil
	}
	if !t.lastInitAttempt.IsZero() && time.Since(t.lastInitAttempt) < t.config.PollInterval {
		return nil, status.Error(codes.Unavailable, "trillian log root unavailable: initialization throttled after a recent failure")
	}
	s := &rootFetch{done: make(chan struct{})}
	t.initInFlight = s
	t.wg.Go(func() { t.runInit(s) })
	return s, nil
}

// awaitFetch blocks until a shared fetch finishes, this caller gives up, or the
// client closes. Giving up abandons the fetch rather than aborting it: it runs
// on bgCtx and is still owed to every other coalesced waiter.
func (t *cachedTrillianClient) awaitFetch(ctx context.Context, s *rootFetch) error {
	select {
	case <-s.done:
		return s.err
	case <-ctx.Done():
		// FromContextError maps context.DeadlineExceeded/Canceled to the
		// matching gRPC codes so the Response's Status reflects the real
		// cause rather than falling through to codes.Unknown.
		return status.FromContextError(ctx.Err()).Err()
	case <-t.bgCtx.Done():
		return status.Error(codes.Canceled, "client closed")
	}
}

// ensureFresh prepares the client to serve out of the cache: initialize on
// first use, then enforce the MaxSTHStaleness bound on the cached root,
// attempting one single-flighted refresh before giving up.
//
// Every path that returns a proof or a root must call this rather than
// ensureStarted alone. A proof is verified against snap.root and handed back
// with snap.signed, which Rekor signs into a checkpoint — so a root we have not
// been able to corroborate is exactly as unservable on the proof paths as it is
// on GetLatest. Gating only GetLatest would advertise a freshness bound while
// enforcing it on one of four entry points.
//
// Frozen trees are immutable after initialization; isStale exempts them.
func (t *cachedTrillianClient) ensureFresh(ctx context.Context) error {
	if err := t.ensureStarted(ctx); err != nil {
		return err
	}
	if !t.isStale() {
		return nil
	}
	if err := t.refreshRoot(ctx); err != nil {
		return err
	}
	// A nil error does not imply a fresh cache: the fetch may have been
	// throttled, or publishRoot may have declined to stamp an integrity
	// anomaly. Failing is better than serving a root we could not corroborate.
	if t.isStale() {
		return status.Errorf(codes.Unavailable, "cached signed log root is stale: last successful fetch was %s ago (maximum %s)", t.rootAge().Round(time.Millisecond), t.config.MaxSTHStaleness)
	}
	return nil
}

// runInit performs one initialization attempt in a background goroutine.
// Signals completion via close(s.done) and clears t.initInFlight so subsequent
// callers either see a completed init (via the t.started fast path) or trigger
// a fresh retry.
//
// On success, the publish + updater spawn + t.started store happen under
// launchMu (outer) + t.mu (inner). launchMu enforces the shuttingDown gate so
// no new wg.Go races Close's wg.Wait. t.mu keeps snapshot/started publication
// coherent with concurrent readers.
//
// Init does NOT touch nextGate. The initial gate was installed by
// newCachedTrillianClient; the updater's first cycle will Swap it out and
// close it. Any reader arriving after ensureStarted returns and before the
// first updater cycle completes will observe the initial gate; its wait
// resolves when cycle 1 closes it — cycle 1's RPC was sent strictly after
// cycle 1's Swap-out, which is strictly after the reader's Load. Correctness
// preserved without any init-side coordination with the gate.
func (t *cachedTrillianClient) runInit(s *rootFetch) {
	var attemptErr error
	defer func() {
		t.launchMu.Lock()
		// Stamp before clearing initInFlight so the next caller cannot observe
		// an empty slot with a stale attempt time and slip past the throttle.
		// Stamped unconditionally: on success started is true and the throttle
		// is never consulted again.
		t.lastInitAttempt = time.Now()
		if t.initInFlight == s {
			t.initInFlight = nil
		}
		t.launchMu.Unlock()

		s.err = attemptErr
		close(s.done)
	}()

	r, signed, err := t.fetchRoot()
	if err != nil {
		attemptErr = err
		return
	}

	// Commit under launchMu (shutdown gate) + t.mu (snapshot coherence).
	// Lock ordering: launchMu outer, t.mu inner — consistent everywhere.
	t.launchMu.Lock()
	if t.shuttingDown {
		t.launchMu.Unlock()
		attemptErr = status.Error(codes.Canceled, "client closed")
		return
	}
	t.mu.Lock()
	// Initial publish bypasses publishRoot: the zero-value snapshot has TreeSize
	// 0 and publishRoot's advance-only check would reject an initial root for an
	// empty tree. This is the only ever-first publish; nothing competes with it.
	t.storeSnapshot(r, signed)
	if !t.frozen {
		t.wg.Go(t.updater)
	}
	t.started.Store(true) // release-store; last publication under the locks
	t.mu.Unlock()
	t.launchMu.Unlock()
}

// fetchRoot issues one root fetch bounded by RootRPCTimeout. The context is
// bgCtx, never a caller's: the RPC is shared by every coalesced waiter, so one
// caller giving up must not abort it for the rest.
func (t *cachedTrillianClient) fetchRoot() (types.LogRootV1, *trillian.SignedLogRoot, error) {
	cctx, cancel := context.WithTimeout(t.bgCtx, t.config.RootRPCTimeout)
	defer cancel()
	return t.fetchAndVerifyRoot(cctx)
}

// fetchAndVerifyRoot issues one GetLatestSignedLogRoot on ctx and proves the
// returned root is an append-only extension of the root we already trust.
// Without this, a corrupted or forked log reporting a larger tree would be
// cached and then signed into a Rekor checkpoint unchallenged: publishRoot's
// same-size hash comparison cannot catch that, because a divergence would have
// to collide exactly on tree size to be noticed.
//
// FirstTreeSize asks Trillian for the consistency proof in the same transaction
// that reads the root, so verification costs no extra RPC and cannot race a
// later tree state. Trillian rejects the call outright if FirstTreeSize exceeds
// its own tree size, but that cannot happen here: every log server reads the
// same MySQL, so the size we cached was already committed there and the log
// never moves backwards.
func (t *cachedTrillianClient) fetchAndVerifyRoot(ctx context.Context) (types.LogRootV1, *trillian.SignedLogRoot, error) {
	trusted := t.snapshot.Load().(rootSnapshot).root

	slr, err := t.client.GetLatestSignedLogRoot(ctx, &trillian.GetLatestSignedLogRootRequest{
		LogId:         t.logID,
		FirstTreeSize: int64(trusted.TreeSize),
	})
	if err != nil {
		return types.LogRootV1{}, nil, err
	}
	if slr == nil || slr.SignedLogRoot == nil {
		return types.LogRootV1{}, nil, fmt.Errorf("nil signed log root")
	}
	r, err := internalclient.UnmarshalLogRoot(slr.SignedLogRoot.LogRoot)
	if err != nil {
		return types.LogRootV1{}, nil, err
	}

	// Only a strict advance needs a proof. A zero trusted size is the first root
	// we have ever seen and has nothing to be consistent with, and at an equal
	// size Trillian returns an empty proof whose only assertion — that the two
	// root hashes match — is exactly what publishRoot already checks.
	if trusted.TreeSize > 0 && r.TreeSize > trusted.TreeSize {
		if _, err := t.v.VerifyRoot(&trusted, slr.SignedLogRoot, slr.GetProof().GetHashes()); err != nil {
			log.Logger.Errorw("trillian root failed consistency verification",
				"treeID", t.logID, "from", trusted.TreeSize, "to", r.TreeSize, "err", err)
			metricRootIntegrityAnomaly.WithLabelValues(t.treeIDStr).Inc()
			return types.LogRootV1{}, nil, fmt.Errorf("root consistency verification failed %d->%d: %w", trusted.TreeSize, r.TreeSize, err)
		}
	}
	return r, slr.SignedLogRoot, nil
}

// refreshRoot attempts to restore freshness on demand when the cache has gone
// stale. A nil return does NOT mean the cache is now fresh — the fetch may have
// been throttled, or publishRoot may have refused the result — so the caller
// must re-check staleness either way.
//
// Two mechanisms bound the load this puts on an already-struggling Trillian,
// and both are needed because they cover opposite failure shapes:
//
//   - t.refreshInFlight coalesces concurrent callers onto one RPC. This bounds
//     a SLOW Trillian, where requests pile up during a fetch that runs to
//     RootRPCTimeout.
//   - lastRefreshAttempt enforces a PollInterval floor between fetches. This
//     bounds a FAST-FAILING Trillian, where each attempt returns in microseconds
//     and clears refreshInFlight before the next request arrives — coalescing
//     alone would degenerate to one RPC per request and turn a brownout into a
//     retry storm. PollInterval is the natural floor: the refresh exists to
//     cover polls the updater missed, so it need never outpace the updater.
//
// Waiting is shared with ensureStarted via awaitFetch: a caller that gives up
// returns immediately without aborting the shared fetch.
func (t *cachedTrillianClient) refreshRoot(ctx context.Context) error {
	s, err := t.joinRefreshFetch()
	if s == nil {
		return err
	}
	return t.awaitFetch(ctx, s)
}

// joinRefreshFetch returns the shared refresh fetch to wait on, spawning it if
// this caller is the first and the PollInterval floor allows it. A nil fetch
// with a nil error means the attempt was throttled — the caller's staleness
// re-check, not this return value, decides what that means.
//
// As in joinInitFetch, handing the fetch back rather than waiting on it keeps
// launchMu scoped to this function.
func (t *cachedTrillianClient) joinRefreshFetch() (*rootFetch, error) {
	t.launchMu.Lock()
	defer t.launchMu.Unlock()

	if t.shuttingDown {
		return nil, status.Error(codes.Canceled, "client closed")
	}
	if s := t.refreshInFlight; s != nil {
		return s, nil
	}
	if time.Since(t.lastRefreshAttempt) < t.config.PollInterval {
		return nil, nil
	}
	s := &rootFetch{done: make(chan struct{})}
	t.refreshInFlight = s
	t.wg.Go(func() { t.runRefresh(s) })
	return s, nil
}

// runRefresh performs one on-demand root fetch. It publishes through
// publishRoot rather than storing directly, so the monotonicity,
// integrity-anomaly, and post-Close guards apply to refreshes exactly as they
// do to updater polls. A nil error therefore means the RPC succeeded, not that
// the result was accepted — callers must re-check staleness.
func (t *cachedTrillianClient) runRefresh(s *rootFetch) {
	var attemptErr error
	defer func() {
		t.launchMu.Lock()
		// Stamp before clearing refreshInFlight so the next caller cannot
		// observe an empty slot with a stale attempt time and slip past the
		// throttle.
		t.lastRefreshAttempt = time.Now()
		if t.refreshInFlight == s {
			t.refreshInFlight = nil
		}
		t.launchMu.Unlock()

		s.err = attemptErr
		close(s.done)
	}()

	r, signed, err := t.fetchRoot()
	if err != nil {
		attemptErr = err
		metricRootRefresh.WithLabelValues(t.treeIDStr, "error").Inc()
		return
	}
	t.publishRoot(r, signed)
	// Staleness surviving the publish means publishRoot declined to corroborate
	// the root: an integrity anomaly, or a publish that lost the race with Close.
	// Counting either as a success would hide the exact case GetLatest's
	// post-refresh re-check exists to catch.
	outcome := "success"
	if t.isStale() {
		outcome = "rejected"
	}
	metricRootRefresh.WithLabelValues(t.treeIDStr, outcome).Inc()
}

// publishRoot decides what a freshly fetched root means for cached state. It
// replaces the snapshot only when the tree strictly advances, which is also the
// only case that notifies size-based waiters and updates metricLatestTreeSize.
// Every outcome except an integrity anomaly stamps the fetch timestamp.
//
// Advance semantics:
//   - newRoot.TreeSize > current: publish, notify, update gauge, return true.
//   - newRoot.TreeSize == current with matching hash: stamp the fetch timestamp
//     and return false without touching the snapshot. Trillian no longer signs
//     the root despite the SignedLogRoot name, so at an identical size and hash
//     the cached copy is equivalent to the new one — the only field that differs
//     is a timestamp nothing reads. Re-storing would churn the atomic on every
//     poll of an idle tree for no observable gain.
//   - newRoot.TreeSize < current: keep the cached root but still stamp the fetch
//     timestamp. This should be unobservable — every Trillian log server reads
//     the same MySQL, so the size we cached is already committed there and the
//     log cannot move backwards, whichever server answers. The branch is kept
//     as a guard so a shrinking tree can never overwrite a larger cached root.
//   - newRoot.TreeSize == current but hash differs: integrity anomaly — log at
//     Error level, bump metricRootIntegrityAnomaly, and do NOT publish. A valid
//     Merkle tree cannot produce two distinct roots at the same size. Note this
//     path also skips the fetch timestamp, so a persistent anomaly eventually
//     trips GetLatest's staleness check rather than serving a root we distrust.
//
// Also bails on <-t.stopCh so a late-arriving publish after Close does nothing.
// Acquires t.mu internally; caller must NOT hold it.
//
// Note: the fetch-gate is closed by the updater loop, NOT by publishRoot. A
// no-advance or errored cycle still closes its gate so gate waiters aren't
// stranded — but only publishRoot's successful path wakes size-based waiters.
func (t *cachedTrillianClient) publishRoot(newRoot types.LogRootV1, signed *trillian.SignedLogRoot) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	select {
	case <-t.stopCh:
		return false
	default:
	}

	old := t.snapshot.Load().(rootSnapshot)

	if newRoot.TreeSize < old.root.TreeSize {
		t.stampRootFetch()
		return false
	}
	if newRoot.TreeSize == old.root.TreeSize {
		if !bytes.Equal(newRoot.RootHash, old.root.RootHash) {
			log.Logger.Errorw("trillian returned differing root hash at same tree size",
				"treeID", t.logID, "size", newRoot.TreeSize)
			metricRootIntegrityAnomaly.WithLabelValues(t.treeIDStr).Inc()
			return false
		}
		t.stampRootFetch()
		return false
	}

	t.storeSnapshot(newRoot, signed)
	t.notifyWaiters(newRoot.TreeSize)
	metricLatestTreeSize.WithLabelValues(t.treeIDStr).Set(float64(newRoot.TreeSize))
	return true
}

// isCacheStaleMiss classifies a proof response as potentially caused by a stale
// cached tree size (i.e., the leaf may exist at Trillian's current size but not
// at ours). Only NotFound and OutOfRange qualify; other errors are real failures
// and should be surfaced to the caller.
func isCacheStaleMiss(resp *internalclient.Response) bool {
	if resp == nil || resp.Err == nil {
		return false
	}
	code := status.Code(resp.Err)
	return code == codes.NotFound || code == codes.OutOfRange
}

// updater polls Trillian for the latest root at a fixed cadence, publishing
// on every observed advance and closing the current fetch-gate on every
// completed cycle regardless of outcome. Polling is continuous and independent
// of local demand because the gate primitive and the size-based waiters both
// derive their liveness from cycles turning: an AddLeaf caller blocked in
// waitForRootAtLeast is woken only by a poll that observes the advance, and a
// hash-lookup miss is unblocked only by the next cycle closing its gate. A
// demand-driven updater would leave both parked. GetLatest is the one path that
// no longer depends on this, since refreshRoot can fetch on demand.
//
// The normal "no change yet" poll is not an error and simply waits one
// PollInterval before the next poll. A bounded exponential backoff applies only
// to genuine RPC failures. Each iteration waits exactly once — the wait duration
// is the backoff after a failed poll, or the steady PollInterval otherwise —
// so a Trillian hiccup doesn't stack backoff + PollInterval and delay recovery.
//
// Each poll RPC is bounded by RootRPCTimeout via a per-iteration derived
// context. Without this bound, a hung Trillian call would stall the updater
// indefinitely (the loop is single-goroutine sequential — one call at a time),
// freezing the cached snapshot and blocking every AddLeaf waiter until each
// caller's own HTTP context expired.
//
// Fetch-gate semantics (per cycle):
//  1. Swap in a fresh gate for the NEXT cycle. Any reader whose nextGate.Load
//     happens after this Swap will observe the new gate.
//  2. Send the RPC. Because the RPC send follows the Swap, its Trillian
//     observation is strictly after any Load that returned the previous gate.
//  3. Process response (advance / no-change / error).
//  4. Close the PREVIOUS gate's done — waking any reader who captured it.
//     Their retry sees a snapshot that reflects Trillian at RPC-send-time,
//     which is strictly after their miss.
//
// Shutdown exception: if bgCtx is canceled between Swap and post-RPC
// processing, the cycle exits early WITHOUT closing the gate. Readers
// select on bgCtx.Done() and take that branch, returning Canceled directly
// rather than falling through to attempt a hash RPC against a shutting-down
// gRPC connection.
func (t *cachedTrillianClient) updater() {
	errBackoff := backoff.Backoff{
		Min:    updaterBackoffMin,
		Max:    updaterBackoffMax,
		Factor: updaterBackoffFactor,
		Jitter: true,
	}
	// Starting with PollInterval also gives a just-queued leaf time to be
	// sequenced before the first post-init poll.
	nextWait := t.config.PollInterval
	for {
		select {
		case <-t.bgCtx.Done():
			return
		case <-time.After(nextWait):
		}

		// Install the fetch-gate for the NEXT cycle; the returned thisGate is
		// what readers observed before the Swap, and represents the fetch we
		// are about to issue.
		thisGate := t.nextGate.Swap(&fetchGate{done: make(chan struct{})})

		cctx, cancel := context.WithTimeout(t.bgCtx, t.config.RootRPCTimeout)
		nr, signed, err := t.fetchAndVerifyRoot(cctx)
		cancel()
		if t.bgCtx.Err() != nil {
			// Shutdown path: intentionally do NOT close thisGate. See updater
			// doc; bgCtx wakes readers via their select and returns Canceled
			// without a fall-through RPC attempt.
			return
		}

		// Every other exit path must close thisGate so waiting readers can
		// retry once, hence the deferred close in a closure.
		func() {
			defer close(thisGate.done)
			if err != nil {
				log.Logger.Debugw("trillian latest root fetch failed", "treeID", t.logID, "err", err)
				metricUpdaterErrors.WithLabelValues(t.treeIDStr).Inc()
				nextWait = errBackoff.Duration()
				return
			}
			errBackoff.Reset()
			nextWait = t.config.PollInterval

			// publishRoot enforces monotonic-advance and integrity checks; the
			// consistency proof was already verified by fetchAndVerifyRoot.
			t.publishRoot(nr, signed)
		}()
	}
}

// Close stops the updater and unblocks all waiters. Safe to call multiple times
// and from multiple goroutines: stopCh being closed is the idempotency guard for
// the not-safe-to-repeat steps (closing stopCh, closing waiter channels). A
// repeat caller still runs t.wg.Wait so the "Close returned ⇒ background work
// stopped" invariant holds regardless of call order.
//
// Ordering matters:
//
//  1. bgCancel() first (lock-free, idempotent) — cancels any in-flight init,
//     refresh, or updater RPC and wakes fetch-gate waiters via their
//     bgCtx.Done() branch. Avoids holding shutdown up for RootRPCTimeout.
//
//  2. launchMu → set shuttingDown = true → release. This is the linearization
//     point for shutdown: no new wg.Go for background work can happen after
//     it (ensureStarted, refreshRoot, and runInit check shuttingDown under
//     launchMu before calling wg.Go). Prevents Add-vs-Wait races.
//
//  3. t.mu → close(stopCh) idempotently → drain the waiter heap → release.
//     publishRoot also checks stopCh under t.mu, so any late poll that
//     completes its RPC after this point observes the close and does not
//     publish.
//
//  4. wg.Wait() — reap all preexisting in-flight goroutines. Since
//     shuttingDown gates any future Add, the counter is monotonically
//     decreasing from here.
//
// A caller racing between our Unlock and their registerWaiter cannot hang: they
// observe stopCh closed inside waitForRootAtLeast (its stopCh-under-t.mu check
// gates registration) and exit via codes.Canceled.
//
// nextGate is deliberately NOT closed here. Its `done` closure happens per
// cycle in the updater; on shutdown the updater exits without closing the
// current cycle's gate, and readers wake via bgCtx.Done() (see updater doc).
func (t *cachedTrillianClient) Close() {
	t.bgCancel()

	t.launchMu.Lock()
	t.shuttingDown = true
	t.launchMu.Unlock()

	t.mu.Lock()
	select {
	case <-t.stopCh:
		t.mu.Unlock()
		t.wg.Wait()
		return
	default:
	}
	close(t.stopCh)
	// Drain the heap directly; heap order doesn't matter for a full drain.
	// Clearing index is required, not cosmetic: a drained waiter that wakes and
	// takes its stopCh cleanup branch calls removeWaiter, which would otherwise
	// heap.Remove against the nil heap below.
	for _, it := range t.waitersHeap {
		it.index = -1
		close(it.ch)
	}
	t.waitersHeap = nil
	t.mu.Unlock()
	t.wg.Wait()
}

func (t *cachedTrillianClient) AddLeaf(ctx context.Context, byteValue []byte) *internalclient.Response {
	// Checked before QueueLeaf, not after. An AddLeaf that cannot corroborate
	// the root cannot finish: baselineSize below would be read from a root of
	// unknown age, and the inclusion proof would be built against it. Failing
	// after the queue succeeds is the worst outcome available — the caller sees
	// an error while the entry is permanently in the log — so refuse before
	// anything is written.
	if err := t.ensureFresh(ctx); err != nil {
		return rootFetchErrResp(ctx, err)
	}
	// Capture baseline tree size before queueing to set the first gate correctly.
	preSnap := t.snapshot.Load().(rootSnapshot)
	baselineSize := preSnap.root.TreeSize
	leaf := &trillian.LogLeaf{
		LeafValue: byteValue,
	}
	rqst := &trillian.QueueLeafRequest{
		LogId: t.logID,
		Leaf:  leaf,
	}
	resp, err := t.client.QueueLeaf(ctx, rqst)
	if err != nil {
		return &internalclient.Response{
			Status:       status.Code(err),
			Err:          err,
			GetAddResult: resp,
		}
	}
	if resp == nil || resp.QueuedLeaf == nil || resp.QueuedLeaf.Leaf == nil {
		return &internalclient.Response{
			Status: codes.Internal,
			Err:    fmt.Errorf("unexpected nil in QueueLeaf response"),
		}
	}
	// Non-OK insertion status (e.g. ALREADY_EXISTS) is not a gRPC error.
	// Return Status: OK with the response so callers can inspect QueuedLeaf.Status
	// to determine the insertion-level outcome (e.g. HTTP 409 for duplicates).
	if resp.QueuedLeaf.Status != nil && resp.QueuedLeaf.Status.Code != int32(codes.OK) {
		return &internalclient.Response{
			Status:       codes.OK,
			GetAddResult: resp,
		}
	}

	// Gate the first proof attempt on the next root advance relative to the
	// snapshot observed here. This avoids an almost-always NotFound on the
	// very first try and trims unnecessary RPCs without impacting latency
	// (we need a root advance to include the leaf anyway).
	minSize := baselineSize + 1
	proofResp := t.waitForInclusionWithMinSize(ctx, resp.QueuedLeaf.Leaf.MerkleLeafHash, minSize)
	if proofResp.Err != nil {
		return &internalclient.Response{
			Status:       status.Code(proofResp.Err),
			Err:          proofResp.Err,
			GetAddResult: resp,
		}
	}

	proofs := proofResp.GetProofResult.Proof
	if len(proofs) != 1 {
		err := fmt.Errorf("expected 1 proof from getProofByHash for %v, found %v", hex.EncodeToString(resp.QueuedLeaf.Leaf.MerkleLeafHash), len(proofs))
		return &internalclient.Response{
			Status:       status.Code(err),
			Err:          err,
			GetAddResult: resp,
		}
	}

	leafIndex := proofs[0].LeafIndex
	// fetch the leaf without re-requesting a proof (since we already have it)
	leafOnlyResp := t.getStandaloneLeaf(ctx, leafIndex, resp.QueuedLeaf.Leaf.MerkleLeafHash, proofs[0], proofResp.GetProofResult.SignedLogRoot)
	if leafOnlyResp.Err != nil {
		return &internalclient.Response{
			Status:       status.Code(leafOnlyResp.Err),
			Err:          leafOnlyResp.Err,
			GetAddResult: resp,
		}
	}

	// Copy this value explicitly because it contains the integrated timestamp
	resp.QueuedLeaf.Leaf = leafOnlyResp.GetLeafAndProofResult.Leaf

	return &internalclient.Response{
		Status:                codes.OK,
		GetAddResult:          resp,
		GetLeafAndProofResult: leafOnlyResp.GetLeafAndProofResult,
	}
}

// GetLeafAndProofByHash looks up a leaf by its Merkle hash and returns an
// inclusion proof against the cached snapshot. On a stale-cache miss (the leaf
// may exist in Trillian's current tree but not in our cached view), the reader
// waits for one updater fetch-gate cycle whose RPC send is provably after the
// miss, then retries once — but only if that cycle actually advanced the tree,
// since an unchanged root can only produce the same miss. If still not found,
// returns NotFound and lets the client SDK retry.
//
// That wait is what a miss costs: typically one PollInterval, but up to
// updaterBackoffMax + RootRPCTimeout while Trillian is unhealthy, versus the
// immediate NotFound the direct client returns. Callers that probe many hashes
// (SearchLogQuery) pay it per miss, sequentially.
//
// For frozen trees there is no updater, so any stale-cache miss is authoritative
// — return NotFound directly without a gate wait.
func (t *cachedTrillianClient) GetLeafAndProofByHash(ctx context.Context, hash []byte) *internalclient.Response {
	if err := t.ensureFresh(ctx); err != nil {
		return rootFetchErrResp(ctx, err)
	}
	snap := t.snapshot.Load().(rootSnapshot)
	proofResp := t.getProofByHashWithRoot(ctx, hash, snap.root, snap.signed)
	if isCacheStaleMiss(proofResp) && !t.frozen {
		// Capture the fetch-gate AFTER the miss. The gate's `done` will be
		// closed by the updater cycle whose Swap-in of the SUCCESSOR gate
		// followed this Load — i.e., whose RPC send is strictly after our
		// miss. Retry against the resulting fresh snapshot.
		gate := t.nextGate.Load()
		if err := t.waitForFetchGate(ctx, gate); err != nil {
			// Prefer surfacing a retryable code over falsifying NotFound.
			return &internalclient.Response{
				Status: status.Code(err),
				Err:    err,
			}
		}
		// A cycle completes whether or not it advanced the tree — it may have
		// failed its RPC, or simply found no new leaves. The set of leaves
		// answerable by hash is determined by the tree size, so retrying against
		// an unchanged root would re-issue the identical query and buy the
		// identical miss. Keep the first response as the answer.
		if newSnap := t.snapshot.Load().(rootSnapshot); newSnap.root.TreeSize > snap.root.TreeSize {
			snap = newSnap
			proofResp = t.getProofByHashWithRoot(ctx, hash, snap.root, snap.signed)
		}
	}
	if proofResp.Err != nil {
		return &internalclient.Response{
			Status: status.Code(proofResp.Err),
			Err:    proofResp.Err,
		}
	}
	proofs := proofResp.GetProofResult.Proof
	if len(proofs) != 1 {
		err := fmt.Errorf("expected 1 proof from getProofByHash for %v, found %v", hex.EncodeToString(hash), len(proofs))
		return &internalclient.Response{
			Status: status.Code(err),
			Err:    err,
		}
	}

	leafIndex := proofs[0].LeafIndex
	// fetch the leaf without re-requesting a proof (since we already have it)
	leafOnlyResp := t.getStandaloneLeaf(ctx, leafIndex, hash, proofs[0], proofResp.GetProofResult.SignedLogRoot)
	if leafOnlyResp.Err != nil {
		return &internalclient.Response{
			Status: status.Code(leafOnlyResp.Err),
			Err:    leafOnlyResp.Err,
		}
	}

	return leafOnlyResp
}

// waitForFetchGate blocks until `gate.done` closes, or ctx expires, or the
// client is shutting down. Emits the wait-time histogram regardless of outcome.
func (t *cachedTrillianClient) waitForFetchGate(ctx context.Context, gate *fetchGate) error {
	start := time.Now()
	success := false
	defer func() {
		metricHashReadGateWait.WithLabelValues(t.treeIDStr, strconv.FormatBool(success)).Observe(time.Since(start).Seconds())
	}()

	select {
	case <-gate.done:
		success = true
		return nil
	case <-ctx.Done():
		return status.FromContextError(ctx.Err()).Err()
	case <-t.bgCtx.Done():
		return status.Error(codes.Canceled, "client closed")
	}
}

// GetLeafAndProofByIndex returns the leaf at the given index with an inclusion
// proof against the cached snapshot. If the index is below cached TreeSize the
// cache is authoritative (Trillian logs are dense over indices) and we serve
// immediately. Otherwise the reader waits for one fetch-gate cycle and
// retries once against the post-cycle snapshot; if still out of range,
// returns NotFound.
//
// The fetch-gate is shared with GetLeafAndProofByHash so a wave of out-of-
// range index reads and hash misses both coalesce onto the same updater poll.
// The one-shot semantic preserves the previous contract: NotFound after one
// wait means "this index is not in Trillian's currently-observable tree,"
// leaving retry policy to the client SDK. For frozen trees, an out-of-cache-
// range index returns NotFound directly (no updater exists to wait on).
func (t *cachedTrillianClient) GetLeafAndProofByIndex(ctx context.Context, index int64) *internalclient.Response {
	// Reject malformed input BEFORE ensureStarted so a bad request doesn't
	// induce init RPCs.
	if index < 0 {
		return &internalclient.Response{
			Status: codes.InvalidArgument,
			Err:    status.Errorf(codes.InvalidArgument, "negative leaf index %d", index),
		}
	}
	if err := t.ensureFresh(ctx); err != nil {
		return rootFetchErrResp(ctx, err)
	}
	snap := t.snapshot.Load().(rootSnapshot)
	if uint64(index) < snap.root.TreeSize {
		// Cache is authoritative: the leaf provably exists in this snap
		// (Trillian's log is dense over indices, so index in [0, TreeSize)
		// always has a leaf). No wait needed.
		return t.buildIndexResp(ctx, index, snap)
	}
	if t.frozen {
		return &internalclient.Response{
			Status: codes.NotFound,
			Err:    status.Errorf(codes.NotFound, "leaf index %d out of range for frozen tree size %d", index, snap.root.TreeSize),
		}
	}
	// Out of cache range: wait for one updater fetch-gate cycle whose RPC
	// was sent strictly after this Load, then retry against the post-cycle
	// snapshot. See GetLeafAndProofByHash for the temporal-correctness
	// argument.
	gate := t.nextGate.Load()
	if err := t.waitForFetchGate(ctx, gate); err != nil {
		return &internalclient.Response{
			Status: status.Code(err),
			Err:    err,
		}
	}
	snap = t.snapshot.Load().(rootSnapshot)
	if uint64(index) >= snap.root.TreeSize {
		return &internalclient.Response{
			Status: codes.NotFound,
			Err:    status.Errorf(codes.NotFound, "leaf index %d out of range for tree size %d", index, snap.root.TreeSize),
		}
	}
	return t.buildIndexResp(ctx, index, snap)
}

func (t *cachedTrillianClient) buildIndexResp(ctx context.Context, index int64, snap rootSnapshot) *internalclient.Response {
	resp, err := t.client.GetEntryAndProof(ctx, &trillian.GetEntryAndProofRequest{
		LogId:     t.logID,
		LeafIndex: index,
		TreeSize:  int64(snap.root.TreeSize),
	})
	if err != nil {
		return &internalclient.Response{
			Status: status.Code(err),
			Err:    err,
		}
	}
	if resp == nil || resp.Proof == nil {
		return &internalclient.Response{
			Status: codes.NotFound,
			Err:    fmt.Errorf("trillian returned empty response for index %d", index),
		}
	}
	if resp.Leaf == nil {
		return &internalclient.Response{
			Status: codes.Internal,
			Err:    fmt.Errorf("trillian returned a proof with no leaf for index %d", index),
		}
	}
	// Bind the proof to the index the caller asked about. VerifyInclusionByHash
	// verifies at proof.LeafIndex, which the response supplies, so on its own it
	// only proves "this leaf is somewhere in the tree" — a response carrying
	// leaf j with a valid proof for j would satisfy a request for leaf i. The
	// hash-lookup paths are bound by the requested hash instead; an index lookup
	// has nothing but the index to bind to.
	if resp.Proof.LeafIndex != index {
		return &internalclient.Response{
			Status: codes.Internal,
			Err:    fmt.Errorf("trillian returned a proof for index %d, but index %d was requested", resp.Proof.LeafIndex, index),
		}
	}
	root := snap.root
	if err := t.v.VerifyInclusionByHash(&root, resp.Leaf.MerkleLeafHash, resp.Proof); err != nil {
		return &internalclient.Response{
			Status: status.Code(err),
			Err:    err,
		}
	}
	return &internalclient.Response{
		Status: codes.OK,
		GetLeafAndProofResult: &trillian.GetEntryAndProofResponse{
			Proof:         resp.Proof,
			Leaf:          resp.Leaf,
			SignedLogRoot: snap.signed,
		},
	}
}

// rootFetchErrResp renders a failed init or refresh as a response. Every
// server-side reason a root fetch can fail — RPC error, RootRPCTimeout, client
// shutdown — is transient from the caller's point of view, so all of them
// collapse to Unavailable. The timeout case is why this exists: it is the
// ordinary signature of a Trillian brownout, and status.Code would surface it
// as DeadlineExceeded, which pkg/api reports as HTTP 500 — a server defect
// rather than the "retry shortly" the situation calls for.
//
// A caller whose own context ended is the exception: its error passes through
// untouched so an abandoned request is not recorded as a Trillian outage. So
// does an error that already says Unavailable — chiefly ensureFresh's staleness
// error, whose message names the actual age and bound and would only be
// obscured by re-wrapping.
func rootFetchErrResp(ctx context.Context, err error) *internalclient.Response {
	if ctx.Err() != nil || status.Code(err) == codes.Unavailable {
		return &internalclient.Response{
			Status: status.Code(err),
			Err:    err,
		}
	}
	return &internalclient.Response{
		Status: codes.Unavailable,
		Err:    status.Errorf(codes.Unavailable, "could not fetch signed log root: %v", err),
	}
}

// GetLatest returns the cached snapshot maintained by the background updater.
// When an active tree's cached root has gone longer than MaxSTHStaleness
// without corroboration, it first attempts a synchronous single-flighted
// refresh; only if that fails to restore freshness does it return Unavailable.
// Frozen trees are immutable after initialization and are therefore exempt from
// the freshness bound.
func (t *cachedTrillianClient) GetLatest(ctx context.Context) *internalclient.Response {
	if err := t.ensureFresh(ctx); err != nil {
		return rootFetchErrResp(ctx, err)
	}
	signed := t.snapshot.Load().(rootSnapshot).signed
	if signed == nil {
		return &internalclient.Response{
			Status: codes.NotFound,
			Err:    status.Error(codes.NotFound, "no signed root available"),
		}
	}
	return &internalclient.Response{
		Status: codes.OK,
		GetLatestResult: &trillian.GetLatestSignedLogRootResponse{
			SignedLogRoot: signed,
		},
	}
}

func (t *cachedTrillianClient) GetConsistencyProof(ctx context.Context, firstSize, lastSize int64) *internalclient.Response {
	resp, err := t.client.GetConsistencyProof(ctx, &trillian.GetConsistencyProofRequest{
		LogId:          t.logID,
		FirstTreeSize:  firstSize,
		SecondTreeSize: lastSize,
	})
	return &internalclient.Response{
		Status:                    status.Code(err),
		Err:                       err,
		GetConsistencyProofResult: resp,
	}
}

func (t *cachedTrillianClient) getProofByHashWithRoot(ctx context.Context, hashValue []byte, root types.LogRootV1, signed *trillian.SignedLogRoot) *internalclient.Response {
	// issue 1308: if the tree is empty, there's no way we can return a proof
	if root.TreeSize == 0 {
		return &internalclient.Response{
			Status: codes.NotFound,
			Err:    status.Error(codes.NotFound, "tree is empty"),
		}
	}
	resp, err := t.client.GetInclusionProofByHash(ctx, &trillian.GetInclusionProofByHashRequest{
		LogId:    t.logID,
		LeafHash: hashValue,
		TreeSize: int64(root.TreeSize), //nolint:gosec
	})
	if err != nil {
		return &internalclient.Response{
			Status: status.Code(err),
			Err:    err,
		}
	}
	if resp != nil {
		for _, p := range resp.Proof {
			if err := t.v.VerifyInclusionByHash(&root, hashValue, p); err != nil {
				return &internalclient.Response{
					Status: status.Code(err),
					Err:    err,
				}
			}
		}
		return &internalclient.Response{
			Status: codes.OK,
			GetProofResult: &trillian.GetInclusionProofByHashResponse{
				Proof:         resp.Proof,
				SignedLogRoot: signed,
			},
		}
	}
	return &internalclient.Response{
		Status: codes.Unknown,
		Err:    fmt.Errorf("trillian returned empty proof for hash %s", hex.EncodeToString(hashValue)),
	}
}

// waitForInclusionWithMinSize behaves like waitForInclusion but ensures the
// first inclusion-proof attempt happens only after the tree has reached at
// least minSize. This reduces initial NotFound churn without increasing time
// to success (since inclusion requires a root advance).
func (t *cachedTrillianClient) waitForInclusionWithMinSize(ctx context.Context, leafHash []byte, minSize uint64) *internalclient.Response {
	start := time.Now()
	success := false
	defer func() {
		metricInclusionWait.WithLabelValues(t.treeIDStr, strconv.FormatBool(success)).Observe(time.Since(start).Seconds())
	}()

	// Optionally delay the very first attempt until minSize is reached.
	// If the current snapshot is already beyond minSize, this returns immediately.
	if err := t.waitForRootAtLeast(ctx, minSize); err != nil {
		return &internalclient.Response{Status: status.Code(err), Err: err}
	}

	for {
		if err := ctx.Err(); err != nil {
			serr := status.FromContextError(err).Err()
			return &internalclient.Response{Status: status.Code(serr), Err: serr}
		}
		snap := t.snapshot.Load().(rootSnapshot)
		root := snap.root
		signed := snap.signed

		proofResp := t.getProofByHashWithRoot(ctx, leafHash, root, signed)
		if proofResp.Err == nil || status.Code(proofResp.Err) != codes.NotFound {
			success = proofResp.Err == nil
			return proofResp
		}

		// NotFound: wait for the tree to grow and try again
		if err := t.waitForRootAtLeast(ctx, root.TreeSize+1); err != nil {
			return &internalclient.Response{Status: status.Code(err), Err: err}
		}
	}
}

// waitForRootAtLeast blocks until the cached root TreeSize >= size, or context/client closes.
// For frozen trees, returns immediately with an error if the current size is insufficient,
// since the tree will never advance.
func (t *cachedTrillianClient) waitForRootAtLeast(ctx context.Context, size uint64) error {
	cur := t.snapshot.Load().(rootSnapshot)
	if cur.root.TreeSize >= size {
		return nil
	}

	// Frozen trees will never advance; fail immediately rather than blocking forever.
	if t.frozen {
		return status.Errorf(codes.FailedPrecondition, "tree %d is frozen at size %d, requested %d", t.logID, cur.root.TreeSize, size)
	}

	// Register waiter
	t.mu.Lock()
	// If Close ran between the fast path and now, fail immediately rather than
	// registering a waiter that will never be signaled by an advance.
	select {
	case <-t.stopCh:
		t.mu.Unlock()
		return status.Error(codes.Canceled, "client closed")
	default:
	}
	// Re-check under lock (snapshot may have advanced)
	cur = t.snapshot.Load().(rootSnapshot)
	if cur.root.TreeSize >= size {
		t.mu.Unlock()
		return nil
	}
	it := t.registerWaiter(size)
	t.mu.Unlock()

	// Wait on channel, context, or stop.
	// When multiple channels fire simultaneously, select picks one
	// non-deterministically. After receiving from ch, we re-check stopCh
	// to avoid returning success during shutdown.
	select {
	case <-it.ch:
		select {
		case <-t.stopCh:
			return status.Error(codes.Canceled, "client closed")
		default:
		}
		return nil
	case <-ctx.Done():
		t.mu.Lock()
		t.removeWaiter(it)
		t.mu.Unlock()
		return status.FromContextError(ctx.Err()).Err()
	case <-t.stopCh:
		t.mu.Lock()
		t.removeWaiter(it)
		t.mu.Unlock()
		return status.Error(codes.Canceled, "client closed")
	}
}

// GetLeavesByRange fetches leaves from startIndex (inclusive) up to count leaves without proofs.
func (t *cachedTrillianClient) GetLeavesByRange(ctx context.Context, startIndex, count int64) *internalclient.Response {
	resp, err := t.client.GetLeavesByRange(ctx, &trillian.GetLeavesByRangeRequest{
		LogId:      t.logID,
		StartIndex: startIndex,
		Count:      count,
	})
	return &internalclient.Response{
		Status:                 status.Code(err),
		Err:                    err,
		GetLeavesByRangeResult: resp,
	}
}

// GetLeafWithoutProof is a convenience wrapper for fetching a single leaf by index without proofs.
func (t *cachedTrillianClient) GetLeafWithoutProof(ctx context.Context, index int64) *internalclient.Response {
	return t.GetLeavesByRange(ctx, index, 1)
}

// getStandaloneLeaf gets just the leaf, returns it in GetLeafAndProof result for easier reuse
func (t *cachedTrillianClient) getStandaloneLeaf(ctx context.Context, index int64, hash []byte, proof *trillian.Proof, signedRoot *trillian.SignedLogRoot) *internalclient.Response {
	leafOnlyResp := t.GetLeafWithoutProof(ctx, index)
	if leafOnlyResp.Err != nil {
		return &internalclient.Response{
			Status: status.Code(leafOnlyResp.Err),
			Err:    leafOnlyResp.Err,
		}
	}

	if leafOnlyResp.GetLeavesByRangeResult == nil || len(leafOnlyResp.GetLeavesByRangeResult.Leaves) == 0 {
		err := fmt.Errorf("no leaf returned for index %d", index)
		return &internalclient.Response{
			Status: codes.NotFound,
			Err:    err,
		}
	}
	// shouldn't happen since we're using a log mode that prevents duplicates
	if len(leafOnlyResp.GetLeavesByRangeResult.Leaves) != 1 {
		err := fmt.Errorf("multiple leaves returned for index %d", index)
		return &internalclient.Response{
			Status: codes.FailedPrecondition,
			Err:    err,
		}
	}
	leaf := leafOnlyResp.GetLeavesByRangeResult.Leaves[0]

	if !bytes.Equal(leaf.MerkleLeafHash, hash) {
		// extremely unlikely but this means the index in the proof doesn't match the content stored in the index
		err := fmt.Errorf("leaf hash mismatch: expected %v, got %v", hex.EncodeToString(hash), hex.EncodeToString(leaf.MerkleLeafHash))
		return &internalclient.Response{
			Status: status.Code(err),
			Err:    err,
		}
	}

	return &internalclient.Response{
		Status: codes.OK,
		GetLeafAndProofResult: &trillian.GetEntryAndProofResponse{
			Proof:         proof,
			Leaf:          leaf,
			SignedLogRoot: signedRoot,
		},
	}
}
