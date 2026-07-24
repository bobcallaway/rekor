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
// this package: initialization and each background updater poll. Overridable
// via Config. Set large enough to accommodate a healthy Trillian response with
// margin, small enough that a hung backend cannot stall updater progress for
// more than one poll cycle — the updater is sequential, so a single stuck RPC
// blocks all subsequent polls until it returns or its deadline expires.
// Deadline expiry is treated as an updater error and feeds the existing
// exponential backoff.
const DefaultRootRPCTimeout = 3 * time.Second

// DefaultPollInterval is the steady cadence at which the background updater
// fetches the latest root. It can be overridden via Config. Lower values keep
// the cache fresher (lower read staleness and write latency) at the cost of
// more Trillian RPCs per shard per replica.
const DefaultPollInterval = 250 * time.Millisecond

const successfulRootFetchMaxPollIntervals = 3

var (
	metricUpdaterErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rekor_trillian_updater_errors_total",
			Help: "Total updater errors (wait/fetch/marshal).",
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
			Name:    "rekor_trillian_inclusion_wait_ms",
			Help:    "Time to obtain an inclusion proof (ms).",
			Buckets: prometheus.ExponentialBuckets(1, 2, 12),
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
			Name:    "rekor_trillian_hash_read_gate_wait_ms",
			Help:    "Time a hash-lookup miss spent waiting for the next updater fetch to complete before retrying (ms).",
			Buckets: prometheus.ExponentialBuckets(1, 2, 12),
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
)

// cachedClientConfig holds behavior settings for a single cachedTrillianClient.
// Zero values are replaced by package defaults in newCachedTrillianClient.
type cachedClientConfig struct {
	// RootRPCTimeout bounds every GetLatestSignedLogRoot RPC issued by this
	// client: initialization and each background updater poll. If <= 0,
	// DefaultRootRPCTimeout is used.
	RootRPCTimeout time.Duration
	// PollInterval is the steady cadence at which the background updater fetches
	// the latest root. If <= 0, DefaultPollInterval is used.
	PollInterval time.Duration
	// MaxSTHStaleness is the maximum age of the last successful root fetch for
	// an active tree before GetLatest returns Unavailable. If <= 0, it is
	// derived from three poll intervals plus RootRPCTimeout.
	MaxSTHStaleness time.Duration
	// FrozenTreeIDs is the set of tree IDs for frozen (inactive) logs. Cached
	// clients for these trees fetch the root once and never start the background
	// updater. Uses the empty-struct set idiom to make membership semantics clear.
	FrozenTreeIDs map[int64]struct{}
}

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
	config    cachedClientConfig
	frozen    bool // when true, the tree is frozen; no updater is started

	// shared inclusion-proof verifier
	v  *client.LogVerifier
	mu sync.Mutex
	// waitersHeap is a min-heap of *waiterItem ordered by target tree size.
	// notifyWaiters pops from the top while top.size <= newSize, giving
	// O(k_satisfied · log n) fan-out instead of O(n) on every advance.
	waitersHeap waiterHeap
	// waitersByCh maps a waiter's channel to its heap item so removeWaiter
	// (context cancellation) can locate and heap.Remove in O(log n) rather
	// than scanning the heap. Kept in lockstep with waitersHeap: every
	// register/notify/remove touches both. Invariant:
	// len(waitersByCh) == waitersHeap.Len().
	waitersByCh map[chan struct{}]*waiterItem
	wg          sync.WaitGroup

	// cached root snapshot (atomic for read-heavy paths)
	snapshot atomic.Value // stores rootSnapshot

	// nextGate is the fetch-gate representing the NEXT updater fetch that will
	// be issued. Its `done` channel is closed by the updater at the END of
	// that fetch's cycle. Readers capture nextGate AFTER their stale miss and
	// wait on `done`; by construction, the completing fetch's RPC was sent
	// strictly after the reader's Load. Nil for frozen trees (no updater
	// exists to close it). See updater doc for the timing argument.
	nextGate atomic.Pointer[fetchGate]

	// lifecycle. started is atomic to allow ensureStarted's hot path to skip
	// t.mu once initialization has succeeded; t.mu is still contended by the
	// updater's notify loop and waiter registration, so keeping the fast path
	// lock-free matters under high request load against an actively advancing tree.
	started atomic.Bool
	stopCh  chan struct{}

	// launchMu gates every background-work launch (init and the updater it
	// spawns). Any t.wg.Go for background work happens under launchMu after a
	// shuttingDown check. Close sets shuttingDown = true under launchMu BEFORE
	// calling t.wg.Wait, so a new Add cannot race Wait's return. Held only for
	// the brief moment it takes to observe/publish state — never across an RPC.
	launchMu     sync.Mutex
	shuttingDown bool
	initInFlight *initState

	// bgCtx is canceled on Close to interrupt any in-flight init or updater RPC.
	bgCtx    context.Context
	bgCancel context.CancelFunc
}

// initState carries the outcome of one in-flight init attempt. done is closed
// by the runner goroutine when it exits (success or failure); err is set
// before done is closed. Waiters read err after observing done.
type initState struct {
	done chan struct{}
	err  error
}

type rootSnapshot struct {
	root                    types.LogRootV1
	signed                  *trillian.SignedLogRoot
	lastSuccessfulRootFetch time.Time
}

func (t *cachedTrillianClient) recordSuccessfulRootFetch(at time.Time) {
	if t.frozen {
		return
	}
	metricLastSuccessfulRootFetch.WithLabelValues(t.treeIDStr).Set(float64(at.UnixNano()) / 1e9)
}

// fetchGate carries the completion signal for one specific upcoming updater
// fetch cycle. The updater installs a fresh gate at the START of each cycle
// (via atomic Swap on nextGate) and closes the PREVIOUS gate's `done` at the
// END of that cycle. A reader who captures a gate via t.nextGate.Load() and
// waits on `done` observes the completion of a fetch whose RPC was sent
// strictly after the reader's Load — the linearization point that lets us
// approximate read-your-writes without an on-demand refresh path.
//
// The gate is closed on every completed cycle (advance, no-advance, or RPC
// error), so a stuck-then-recovered Trillian doesn't turn a bounded wait into
// an unbounded one. The one exception is shutdown: if the updater exits via
// bgCtx cancellation, it does NOT close the current gate — readers select on
// bgCtx.Done() and take that branch, which returns Canceled directly rather
// than falling through to attempt a hash RPC against a shutting-down connection.
type fetchGate struct {
	done chan struct{}
}

// newCachedTrillianClient creates a cachedTrillianClient with the given Trillian client, log/tree ID, and config.
// If the tree ID appears in config.FrozenTreeIDs, the client fetches the root once during
// initialization and never starts the background updater, avoiding wasted RPCs on trees
// that will never advance.
func newCachedTrillianClient(logClient trillian.TrillianLogClient, logID int64, config cachedClientConfig) *cachedTrillianClient {
	if config.PollInterval <= 0 {
		config.PollInterval = DefaultPollInterval
	}
	if config.RootRPCTimeout <= 0 {
		config.RootRPCTimeout = DefaultRootRPCTimeout
	}
	if config.MaxSTHStaleness <= 0 {
		config.MaxSTHStaleness = successfulRootFetchMaxPollIntervals*config.PollInterval + config.RootRPCTimeout
	}
	_, frozen := config.FrozenTreeIDs[logID]
	treeIDStr := strconv.FormatInt(logID, 10)
	t := &cachedTrillianClient{
		client:      logClient,
		logID:       logID,
		treeIDStr:   treeIDStr,
		config:      config,
		frozen:      frozen,
		stopCh:      make(chan struct{}),
		waitersByCh: make(map[chan struct{}]*waiterItem),
	}
	t.bgCtx, t.bgCancel = context.WithCancel(context.Background())
	// initialize atomic snapshot with zero value
	t.snapshot.Store(rootSnapshot{})
	// Install the initial fetch-gate. The updater's first cycle will Swap it
	// out and close it at the end of that cycle. For frozen trees no updater
	// runs, so this gate is never closed — GetLeafAndProofByHash branches out
	// before it would wait on it.
	if !frozen {
		t.nextGate.Store(&fetchGate{done: make(chan struct{})})
	}
	return t
}

// waiterItem is one caller waiting for the cached tree size to reach `size`.
// index is the item's current position in waitersHeap; heap.Interface's Swap
// keeps it up to date so removeWaiter can heap.Remove in O(log n) without a
// linear scan. Set to -1 by Pop as a defensive sentinel after removal.
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

// registerWaiter adds a new waiter for the given tree size and returns its
// channel. O(log n). Must be called with t.mu held.
func (t *cachedTrillianClient) registerWaiter(size uint64) chan struct{} {
	ch := make(chan struct{})
	it := &waiterItem{ch: ch, size: size}
	heap.Push(&t.waitersHeap, it)
	t.waitersByCh[ch] = it
	return ch
}

// removeWaiter removes a waiter by its channel (used for cleanup on context
// cancellation). O(log n) via heap.Remove using the item's tracked index; the
// map lookup avoids scanning the heap. Must be called with t.mu held. No-op
// for a channel that is not registered.
func (t *cachedTrillianClient) removeWaiter(ch chan struct{}) {
	it, ok := t.waitersByCh[ch]
	if !ok {
		return
	}
	heap.Remove(&t.waitersHeap, it.index)
	delete(t.waitersByCh, ch)
}

// notifyWaiters closes the channels of all waiters whose requested size is
// satisfied by newSize, removes them from both the heap and the map, and does
// so in O(k_satisfied · log n) rather than O(n). Must be called with t.mu held.
//
// Correctness of the "pop while top ≤ newSize" loop rests on the min-heap
// invariant: if the smallest unsatisfied target is > newSize, no larger target
// can be satisfied either, so we can stop.
func (t *cachedTrillianClient) notifyWaiters(newSize uint64) {
	for len(t.waitersHeap) > 0 && t.waitersHeap[0].size <= newSize {
		it := heap.Pop(&t.waitersHeap).(*waiterItem)
		close(it.ch)
		delete(t.waitersByCh, it.ch)
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

	t.launchMu.Lock()
	if t.shuttingDown {
		t.launchMu.Unlock()
		return status.Error(codes.Canceled, "client closed")
	}
	s := t.initInFlight
	if s == nil {
		s = &initState{done: make(chan struct{})}
		t.initInFlight = s
		t.wg.Go(func() { t.runInit(s) })
	}
	t.launchMu.Unlock()

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
func (t *cachedTrillianClient) runInit(s *initState) {
	var attemptErr error
	defer func() {
		t.launchMu.Lock()
		if t.initInFlight == s {
			t.initInFlight = nil
		}
		t.launchMu.Unlock()

		s.err = attemptErr
		close(s.done)
	}()

	cctx, cancel := context.WithTimeout(t.bgCtx, t.config.RootRPCTimeout)
	defer cancel()
	slr, err := t.client.GetLatestSignedLogRoot(cctx, &trillian.GetLatestSignedLogRootRequest{LogId: t.logID})
	if err != nil {
		attemptErr = err
		return
	}
	if slr == nil || slr.SignedLogRoot == nil {
		attemptErr = fmt.Errorf("nil signed log root")
		return
	}
	r, uerr := internalclient.UnmarshalLogRoot(slr.SignedLogRoot.LogRoot)
	if uerr != nil {
		attemptErr = uerr
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
	t.v = client.NewLogVerifier(rfc6962.DefaultHasher)
	// Initial publish is a direct store, not publishRoot: the zero-value
	// snapshot has TreeSize 0 and publishRoot's advance-only check would
	// reject an initial root for an empty tree. This is the only ever-first
	// publish; nothing competes with it.
	fetchedAt := time.Now()
	t.snapshot.Store(rootSnapshot{root: r, signed: slr.SignedLogRoot, lastSuccessfulRootFetch: fetchedAt})
	t.recordSuccessfulRootFetch(fetchedAt)
	if !t.frozen {
		t.wg.Go(t.updater)
	}
	t.started.Store(true) // release-store; last publication under the locks
	t.mu.Unlock()
	t.launchMu.Unlock()
}

// publishRoot atomically updates the cached snapshot for every monotonic root
// fetch. It notifies size-based waiters and updates metricLatestTreeSize only
// when the tree strictly advances.
//
// Advance semantics:
//   - newRoot.TreeSize > current: publish, notify, update gauge, return true.
//   - newRoot.TreeSize == current with matching hash: refresh the signed root
//     and successful-fetch timestamp, then return false.
//   - newRoot.TreeSize < current: silently drop (stale/out-of-order response).
//     Retained as a defensive guard; with the on-demand refresh path removed,
//     only the updater publishes, but a delayed RPC response could still land
//     after bgCtx cancellation or across a hypothetical future concurrent path.
//   - newRoot.TreeSize == current but hash differs: integrity anomaly — log at
//     Error level, bump metricRootIntegrityAnomaly, and do NOT publish. A valid
//     Merkle tree cannot produce two distinct roots at the same size.
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
	fetchedAt := time.Now()

	// Smaller: out-of-order response, ignore.
	if newRoot.TreeSize < old.root.TreeSize {
		return false
	}
	// Equal size: not an advance; log an integrity anomaly if the hash differs.
	if newRoot.TreeSize == old.root.TreeSize {
		if !bytes.Equal(newRoot.RootHash, old.root.RootHash) {
			log.Logger.Errorw("trillian returned differing root hash at same tree size",
				"treeID", t.logID, "size", newRoot.TreeSize)
			metricRootIntegrityAnomaly.WithLabelValues(t.treeIDStr).Inc()
		}
		if !bytes.Equal(newRoot.RootHash, old.root.RootHash) {
			return false
		}
		t.snapshot.Store(rootSnapshot{root: newRoot, signed: signed, lastSuccessfulRootFetch: fetchedAt})
		t.recordSuccessfulRootFetch(fetchedAt)
		return false
	}

	t.snapshot.Store(rootSnapshot{root: newRoot, signed: signed, lastSuccessfulRootFetch: fetchedAt})
	t.recordSuccessfulRootFetch(fetchedAt)
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
// of local demand: in a multi-replica deployment the shared tree can advance
// due to writes handled by other replicas, so the cache must refresh even when
// this process issues no writes of its own.
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
		Min:    100 * time.Millisecond,
		Max:    10 * time.Second,
		Factor: 2.0,
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
		slr, err := t.client.GetLatestSignedLogRoot(cctx, &trillian.GetLatestSignedLogRootRequest{LogId: t.logID})
		cancel()
		if t.bgCtx.Err() != nil {
			// Shutdown path: intentionally do NOT close thisGate. See updater
			// doc; bgCtx wakes readers via their select and returns Canceled
			// without a fall-through RPC attempt.
			return
		}

		// Any other exit path (RPC success, RPC error, unmarshal error, empty
		// response) must close thisGate so waiting readers can retry-once.
		// Wrap in a closure so a single deferred close covers all branches.
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

			if slr == nil || slr.SignedLogRoot == nil {
				return
			}
			nr, uerr := internalclient.UnmarshalLogRoot(slr.SignedLogRoot.LogRoot)
			if uerr != nil {
				log.Logger.Debugw("failed to unmarshal latest log root", "treeID", t.logID, "err", uerr)
				metricUpdaterErrors.WithLabelValues(t.treeIDStr).Inc()
				return
			}
			// publishRoot enforces monotonic-advance and integrity checks.
			t.publishRoot(nr, slr.SignedLogRoot)
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
//  1. bgCancel() first (lock-free, idempotent) — cancels any in-flight init
//     or updater RPC and wakes fetch-gate waiters via their bgCtx.Done()
//     branch. Avoids holding shutdown up for RootRPCTimeout.
//
//  2. launchMu → set shuttingDown = true → release. This is the linearization
//     point for shutdown: no new wg.Go for background work can happen after
//     it (ensureStarted and runInit check shuttingDown under launchMu before
//     calling wg.Go). Prevents Add-vs-Wait races.
//
//  3. t.mu → close(stopCh) idempotently → drain the waiter heap and map →
//     release. publishRoot also checks stopCh under t.mu, so any late poll
//     that completes its RPC after this point observes the close and does
//     not publish.
//
//  4. wg.Wait() — reap all preexisting in-flight goroutines. Since
//     shuttingDown gates any future Add, the counter is monotonically
//     decreasing from here.
//
// The waitersByCh map is left non-nil (never set to nil) so any caller racing
// between our Unlock and their registerWaiter cannot panic assigning to a nil
// map — they will observe stopCh closed inside waitForRootAtLeast (its
// stopCh-under-t.mu check gates registration) and exit cleanly via codes.Canceled.
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
	// Drain the heap directly (single-pass over the underlying slice; heap
	// order doesn't matter for a full drain), close every waiter, and clear
	// the parallel map. waitersByCh stays non-nil for the Close-races-registerWaiter
	// guarantee documented above.
	for _, it := range t.waitersHeap {
		close(it.ch)
	}
	t.waitersHeap = nil
	for ch := range t.waitersByCh {
		delete(t.waitersByCh, ch)
	}
	t.mu.Unlock()
	t.wg.Wait()
}

func (t *cachedTrillianClient) AddLeaf(ctx context.Context, byteValue []byte) *internalclient.Response {
	if err := t.ensureStarted(ctx); err != nil {
		return &internalclient.Response{
			Status: status.Code(err),
			Err:    err,
		}
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
// miss, then retries against the fresh snapshot. If still not found, returns
// NotFound and lets the client SDK retry.
//
// This is a deliberate relaxation from the previous refresh-on-miss design.
// The direct client returned NotFound on any miss and relied on client-side
// retry for read-your-writes; the fetch-gate cached client offers the same
// contract with one round of automatic wait-and-retry, at the price of
// letting Trillian's own sequencer latency drive the timing rather than
// launching a dedicated per-miss RPC.
//
// For frozen trees there is no updater, so any stale-cache miss is authoritative
// — return NotFound directly without a gate wait.
func (t *cachedTrillianClient) GetLeafAndProofByHash(ctx context.Context, hash []byte) *internalclient.Response {
	if err := t.ensureStarted(ctx); err != nil {
		return &internalclient.Response{
			Status: status.Code(err),
			Err:    err,
		}
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
		snap = t.snapshot.Load().(rootSnapshot)
		proofResp = t.getProofByHashWithRoot(ctx, hash, snap.root, snap.signed)
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
// gate is nil for frozen trees; callers should short-circuit before invoking
// this function in that case.
func (t *cachedTrillianClient) waitForFetchGate(ctx context.Context, gate *fetchGate) error {
	start := time.Now()
	success := false
	defer func() {
		metricHashReadGateWait.WithLabelValues(t.treeIDStr, strconv.FormatBool(success)).Observe(float64(time.Since(start).Milliseconds()))
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
	if err := t.ensureStarted(ctx); err != nil {
		return &internalclient.Response{
			Status: status.Code(err),
			Err:    err,
		}
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

// buildIndexResp issues the GetEntryAndProof RPC against snap and returns the
// verified proof/leaf response. Extracted so the two paths in
// GetLeafAndProofByIndex (cache-authoritative and post-wait) can share it.
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
	if resp != nil && resp.Proof != nil {
		root := snap.root
		if err := t.v.VerifyInclusionByHash(&root, resp.GetLeaf().MerkleLeafHash, resp.Proof); err != nil {
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
	return &internalclient.Response{
		Status: codes.NotFound,
		Err:    fmt.Errorf("trillian returned empty response for index %d", index),
	}
}

// GetLatest returns the cached snapshot maintained by the background updater.
// It returns Unavailable when an active tree has not completed a valid root
// fetch within MaxSTHStaleness. Frozen trees are immutable after initialization
// and are therefore exempt from the active-tree freshness bound.
func (t *cachedTrillianClient) GetLatest(ctx context.Context) *internalclient.Response {
	if err := t.ensureStarted(ctx); err != nil {
		return &internalclient.Response{
			Status: status.Code(err),
			Err:    err,
		}
	}
	snap := t.snapshot.Load().(rootSnapshot)
	if !t.frozen && time.Since(snap.lastSuccessfulRootFetch) > t.config.MaxSTHStaleness {
		err := status.Errorf(codes.Unavailable, "cached signed log root is stale: last successful fetch was %s ago (maximum %s)", time.Since(snap.lastSuccessfulRootFetch).Round(time.Millisecond), t.config.MaxSTHStaleness)
		return &internalclient.Response{
			Status: codes.Unavailable,
			Err:    err,
		}
	}
	signed := snap.signed
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
		metricInclusionWait.WithLabelValues(t.treeIDStr, strconv.FormatBool(success)).Observe(float64(time.Since(start).Milliseconds()))
	}()

	// Optionally delay the very first attempt until minSize is reached.
	// If the current snapshot is already beyond minSize, this returns immediately.
	if err := t.waitForRootAtLeast(ctx, minSize); err != nil {
		return &internalclient.Response{Status: status.Code(err), Err: err}
	}

	for {
		if err := ctx.Err(); err != nil {
			return &internalclient.Response{Status: status.Code(err), Err: err}
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
	ch := t.registerWaiter(size)
	t.mu.Unlock()

	// Wait on channel, context, or stop.
	// When multiple channels fire simultaneously, select picks one
	// non-deterministically. After receiving from ch, we re-check stopCh
	// to avoid returning success during shutdown.
	select {
	case <-ch:
		select {
		case <-t.stopCh:
			return status.Error(codes.Canceled, "client closed")
		default:
		}
		return nil
	case <-ctx.Done():
		t.mu.Lock()
		t.removeWaiter(ch)
		t.mu.Unlock()
		return ctx.Err()
	case <-t.stopCh:
		t.mu.Lock()
		t.removeWaiter(ch)
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
