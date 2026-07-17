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
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/testonly"
	"github.com/google/trillian/types"
	"github.com/prometheus/client_golang/prometheus/testutil"
	internalclient "github.com/sigstore/rekor/internal/trillianclient"
	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/merkle/rfc6962"
	"go.uber.org/goleak"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// advanceRoot updates the cached snapshot and notifies waiters via the channel-per-caller mechanism.
func advanceRoot(t *testing.T, tc *cachedTrillianClient, size uint64, rootHash []byte) {
	t.Helper()
	lr := &types.LogRootV1{TreeSize: size, RootHash: rootHash}
	b, err := lr.MarshalBinary()
	require.NoError(t, err)
	tc.mu.Lock()
	tc.snapshot.Store(rootSnapshot{root: *lr, signed: &trillian.SignedLogRoot{LogRoot: b}})
	tc.notifyWaiters(size)
	tc.mu.Unlock()
}

// waitForWaiters blocks until at least n callers have registered in tc.waitersByCh,
// or fails the test after a timeout. Replaces fragile time.Sleep registration barriers.
func waitForWaiters(t *testing.T, tc *cachedTrillianClient, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		tc.mu.Lock()
		got := len(tc.waitersByCh)
		tc.mu.Unlock()
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d waiters to register, got %d", n, got)
		}
		runtime.Gosched()
	}
}

type fakeCloseTrackingClient struct {
	closeCalls atomic.Int32
}

func (f *fakeCloseTrackingClient) AddLeaf(_ context.Context, _ []byte) *internalclient.Response {
	return &internalclient.Response{Status: codes.OK}
}

func (f *fakeCloseTrackingClient) GetLatest(_ context.Context) *internalclient.Response {
	return &internalclient.Response{Status: codes.OK}
}

func (f *fakeCloseTrackingClient) GetLeafAndProofByHash(_ context.Context, _ []byte) *internalclient.Response {
	return &internalclient.Response{Status: codes.OK}
}

func (f *fakeCloseTrackingClient) GetLeafAndProofByIndex(_ context.Context, _ int64) *internalclient.Response {
	return &internalclient.Response{Status: codes.OK}
}

func (f *fakeCloseTrackingClient) GetConsistencyProof(_ context.Context, _, _ int64) *internalclient.Response {
	return &internalclient.Response{Status: codes.OK}
}

func (f *fakeCloseTrackingClient) GetLeavesByRange(_ context.Context, _, _ int64) *internalclient.Response {
	return &internalclient.Response{Status: codes.OK}
}

func (f *fakeCloseTrackingClient) GetLeafWithoutProof(_ context.Context, _ int64) *internalclient.Response {
	return &internalclient.Response{Status: codes.OK}
}

func (f *fakeCloseTrackingClient) Close() {
	f.closeCalls.Add(1)
}

func (f *fakeCloseTrackingClient) CloseCalls() int32 {
	return f.closeCalls.Load()
}

func TestEnsureStartedAndGetLatest(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	// Initial root (empty tree)
	slr := mkSLR(t, 0, make([]byte, 32))
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: slr}, nil).MinTimes(1)

	conn := dialMock(t, s.Addr)
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 42, cachedClientConfig{})
	t.Cleanup(tc.Close)

	resp := tc.GetLatest(context.Background())
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.NotNil(t, resp.GetLatestResult)
	require.NotNil(t, resp.GetLatestResult.SignedLogRoot)

	// Unmarshal and check size
	var got types.LogRootV1
	require.NoError(t, got.UnmarshalBinary(resp.GetLatestResult.SignedLogRoot.LogRoot))
	require.EqualValues(t, 0, got.TreeSize)
}

func TestGetLatest_RejectsStaleActiveRoot(t *testing.T) {
	tc := newCachedTrillianClient(nil, 790, cachedClientConfig{MaxSTHStaleness: time.Second})
	tc.started.Store(true)
	tc.snapshot.Store(rootSnapshot{
		root:                    types.LogRootV1{TreeSize: 1},
		signed:                  mkSLR(t, 1, make([]byte, 32)),
		lastSuccessfulRootFetch: time.Now().Add(-2 * time.Second),
	})
	t.Cleanup(tc.Close)

	resp := tc.GetLatest(context.Background())
	require.Equal(t, codes.Unavailable, resp.Status)
	require.Error(t, resp.Err)
}

func TestGetLatest_AllowsStaleFrozenRoot(t *testing.T) {
	tc := newCachedTrillianClient(nil, 791, cachedClientConfig{
		MaxSTHStaleness: time.Second,
		FrozenTreeIDs:   map[int64]struct{}{791: {}},
	})
	tc.started.Store(true)
	tc.snapshot.Store(rootSnapshot{
		root:                    types.LogRootV1{TreeSize: 1},
		signed:                  mkSLR(t, 1, make([]byte, 32)),
		lastSuccessfulRootFetch: time.Now().Add(-2 * time.Second),
	})
	t.Cleanup(tc.Close)

	resp := tc.GetLatest(context.Background())
	require.Equal(t, codes.OK, resp.Status)
	require.NoError(t, resp.Err)
}

func TestPublishRoot_RefreshesSuccessfulFetchTimeAndMetric(t *testing.T) {
	const treeID = 792
	rootHash := bytes.Repeat([]byte{0x42}, 32)
	root := types.LogRootV1{TreeSize: 1, RootHash: rootHash}
	signed := mkSLR(t, 1, rootHash)
	tc := newCachedTrillianClient(nil, treeID, cachedClientConfig{})
	tc.snapshot.Store(rootSnapshot{
		root:                    root,
		signed:                  signed,
		lastSuccessfulRootFetch: time.Now().Add(-time.Hour),
	})
	t.Cleanup(tc.Close)

	tc.publishRoot(root, signed)
	snap := tc.snapshot.Load().(rootSnapshot)
	require.WithinDuration(t, time.Now(), snap.lastSuccessfulRootFetch, time.Second)
	require.Greater(t, testutil.ToFloat64(metricLastSuccessfulRootFetch.WithLabelValues(tc.treeIDStr)), float64(time.Now().Add(-time.Second).Unix()))
}

// Note: waiting for an advance via the background updater's fixed-cadence poll
// is exercised indirectly in other tests (AddLeaf), and is hard to
// deterministically simulate across environments with the mock server; we avoid
// a direct "firstSize" wait test here.

func TestGetLeafAndProofByIndex_VerifiesProof(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	// Tree of size 1, root equals leaf hash. Empty proof should verify.
	rootHash := make([]byte, 32)
	slr1 := mkSLR(t, 1, rootHash)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: slr1}, nil).MinTimes(1)

	s.Log.EXPECT().GetEntryAndProof(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, r *trillian.GetEntryAndProofRequest) (*trillian.GetEntryAndProofResponse, error) {
			// Ensure we were asked for the current tree size
			if r.TreeSize != 1 || r.LeafIndex != 0 {
				return nil, status.Error(codes.InvalidArgument, "unexpected request")
			}
			return &trillian.GetEntryAndProofResponse{
				Leaf:  &trillian.LogLeaf{MerkleLeafHash: rootHash},
				Proof: &trillian.Proof{LeafIndex: 0, Hashes: nil},
			}, nil
		},
	).Times(1)

	conn := dialMock(t, s.Addr)
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 9, cachedClientConfig{})
	t.Cleanup(tc.Close)

	resp := tc.GetLeafAndProofByIndex(context.Background(), 0)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.NotNil(t, resp.GetLeafAndProofResult)
}

func TestGetLeafAndProofByHash_VerifiesProof(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	rootHash := make([]byte, 32)
	slr1 := mkSLR(t, 1, rootHash)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: slr1}, nil).MinTimes(1)

	// Inclusion proof for hash -> index 0, empty path is valid in size=1
	s.Log.EXPECT().GetInclusionProofByHash(gomock.Any(), gomock.Any()).Return(
		&trillian.GetInclusionProofByHashResponse{Proof: []*trillian.Proof{{LeafIndex: 0, Hashes: nil}}}, nil,
	).Times(1)

	// GetLeafAndProofByHash now calls GetLeavesByRange to fetch the leaf
	s.Log.EXPECT().GetLeavesByRange(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, r *trillian.GetLeavesByRangeRequest) (*trillian.GetLeavesByRangeResponse, error) {
			if r.Count != 1 || r.StartIndex != 0 {
				return nil, status.Error(codes.InvalidArgument, "unexpected range request")
			}
			return &trillian.GetLeavesByRangeResponse{Leaves: []*trillian.LogLeaf{{MerkleLeafHash: rootHash}}}, nil
		},
	).Times(1)

	conn := dialMock(t, s.Addr)
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 13, cachedClientConfig{})
	t.Cleanup(tc.Close)

	resp := tc.GetLeafAndProofByHash(context.Background(), rootHash)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.NotNil(t, resp.GetLeafAndProofResult)
}

func TestAddLeaf_HappyPath(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	leafHash := make([]byte, 32) // leaf 0 hash

	// We'll simulate a root advance from size=0 to size=2 and return a
	// proof for leaf index 0 with a single sibling. Compute a consistent
	// root hash for size=2 so verification succeeds.
	sibling := bytes.Repeat([]byte{0x7f}, 32) // arbitrary sibling hash
	root2 := rfc6962.DefaultHasher.HashChildren(leafHash, sibling)
	slr0 := mkSLR(t, 0, make([]byte, 32))

	// QueueLeaf returns quickly
	s.Log.EXPECT().QueueLeaf(gomock.Any(), gomock.Any()).Return(&trillian.QueueLeafResponse{
		QueuedLeaf: &trillian.QueuedLogLeaf{Leaf: &trillian.LogLeaf{MerkleLeafHash: leafHash}},
	}, nil).Times(1)

	// We bypass ensureStarted's network init and the updater by pre-initializing
	// the client snapshot and verifier, then manually advancing the snapshot.

	// Inclusion proof by hash: success for size=2 with sibling path
	s.Log.EXPECT().GetInclusionProofByHash(gomock.Any(), gomock.Any()).Return(
		&trillian.GetInclusionProofByHashResponse{Proof: []*trillian.Proof{{LeafIndex: 0, Hashes: [][]byte{sibling}}}}, nil,
	).Times(1)

	// After inclusion, client fetches leaf by index without proof to get server-populated fields
	s.Log.EXPECT().GetLeavesByRange(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, r *trillian.GetLeavesByRangeRequest) (*trillian.GetLeavesByRangeResponse, error) {
			if r.Count != 1 || r.StartIndex != 0 {
				return nil, status.Error(codes.InvalidArgument, "unexpected range request")
			}
			return &trillian.GetLeavesByRangeResponse{Leaves: []*trillian.LogLeaf{{MerkleLeafHash: leafHash}}}, nil
		},
	).Times(1)

	conn := dialMock(t, s.Addr)
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 21, cachedClientConfig{})
	// Pre-initialize
	tc.started.Store(true)
	tc.v = client.NewLogVerifier(rfc6962.DefaultHasher)
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0, RootHash: make([]byte, 32)}, signed: slr0})
	// Advance snapshot to size=2 once AddLeaf has registered its inclusion waiter.
	go func() {
		waitForWaiters(t, tc, 1)
		advanceRoot(t, tc, 2, root2)
	}()
	t.Cleanup(tc.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp := tc.AddLeaf(ctx, []byte("hello"))
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.NotNil(t, resp.GetAddResult)
	require.NotNil(t, resp.GetLeafAndProofResult)
}

func TestEnsureStartedError(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(nil, status.Error(codes.Unavailable, "boom")).Times(1)

	conn := dialMock(t, s.Addr)
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 99, cachedClientConfig{})
	t.Cleanup(tc.Close)

	resp := tc.GetLatest(context.Background())
	require.Error(t, resp.Err)
	require.Equal(t, codes.Unavailable, resp.Status)
}

func TestWaitForRootAtLeast_BroadcastWakesAll(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	tc := newCachedTrillianClient(nil, 100, cachedClientConfig{})
	// Start with size 0
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})
	t.Cleanup(tc.Close)

	const numWaiters = 10
	var wg sync.WaitGroup
	wg.Add(numWaiters)

	errs := make(chan error, numWaiters)
	for range numWaiters {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			errs <- tc.waitForRootAtLeast(ctx, 5)
		}()
	}

	waitForWaiters(t, tc, numWaiters)

	// Publish new root and notify waiters
	advanceRoot(t, tc, 5, make([]byte, 32))

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
		close(errs)
		for e := range errs {
			require.NoError(t, e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiters did not unblock after notification")
	}
}

func TestEnsureStarted_SingleRPCWithFanIn(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	slr := mkSLR(t, 0, make([]byte, 32))
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			time.Sleep(30 * time.Millisecond)
			return &trillian.GetLatestSignedLogRootResponse{SignedLogRoot: slr}, nil
		},
	).Times(1)

	conn := dialMock(t, s.Addr)
	cfg := cachedClientConfig{}
	cfg.FrozenTreeIDs = map[int64]struct{}{222: {}} // prevents updater RPC noise
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 222, cfg)
	t.Cleanup(tc.Close)

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)
	for range n {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			r := tc.GetLatest(ctx)
			errs <- r.Err
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e)
	}
}

func TestWaitForRootAtLeast_SpuriousBroadcastIgnored(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	tc := newCachedTrillianClient(nil, 303, cachedClientConfig{})
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 1}})
	t.Cleanup(tc.Close)

	const numWaiters = 6
	var wg sync.WaitGroup
	wg.Add(numWaiters)
	results := make(chan error, numWaiters)
	for range numWaiters {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			results <- tc.waitForRootAtLeast(ctx, 5)
		}()
	}

	waitForWaiters(t, tc, numWaiters)

	// With channel-per-caller, there is no "spurious" broadcast; waiters are only
	// notified when their target size is met. Advance to size 3 (below target 5);
	// waiters for size 5 should remain registered.
	advanceRoot(t, tc, 3, make([]byte, 32))
	tc.mu.Lock()
	stillWaiting := len(tc.waitersByCh)
	tc.mu.Unlock()
	require.Equal(t, numWaiters, stillWaiting, "waiters should remain registered when size is below target")

	// Now increase size to 5; everyone should complete
	advanceRoot(t, tc, 5, make([]byte, 32))

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		close(results)
		for e := range results {
			require.NoError(t, e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiters did not complete after size increased")
	}
}

func TestSnapshotConcurrentReadersWriters_NoDataRace(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	tc := newCachedTrillianClient(nil, 404, cachedClientConfig{})
	tc.started.Store(true)
	// Provide a minimal signed root so GetLatest can return without NotFound
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}, signed: mkSLR(t, 0, make([]byte, 32)), lastSuccessfulRootFetch: time.Now()})
	t.Cleanup(tc.Close)

	stop := make(chan struct{})

	// Writer rapidly updates snapshot, notifying waiters each time
	go func() {
		ticker := time.NewTicker(1 * time.Millisecond)
		defer ticker.Stop()
		sz := uint64(0)
		for range 100 {
			<-ticker.C
			sz++
			lr := &types.LogRootV1{TreeSize: sz}
			b, _ := lr.MarshalBinary()
			tc.mu.Lock()
			tc.snapshot.Store(rootSnapshot{root: *lr, signed: &trillian.SignedLogRoot{LogRoot: b}, lastSuccessfulRootFetch: time.Now()})
			tc.notifyWaiters(sz)
			tc.mu.Unlock()
		}
		close(stop)
	}()

	// Readers call GetLatest repeatedly
	const readers = 16
	var wg sync.WaitGroup
	wg.Add(readers)
	for range readers {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				r := tc.GetLatest(context.Background())
				require.NoError(t, r.Err)
				require.NotNil(t, r.GetLatestResult)
			}
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		// success
	case <-time.After(500 * time.Millisecond):
		t.Fatal("concurrent readers did not complete in time")
	}
}

func TestEnsureStarted_RespectsCallerCtx(t *testing.T) {
	// A caller with a tight deadline must return promptly with ctx.Err() —
	// it must not block on the init RPC's RootRPCTimeout. Init
	// continues in the background and serves other patient callers.
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	// Server takes 100ms — well past the tight caller's 5ms deadline, but well
	// within RootRPCTimeout. Init must eventually succeed and serve
	// concurrent patient callers via the coalesced in-flight state.
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			time.Sleep(100 * time.Millisecond)
			return &trillian.GetLatestSignedLogRootResponse{SignedLogRoot: mkSLR(t, 7, make([]byte, 32))}, nil
		},
	).Times(1) // init runs exactly once even under concurrent callers

	conn := dialMock(t, s.Addr)
	cfg := cachedClientConfig{}
	cfg.FrozenTreeIDs = map[int64]struct{}{606: {}} // avoid updater noise
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 606, cfg)
	t.Cleanup(tc.Close)

	// Tight-deadline caller: must bail on its own ctx well before RootRPCTimeout.
	tightCtx, tightCancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer tightCancel()
	start := time.Now()
	resp := tc.GetLatest(tightCtx)
	elapsed := time.Since(start)
	require.Error(t, resp.Err)
	require.Equal(t, codes.DeadlineExceeded, resp.Status)
	require.Less(t, elapsed, 50*time.Millisecond, "tight-deadline caller must return on its own ctx, not wait for the init RPC")

	// A patient caller sees the init result once it completes.
	patientCtx, patientCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer patientCancel()
	resp = tc.GetLatest(patientCtx)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.True(t, tc.started.Load())
}

func TestClose_UnblocksStuckInit(t *testing.T) {
	// Close must not wait for RootRPCTimeout to expire when init is
	// stuck on a slow Trillian. bgCancel is called before Close acquires any
	// init-related lock; the init RPC observes the cancellation and returns.
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	// Server hangs until its ctx is canceled (which will happen via bgCancel).
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, _ *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	).AnyTimes()

	conn := dialMock(t, s.Addr)
	cfg := cachedClientConfig{RootRPCTimeout: 10 * time.Second} // long, so if Close waited on it the test would fail
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 608, cfg)

	// Kick off init in a goroutine so it's in flight when Close is called.
	initReturned := make(chan struct{})
	go func() {
		defer close(initReturned)
		_ = tc.GetLatest(context.Background())
	}()

	// Give the init RPC time to enter its blocking wait.
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	tc.Close()
	elapsed := time.Since(start)
	require.Less(t, elapsed, 500*time.Millisecond, "Close must not wait for RootRPCTimeout on a stuck init RPC")

	// The in-flight init caller should also unblock via bgCtx.Done.
	select {
	case <-initReturned:
	case <-time.After(time.Second):
		t.Fatal("in-flight init caller did not unblock after Close")
	}
}

func TestEnsureStarted_InitTimeoutRespected(t *testing.T) {
	// RootRPCTimeout still bounds init when Trillian is genuinely slow.
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	// Server blocks until the init RPC's deadline fires, then returns the
	// resulting error. AnyTimes: the timeout may fire before the handler runs.
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, _ *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	).AnyTimes()

	conn := dialMock(t, s.Addr)
	cfg := cachedClientConfig{}
	cfg.RootRPCTimeout = 50 * time.Millisecond
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 607, cfg)
	t.Cleanup(tc.Close)

	start := time.Now()
	resp := tc.GetLatest(context.Background())
	elapsed := time.Since(start)

	require.Error(t, resp.Err)
	require.Equal(t, codes.DeadlineExceeded, resp.Status)
	require.False(t, tc.started.Load(), "started must remain false on init failure so retry is possible")
	require.Less(t, elapsed, 500*time.Millisecond, "init should give up near RootRPCTimeout, not hang")
}

// --- New tests for channel-per-caller and edge cases ---

func TestWaitForRootAtLeast_AlreadySatisfied(t *testing.T) {
	tc := newCachedTrillianClient(nil, 500, cachedClientConfig{})
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 10}})
	t.Cleanup(tc.Close)

	err := tc.waitForRootAtLeast(context.Background(), 5)
	require.NoError(t, err)

	err = tc.waitForRootAtLeast(context.Background(), 10)
	require.NoError(t, err)
}

func TestWaitForRootAtLeast_ContextCancellation(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	tc := newCachedTrillianClient(nil, 501, cachedClientConfig{})
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})
	t.Cleanup(tc.Close)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- tc.waitForRootAtLeast(ctx, 100)
	}()

	waitForWaiters(t, tc, 1)

	// Cancel context - should immediately unblock
	cancel()

	select {
	case err := <-done:
		require.Error(t, err)
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("waiter was not unblocked by context cancellation")
	}
}

func TestClose_UnblocksAllWaiters(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	tc := newCachedTrillianClient(nil, 502, cachedClientConfig{})
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})

	const numWaiters = 5
	var wg sync.WaitGroup
	wg.Add(numWaiters)
	errs := make(chan error, numWaiters)

	for range numWaiters {
		go func() {
			defer wg.Done()
			errs <- tc.waitForRootAtLeast(context.Background(), 999)
		}()
	}

	waitForWaiters(t, tc, numWaiters)
	tc.Close()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
		close(errs)
		for e := range errs {
			require.Error(t, e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock all waiters")
	}
}

// TestWaitForRootAtLeast_AfterClose_NoPanic guards against a regression where
// Close nil'd the waiters map, causing a subsequent waitForRootAtLeast caller
// that raced past the fast path to panic on assignment to a nil map inside
// registerWaiter. The current implementation must return codes.Canceled
// cleanly instead.
func TestWaitForRootAtLeast_AfterClose_NoPanic(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	tc := newCachedTrillianClient(nil, 504, cachedClientConfig{})
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})

	tc.Close()

	// Any request above the current size after Close must return Canceled
	// without panicking on a nil waiters map.
	err := tc.waitForRootAtLeast(context.Background(), 999)
	require.Error(t, err)
	require.Equal(t, codes.Canceled, status.Code(err))
}

// TestClose_Idempotent guards against a regression where a second Close would
// panic on double-close of the waiter channels (the map retained entries
// pointing at already-closed channels). Close must now be safe to invoke
// multiple times, including concurrently, and each caller must synchronize
// with the updater's exit before returning.
func TestClose_Idempotent(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	tc := newCachedTrillianClient(nil, 505, cachedClientConfig{})
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})

	// Register a waiter so the first Close has a channel to close.
	waiterDone := make(chan error, 1)
	go func() { waiterDone <- tc.waitForRootAtLeast(context.Background(), 999) }()
	waitForWaiters(t, tc, 1)

	// Sequential double-close must not panic.
	tc.Close()
	require.NotPanics(t, tc.Close)

	// Concurrent Close calls (racing to be the "second") also must not panic.
	var wg sync.WaitGroup
	for range 5 {
		wg.Go(tc.Close)
	}
	wg.Wait()

	// The pre-registered waiter should have been released with an error.
	select {
	case err := <-waiterDone:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("waiter was not released by Close")
	}
}

func TestNotifyWaiters_PartialSatisfaction(t *testing.T) {
	tc := newCachedTrillianClient(nil, 503, cachedClientConfig{})
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})
	t.Cleanup(tc.Close)

	tc.mu.Lock()
	ch3 := tc.registerWaiter(3)
	ch5 := tc.registerWaiter(5)
	ch10 := tc.registerWaiter(10)
	tc.mu.Unlock()

	// Notify with size 5: should satisfy waiters for 3 and 5, but not 10
	tc.mu.Lock()
	tc.notifyWaiters(5)
	tc.mu.Unlock()

	// ch3 and ch5 should be closed (readable immediately)
	select {
	case <-ch3:
		// expected
	default:
		t.Fatal("waiter for size 3 should have been notified")
	}
	select {
	case <-ch5:
		// expected
	default:
		t.Fatal("waiter for size 5 should have been notified")
	}

	// ch10 should NOT be closed
	select {
	case <-ch10:
		t.Fatal("waiter for size 10 should NOT have been notified")
	default:
		// expected
	}

	// Verify remaining waiters count and heap/map coherence
	tc.mu.Lock()
	require.Len(t, tc.waitersByCh, 1)
	require.Equal(t, tc.waitersHeap.Len(), len(tc.waitersByCh), "heap and map must agree")
	require.Equal(t, uint64(10), tc.waitersByCh[ch10].size)
	tc.mu.Unlock()
}

func TestRemoveWaiter_Cleanup(t *testing.T) {
	tc := newCachedTrillianClient(nil, 504, cachedClientConfig{})
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})
	t.Cleanup(tc.Close)

	tc.mu.Lock()
	ch1 := tc.registerWaiter(5)
	ch2 := tc.registerWaiter(10)
	require.Len(t, tc.waitersByCh, 2)
	require.Equal(t, tc.waitersHeap.Len(), len(tc.waitersByCh), "heap and map must agree after register")

	tc.removeWaiter(ch1)
	require.Len(t, tc.waitersByCh, 1)
	require.Equal(t, tc.waitersHeap.Len(), len(tc.waitersByCh), "heap and map must agree after remove")
	_, ok := tc.waitersByCh[ch2]
	require.True(t, ok)
	_, ok = tc.waitersByCh[ch1]
	require.False(t, ok)

	// Remove non-existent channel is a no-op
	tc.removeWaiter(make(chan struct{}))
	require.Len(t, tc.waitersByCh, 1)
	require.Equal(t, tc.waitersHeap.Len(), len(tc.waitersByCh), "heap and map must agree after no-op remove")
	tc.mu.Unlock()
}

// TestWaiterHeap_OrderingUnderShuffledSizes registers waiters at deliberately
// shuffled target sizes and asserts notifyWaiters wakes exactly the correct
// prefix at each threshold. Exercises the min-heap ordering property.
func TestWaiterHeap_OrderingUnderShuffledSizes(t *testing.T) {
	tc := newCachedTrillianClient(nil, 510, cachedClientConfig{})
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})
	t.Cleanup(tc.Close)

	// Register waiters at sizes chosen to force multiple heap re-siftings.
	sizes := []uint64{50, 10, 100, 20, 5, 75, 30, 1, 60, 40}
	chans := make([]chan struct{}, len(sizes))
	tc.mu.Lock()
	for i, sz := range sizes {
		chans[i] = tc.registerWaiter(sz)
	}
	require.Len(t, tc.waitersByCh, len(sizes))
	require.Equal(t, tc.waitersHeap.Len(), len(tc.waitersByCh))
	tc.mu.Unlock()

	// Step 1: notify size 25 — wakes 1, 5, 10, 20 (4 waiters), leaves 6.
	tc.mu.Lock()
	tc.notifyWaiters(25)
	require.Len(t, tc.waitersByCh, 6)
	require.Equal(t, tc.waitersHeap.Len(), len(tc.waitersByCh))
	tc.mu.Unlock()

	for i, sz := range sizes {
		select {
		case <-chans[i]:
			require.LessOrEqual(t, sz, uint64(25), "only waiters with size ≤ 25 should be closed")
		default:
			require.Greater(t, sz, uint64(25), "waiters with size > 25 should still be open")
		}
	}

	// Step 2: notify size 60 — wakes 30, 40, 50, 60 (4 more), leaves 2 (75, 100).
	tc.mu.Lock()
	tc.notifyWaiters(60)
	require.Len(t, tc.waitersByCh, 2)
	require.Equal(t, tc.waitersHeap.Len(), len(tc.waitersByCh))
	tc.mu.Unlock()

	for i, sz := range sizes {
		if sz > 25 {
			select {
			case <-chans[i]:
				require.LessOrEqual(t, sz, uint64(60), "only waiters with size ≤ 60 should now be closed")
			default:
				require.Greater(t, sz, uint64(60))
			}
		}
	}

	// Step 3: notify size 1000 — drain everything.
	tc.mu.Lock()
	tc.notifyWaiters(1000)
	require.Empty(t, tc.waitersByCh)
	require.Zero(t, tc.waitersHeap.Len())
	tc.mu.Unlock()
}

// TestRemoveWaiter_MidHeap_PreservesInvariants removes a waiter that is not
// at the root of the heap, then verifies subsequent notify still wakes the
// correct set. Regression guard for a broken heap.Remove index-tracking.
func TestRemoveWaiter_MidHeap_PreservesInvariants(t *testing.T) {
	tc := newCachedTrillianClient(nil, 511, cachedClientConfig{})
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})
	t.Cleanup(tc.Close)

	tc.mu.Lock()
	// Push in an order that puts size 50 somewhere in the interior of the heap.
	ch10 := tc.registerWaiter(10)
	ch50 := tc.registerWaiter(50)
	ch20 := tc.registerWaiter(20)
	ch60 := tc.registerWaiter(60)
	ch30 := tc.registerWaiter(30)

	// Remove an interior waiter (size 50 will not be at index 0 given size 10 is smallest).
	require.NotZero(t, tc.waitersByCh[ch50].index, "size 50 should not be the heap root here")
	tc.removeWaiter(ch50)
	require.Len(t, tc.waitersByCh, 4)
	require.Equal(t, tc.waitersHeap.Len(), len(tc.waitersByCh))

	// Notify size 35 — wakes 10, 20, 30. Leaves 60. 50 was removed and must not fire.
	tc.notifyWaiters(35)
	tc.mu.Unlock()

	for _, tt := range []struct {
		ch     chan struct{}
		wake   bool
		reason string
	}{
		{ch10, true, "size 10 ≤ 35"},
		{ch20, true, "size 20 ≤ 35"},
		{ch30, true, "size 30 ≤ 35"},
		{ch60, false, "size 60 > 35"},
	} {
		select {
		case <-tt.ch:
			require.True(t, tt.wake, tt.reason)
		default:
			require.False(t, tt.wake, tt.reason)
		}
	}
	// ch50 was removed, so it must not have been closed by notify.
	select {
	case <-ch50:
		t.Fatal("removed waiter (ch50) must not be closed by notify")
	default:
	}

	tc.mu.Lock()
	require.Len(t, tc.waitersByCh, 1) // only ch60 remains
	require.Equal(t, tc.waitersHeap.Len(), len(tc.waitersByCh))
	tc.mu.Unlock()
}

func TestUpdater_RetriesOnTransientErrors(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	rootHash1 := bytes.Repeat([]byte{0x11}, 32)

	var latestCalls atomic.Int32
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			latestCalls.Add(1)
			return nil, status.Error(codes.Unavailable, "transient")
		},
	).AnyTimes()

	conn := dialMock(t, s.Addr)
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 600, cachedClientConfig{PollInterval: 20 * time.Millisecond})
	t.Cleanup(tc.Close)

	initial := types.LogRootV1{TreeSize: 1, RootHash: rootHash1}
	tc.v = client.NewLogVerifier(rfc6962.DefaultHasher)
	tc.snapshot.Store(rootSnapshot{root: initial, signed: mkSLR(t, 1, rootHash1)})

	done := make(chan struct{})
	go func() {
		tc.updater()
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if latestCalls.Load() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	require.GreaterOrEqual(t, latestCalls.Load(), int32(2), "updater should keep retrying after transient errors")

	tc.Close()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("updater did not stop after Close")
	}
}

// TestUpdater_HangingRPCTimesOutAndNextPollFires is the regression guard for
// a bug where the updater called GetLatestSignedLogRoot with the (deadline-less)
// bgCtx. A hung Trillian RPC therefore stalled the poll loop indefinitely,
// freezing the cached snapshot and blocking every AddLeaf waiter.
//
// The mock hangs every RPC until its context is canceled. With the per-poll
// RootRPCTimeout in effect, each RPC returns DeadlineExceeded, engages
// errBackoff, and the loop reissues. We assert that at least two RPCs are
// observed well before any bgCtx-cancel could excuse the second one — i.e.,
// the deadline (not shutdown) is what unblocks the loop.
func TestUpdater_HangingRPCTimesOutAndNextPollFires(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	// Mock hangs until its ctx is canceled — mimics a Trillian that accepts
	// the RPC but never responds. If the updater uses bgCtx directly, this
	// RPC never returns and no second call is ever made.
	var latestCalls atomic.Int32
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, _ *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			latestCalls.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	).AnyTimes()

	conn := dialMock(t, s.Addr)
	// Tight RootRPCTimeout so each hang unwinds quickly. Short PollInterval
	// so the retry after backoff+wait completes within the test window.
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 601, cachedClientConfig{
		PollInterval:   10 * time.Millisecond,
		RootRPCTimeout: 50 * time.Millisecond,
	})
	tc.v = client.NewLogVerifier(rfc6962.DefaultHasher)
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 1}, signed: mkSLR(t, 1, make([]byte, 32))})

	done := make(chan struct{})
	go func() {
		tc.updater()
		close(done)
	}()

	// Wait for at least two RPCs. First RPC starts almost immediately, hangs
	// ~50ms, then errBackoff.Duration() (Min=100ms, jittered) → second RPC.
	// Budget generously: 3s well exceeds worst-case backoff+timeout for 2 calls
	// but is far less than any bgCtx-cancel-driven unblock (which would require
	// Close, and we haven't called it yet).
	require.Eventually(t, func() bool {
		return latestCalls.Load() >= 2
	}, 3*time.Second, 20*time.Millisecond, "second poll must fire after first RPC hits its deadline; if this times out, the poll is stalled on bgCtx")

	tc.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("updater did not stop after Close")
	}
}

func TestClientManager_CachesClientPerTreeID(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	cm := NewClientManager(Options{DefaultGRPC: GRPCConfig{Address: s.Addr, Port: 0}})

	conn := dialMock(t, s.Addr)
	cm.connMu.Lock()
	cm.connections[cm.opts.DefaultGRPC] = conn
	cm.connMu.Unlock()
	t.Cleanup(func() { _ = cm.Close() })

	c1, err := cm.GetClient(7)
	require.NoError(t, err)
	c2, err := cm.GetClient(7)
	require.NoError(t, err)
	c3, err := cm.GetClient(8)
	require.NoError(t, err)

	require.Same(t, c1, c2, "same tree ID should return cached client instance")
	require.NotSame(t, c1, c3, "different tree IDs should return distinct client instances")
}

func TestClientManagerClose_ClosesClients(t *testing.T) {
	cm := NewClientManager(Options{DefaultGRPC: GRPCConfig{Address: "localhost", Port: 0}})
	fake1 := &fakeCloseTrackingClient{}
	fake2 := &fakeCloseTrackingClient{}

	cm.clientMu.Lock()
	cm.trillianClients[1] = fake1
	cm.trillianClients[2] = fake2
	cm.clientMu.Unlock()

	err := cm.Close()
	require.NoError(t, err)
	require.EqualValues(t, 1, fake1.CloseCalls(), "Close should be called on cached client 1")
	require.EqualValues(t, 1, fake2.CloseCalls(), "Close should be called on cached client 2")

	cm.clientMu.RLock()
	require.True(t, cm.shutdown)
	require.Empty(t, cm.trillianClients)
	cm.clientMu.RUnlock()

	// After Close, GetClient should fail
	_, err = cm.GetClient(1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "shutting down")
}

func TestClientManagerGetConn_RejectsDialAfterClose(t *testing.T) {
	// Verify that getConn refuses to dial after Close has drained connections,
	// even if the early shutdown check passed before Close ran.
	cm := NewClientManager(Options{DefaultGRPC: GRPCConfig{Address: "localhost", Port: 0}})

	// Close drains connections and sets shutdown.
	require.NoError(t, cm.Close())

	// getConn must reject the dial attempt despite the connections map being empty.
	_, err := cm.getConn(1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "shutting down")
}

func TestClientManagerGetConn_ConcurrentCloseNeverLeaks(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })

	cm := NewClientManager(Options{DefaultGRPC: GRPCConfig{Address: "localhost", Port: 0}})

	// Race getConn against Close. getConn must either succeed (connection
	// stored and later cleaned up) or return a shutdown error. It must
	// never leave an orphaned connection.
	const goroutines = 20
	errs := make(chan error, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			_, err := cm.getConn(1)
			errs <- err
		}()
	}

	// Close concurrently.
	closeErr := cm.Close()
	wg.Wait()
	close(errs)

	require.NoError(t, closeErr)
	for e := range errs {
		if e != nil {
			require.Contains(t, e.Error(), "shutting down")
		}
	}

	// After Close, connections map must be empty (no leaked connections).
	cm.connMu.RLock()
	require.Empty(t, cm.connections)
	cm.connMu.RUnlock()
}

func TestClientManagerFactory_SimpleClient(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	cm := NewClientManager(Options{DefaultGRPC: GRPCConfig{Address: s.Addr, Port: 0}})

	// Manually inject a connection since we can't dial properly in tests
	conn := dialMock(t, s.Addr)
	cm.connMu.Lock()
	cm.connections[cm.opts.DefaultGRPC] = conn
	cm.connMu.Unlock()
	t.Cleanup(func() { _ = cm.Close() })

	c, err := cm.GetClient(1)
	require.NoError(t, err)
	_, ok := c.(*directTrillianClient)
	require.True(t, ok, "expected directTrillianClient when CacheSTH=false")
}

func TestClientManagerFactory_CachedClient(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	cm := NewClientManager(Options{
		DefaultGRPC: GRPCConfig{Address: s.Addr, Port: 0},
		CacheSTH:    true,
	})

	// Manually inject a connection
	conn := dialMock(t, s.Addr)
	cm.connMu.Lock()
	cm.connections[cm.opts.DefaultGRPC] = conn
	cm.connMu.Unlock()
	t.Cleanup(func() { _ = cm.Close() })

	c, err := cm.GetClient(1)
	require.NoError(t, err)
	_, ok := c.(*cachedTrillianClient)
	require.True(t, ok, "expected *cachedTrillianClient when CacheSTH=true")
}

// --- Frozen tree tests ---

func TestFrozenClient_NoUpdaterStarted(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	slr := mkSLR(t, 10, make([]byte, 32))
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(
		&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: slr}, nil,
	).Times(1) // Only called once during ensureStarted; no updater polling

	conn := dialMock(t, s.Addr)
	frozenCfg := cachedClientConfig{}
	frozenCfg.FrozenTreeIDs = map[int64]struct{}{700: {}}
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 700, frozenCfg)
	t.Cleanup(tc.Close)

	resp := tc.GetLatest(context.Background())
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)

	var got types.LogRootV1
	require.NoError(t, got.UnmarshalBinary(resp.GetLatestResult.SignedLogRoot.LogRoot))
	require.EqualValues(t, 10, got.TreeSize)
}

func TestFrozenClient_WaitForRootAtLeast_FailsImmediately(t *testing.T) {
	frozenCfg := cachedClientConfig{}
	frozenCfg.FrozenTreeIDs = map[int64]struct{}{701: {}}
	tc := newCachedTrillianClient(nil, 701, frozenCfg)
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 5}})
	t.Cleanup(tc.Close)

	// Request satisfied by current size
	err := tc.waitForRootAtLeast(context.Background(), 5)
	require.NoError(t, err)

	// Request above frozen size fails immediately
	err = tc.waitForRootAtLeast(context.Background(), 10)
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Contains(t, err.Error(), "frozen")
}

func TestClientManagerFactory_FrozenCachedClient(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	t.Cleanup(closeFn)

	cm := NewClientManager(Options{
		DefaultGRPC:   GRPCConfig{Address: s.Addr, Port: 0},
		CacheSTH:      true,
		FrozenTreeIDs: map[int64]struct{}{42: {}},
	})

	conn := dialMock(t, s.Addr)
	cm.connMu.Lock()
	cm.connections[cm.opts.DefaultGRPC] = conn
	cm.connMu.Unlock()
	t.Cleanup(func() { _ = cm.Close() })

	c, err := cm.GetClient(42)
	require.NoError(t, err)
	tc, ok := c.(*cachedTrillianClient)
	require.True(t, ok, "expected *cachedTrillianClient when CacheSTH=true")
	require.True(t, tc.frozen, "expected frozen=true for tree in frozenTreeIDs")

	// Non-frozen tree should not be frozen
	c2, err := cm.GetClient(99)
	require.NoError(t, err)
	tc2, ok := c2.(*cachedTrillianClient)
	require.True(t, ok)
	require.False(t, tc2.frozen, "expected frozen=false for tree not in frozenTreeIDs")
}

// --- Fetch-gate read-after-write tests ---

// primedClient builds a cachedTrillianClient with started=true and a pre-populated
// snapshot at the given size, bypassing init so tests can precisely count
// RPCs without updater noise. No updater goroutine runs; tests that need the
// fetch-gate to fire should drive it with simulateUpdaterCycle.
func primedClient(t *testing.T, s *testonly.MockServer, treeID int64, size uint64, rootHash []byte) *cachedTrillianClient {
	t.Helper()
	conn := dialMock(t, s.Addr)
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), treeID, cachedClientConfig{})
	tc.v = client.NewLogVerifier(rfc6962.DefaultHasher)
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: size, RootHash: rootHash}, signed: mkSLR(t, size, rootHash)})
	tc.started.Store(true)
	return tc
}

// simulateUpdaterCycle mimics one updater poll cycle with deterministic
// timing: Swap-in a fresh gate for the NEXT cycle, optionally publish the
// given root (if size > 0), then close the PREVIOUS gate. Tests can call this
// after a reader has captured the current gate to precisely trigger the
// gate-wake without spinning up a real updater goroutine.
//
// Passing size == 0 simulates a no-advance poll (Trillian returned the same
// size the cache already had): gate still closes so readers wake and retry.
// Passing size > 0 simulates a successful poll that advances the tree.
func simulateUpdaterCycle(t *testing.T, tc *cachedTrillianClient, size uint64, rootHash []byte) {
	t.Helper()
	prev := tc.nextGate.Swap(&fetchGate{done: make(chan struct{})})
	if size > 0 {
		lr := types.LogRootV1{TreeSize: size, RootHash: rootHash}
		b, err := lr.MarshalBinary()
		require.NoError(t, err)
		tc.publishRoot(lr, &trillian.SignedLogRoot{LogRoot: b})
	}
	close(prev.done)
}

// waitForGateCapture spins until at least `n` distinct readers have Load()ed
// the currently-installed nextGate — measured indirectly by observing that
// the gate has not been Swapped since the initial reference. Since Load() is
// unobservable, we approximate by watching that a reader has proceeded past
// its initial cache miss (they'll be blocked in select on the gate). We use a
// small sleep + heuristic rather than a strict handshake because the reader's
// Load happens synchronously inside GetLeafAndProofByHash right after the
// initial getProofByHashWithRoot miss; a few milliseconds is plenty.
func waitForGateCapture(t *testing.T) {
	t.Helper()
	time.Sleep(20 * time.Millisecond)
}

func TestReadAfterWrite_ByIndex_InRange_CacheAuthoritative(t *testing.T) {
	// Cache is authoritative for indices below TreeSize; no gate wait, no
	// updater involvement. Only GetEntryAndProof is called.
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	tc := primedClient(t, s, 800, 1, make([]byte, 32))
	t.Cleanup(tc.Close)

	s.Log.EXPECT().GetEntryAndProof(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, r *trillian.GetEntryAndProofRequest) (*trillian.GetEntryAndProofResponse, error) {
			require.EqualValues(t, 1, r.TreeSize, "buildIndexResp must use the cached tree size")
			return &trillian.GetEntryAndProofResponse{
				Leaf:  &trillian.LogLeaf{MerkleLeafHash: make([]byte, 32)},
				Proof: &trillian.Proof{LeafIndex: 0, Hashes: nil},
			}, nil
		},
	).Times(1)

	resp := tc.GetLeafAndProofByIndex(context.Background(), 0)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
}

func TestReadAfterWrite_ByIndex_OutOfRange_GateAdvanceThenSucceeds(t *testing.T) {
	// Cache says empty; reader captures the gate. A simulated updater cycle
	// publishes size=1 with the target root and closes the gate. Reader wakes,
	// re-checks cache — now at size 1 — and serves the entry.
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	newHash := bytes.Repeat([]byte{0x11}, 32)
	tc := primedClient(t, s, 801, 0, make([]byte, 32))
	t.Cleanup(tc.Close)

	// Only GetEntryAndProof — the "root RPC" is replaced by simulateUpdaterCycle.
	s.Log.EXPECT().GetEntryAndProof(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, r *trillian.GetEntryAndProofRequest) (*trillian.GetEntryAndProofResponse, error) {
			require.EqualValues(t, 1, r.TreeSize, "retry must use post-gate tree size")
			return &trillian.GetEntryAndProofResponse{
				Leaf:  &trillian.LogLeaf{MerkleLeafHash: newHash},
				Proof: &trillian.Proof{LeafIndex: 0, Hashes: nil},
			}, nil
		},
	).Times(1)

	done := make(chan *internalclient.Response, 1)
	go func() {
		done <- tc.GetLeafAndProofByIndex(context.Background(), 0)
	}()
	waitForGateCapture(t)
	simulateUpdaterCycle(t, tc, 1, newHash)

	select {
	case resp := <-done:
		require.NoError(t, resp.Err)
		require.Equal(t, codes.OK, resp.Status)
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not complete after simulated updater cycle")
	}
}

func TestReadAfterWrite_ByIndex_OutOfRange_GateAdvancesButIndexStillOut_NotFound(t *testing.T) {
	// Cache at size 5, request index 100. Updater cycle publishes size 10 —
	// still short of 100. Reader retries, sees still-out-of-range, returns
	// NotFound. Same one-shot semantic as pre-fetch-gate: NotFound after one
	// wait means "not in Trillian's currently-observable tree." GetEntryAndProof
	// must NOT be called.
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	tc := primedClient(t, s, 802, 5, make([]byte, 32))
	t.Cleanup(tc.Close)

	done := make(chan *internalclient.Response, 1)
	go func() {
		done <- tc.GetLeafAndProofByIndex(context.Background(), 100)
	}()
	waitForGateCapture(t)
	simulateUpdaterCycle(t, tc, 10, bytes.Repeat([]byte{0x22}, 32))

	select {
	case resp := <-done:
		require.Error(t, resp.Err)
		require.Equal(t, codes.NotFound, resp.Status)
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not complete after simulated updater cycle")
	}
}

func TestReadAfterWrite_ByIndex_NegativeInvalidArg(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	// No mock server, no client conn — negative check must reject BEFORE
	// ensureStarted, so no init RPC is triggered.
	tc := newCachedTrillianClient(nil, 803, cachedClientConfig{})
	t.Cleanup(tc.Close)

	resp := tc.GetLeafAndProofByIndex(context.Background(), -1)
	require.Error(t, resp.Err)
	require.Equal(t, codes.InvalidArgument, resp.Status)
}

func TestReadAfterWrite_ByHash_MissWaitsForGateThenSucceeds(t *testing.T) {
	// Cache says empty; reader's initial proof attempt short-circuits inside
	// getProofByHashWithRoot on TreeSize==0 and returns NotFound (no RPC).
	// Reader captures the fetch-gate. A simulated updater cycle publishes
	// size=1 with the target hash and closes the gate. Reader wakes, retries
	// getProofByHashWithRoot against size=1, gets the trivial proof, then
	// fetches the leaf via getStandaloneLeaf.
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	newHash := bytes.Repeat([]byte{0x33}, 32)
	tc := primedClient(t, s, 810, 0, make([]byte, 32)) // cache says empty
	t.Cleanup(tc.Close)

	// Retry: at size 1, request the hash — returns the trivial proof.
	s.Log.EXPECT().GetInclusionProofByHash(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, r *trillian.GetInclusionProofByHashRequest) (*trillian.GetInclusionProofByHashResponse, error) {
			require.EqualValues(t, 1, r.TreeSize, "retry must use post-gate tree size")
			return &trillian.GetInclusionProofByHashResponse{
				Proof: []*trillian.Proof{{LeafIndex: 0, Hashes: nil}},
			}, nil
		},
	).Times(1)
	s.Log.EXPECT().GetLeavesByRange(gomock.Any(), gomock.Any()).Return(
		&trillian.GetLeavesByRangeResponse{Leaves: []*trillian.LogLeaf{{MerkleLeafHash: newHash}}}, nil,
	).Times(1)

	done := make(chan *internalclient.Response, 1)
	go func() {
		done <- tc.GetLeafAndProofByHash(context.Background(), newHash)
	}()
	waitForGateCapture(t)
	simulateUpdaterCycle(t, tc, 1, newHash)

	select {
	case resp := <-done:
		require.NoError(t, resp.Err)
		require.Equal(t, codes.OK, resp.Status)
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not complete after simulated updater cycle")
	}
}

func TestReadAfterWrite_ByHash_GateFiresButHashStillMissing_NotFound(t *testing.T) {
	// First proof call at cached size 1: NotFound. Reader captures gate. A
	// simulated updater cycle keeps the tree at size 1 (no advance) but still
	// closes the gate — matching a real "same-size poll" that must not strand
	// waiters. Reader wakes, retries proof at size 1, misses again, returns
	// NotFound. Two proof RPCs total; no infinite loop.
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	rootHash := bytes.Repeat([]byte{0x44}, 32)
	tc := primedClient(t, s, 811, 1, rootHash)
	t.Cleanup(tc.Close)

	var proofCalls atomic.Int32
	s.Log.EXPECT().GetInclusionProofByHash(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ *trillian.GetInclusionProofByHashRequest) (*trillian.GetInclusionProofByHashResponse, error) {
			proofCalls.Add(1)
			return nil, status.Error(codes.NotFound, "no such leaf")
		},
	).Times(2)

	unknownHash := bytes.Repeat([]byte{0x55}, 32)
	done := make(chan *internalclient.Response, 1)
	go func() {
		done <- tc.GetLeafAndProofByHash(context.Background(), unknownHash)
	}()
	waitForGateCapture(t)
	// No-advance cycle: publishRoot would drop the size=1 same-hash "advance"
	// as a no-op, but the gate still closes. Pass size 0 to skip publishRoot
	// entirely (equivalent semantic: gate closes without snapshot change).
	simulateUpdaterCycle(t, tc, 0, nil)

	select {
	case resp := <-done:
		require.Error(t, resp.Err)
		require.Equal(t, codes.NotFound, resp.Status)
		require.EqualValues(t, 2, proofCalls.Load(), "must retry exactly once, not loop")
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not complete after simulated updater cycle")
	}
}

func TestPublishRoot_MonotonicAgainstDelayedPollerResponse(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	// No RPCs — publishRoot exercised directly to verify monotonic guard
	// against out-of-order publishes from concurrent updater+refresh.
	tc := newCachedTrillianClient(nil, 860, cachedClientConfig{})
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}, signed: mkSLR(t, 0, make([]byte, 32))})
	tc.started.Store(true)
	t.Cleanup(tc.Close)

	hash10 := bytes.Repeat([]byte{0x77}, 32)
	hash5 := bytes.Repeat([]byte{0x88}, 32)

	// A waiter for size 10 must be released by the size-10 publish.
	waiterDone := make(chan error, 1)
	go func() {
		waiterDone <- tc.waitForRootAtLeast(context.Background(), 10)
	}()
	waitForWaiters(t, tc, 1)

	// "refresh" publishes size 10 first
	require.True(t, tc.publishRoot(types.LogRootV1{TreeSize: 10, RootHash: hash10}, mkSLR(t, 10, hash10)))

	select {
	case err := <-waiterDone:
		require.NoError(t, err, "size-10 publish must release the waiter")
	case <-time.After(time.Second):
		t.Fatal("waiter for size 10 was not released after size-10 publish")
	}

	// Delayed "poller" tries to publish size 5 — must be dropped.
	require.False(t, tc.publishRoot(types.LogRootV1{TreeSize: 5, RootHash: hash5}, mkSLR(t, 5, hash5)))

	snap := tc.snapshot.Load().(rootSnapshot)
	require.EqualValues(t, 10, snap.root.TreeSize, "snapshot must not regress")
	require.True(t, bytes.Equal(hash10, snap.root.RootHash))
}

func TestPublishRoot_IntegrityAnomaly_NotPublished(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	tc := newCachedTrillianClient(nil, 861, cachedClientConfig{})
	origHash := bytes.Repeat([]byte{0xAA}, 32)
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 5, RootHash: origHash}, signed: mkSLR(t, 5, origHash)})
	tc.started.Store(true)
	t.Cleanup(tc.Close)

	// Same size, different hash → integrity anomaly, must not publish.
	require.False(t, tc.publishRoot(types.LogRootV1{TreeSize: 5, RootHash: bytes.Repeat([]byte{0xBB}, 32)}, mkSLR(t, 5, bytes.Repeat([]byte{0xBB}, 32))))
	snap := tc.snapshot.Load().(rootSnapshot)
	require.True(t, bytes.Equal(origHash, snap.root.RootHash), "hash must not change on anomaly")
}

// --- Fetch-gate mechanism tests ---

func TestFetchGate_InitialGateInstalledForActiveTree(t *testing.T) {
	// newCachedTrillianClient must install an initial gate for non-frozen
	// trees so a hash reader arriving between ensureStarted and the first
	// updater cycle has something to wait on.
	tc := newCachedTrillianClient(nil, 900, cachedClientConfig{})
	t.Cleanup(tc.Close)

	gate := tc.nextGate.Load()
	require.NotNil(t, gate, "active tree must have an initial fetch-gate installed")
	require.NotNil(t, gate.done, "fetch-gate done channel must be non-nil")

	// Not yet closed.
	select {
	case <-gate.done:
		t.Fatal("initial gate must not be closed at construction time")
	default:
	}
}

func TestFetchGate_NoGateForFrozenTree(t *testing.T) {
	// Frozen trees have no updater to swap or close the gate, so we don't
	// install one. The hash-lookup path branches out on t.frozen before it
	// would ever touch nextGate.
	cfg := cachedClientConfig{FrozenTreeIDs: map[int64]struct{}{901: {}}}
	tc := newCachedTrillianClient(nil, 901, cfg)
	t.Cleanup(tc.Close)

	require.Nil(t, tc.nextGate.Load(), "frozen tree must not install a fetch-gate")
}

func TestFetchGate_SimulateCycle_ClosesPreviousInstallsNext(t *testing.T) {
	// Direct verification of the Swap-and-close invariant: after one
	// simulated cycle, the previously-observed gate must be closed and
	// nextGate must point to a distinct, still-open gate.
	tc := newCachedTrillianClient(nil, 902, cachedClientConfig{})
	tc.v = client.NewLogVerifier(rfc6962.DefaultHasher)
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}, signed: mkSLR(t, 0, make([]byte, 32))})
	tc.started.Store(true)
	t.Cleanup(tc.Close)

	pre := tc.nextGate.Load()
	require.NotNil(t, pre)

	simulateUpdaterCycle(t, tc, 1, bytes.Repeat([]byte{0x99}, 32))

	// Previous gate must now be closed.
	select {
	case <-pre.done:
		// expected
	default:
		t.Fatal("previous gate must be closed after simulated cycle")
	}

	// nextGate must now point to a fresh, still-open gate distinct from pre.
	post := tc.nextGate.Load()
	require.NotNil(t, post)
	require.NotSame(t, pre, post, "cycle must install a new gate distinct from the previous one")
	select {
	case <-post.done:
		t.Fatal("newly-installed gate must not be closed")
	default:
	}
}

func TestFetchGate_ClosesEvenOnRPCError_ViaRealUpdater(t *testing.T) {
	// A real updater cycle whose RPC returns an error must still close the
	// current cycle's gate, so readers can wake and retry rather than stall
	// indefinitely. Uses a real updater with a short poll interval; the mock
	// always errors, so the updater loops through backoff and error paths.
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(
		nil, status.Error(codes.Unavailable, "boom"),
	).AnyTimes()

	conn := dialMock(t, s.Addr)
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 903, cachedClientConfig{
		PollInterval:   10 * time.Millisecond,
		RootRPCTimeout: 100 * time.Millisecond,
	})
	tc.v = client.NewLogVerifier(rfc6962.DefaultHasher)
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 1, RootHash: make([]byte, 32)}, signed: mkSLR(t, 1, make([]byte, 32))})
	tc.started.Store(true)
	tc.wg.Go(tc.updater)
	t.Cleanup(tc.Close)

	// Capture the current gate, then wait for it to be closed by an updater
	// cycle. Even though the RPC errors, the gate must close.
	gate := tc.nextGate.Load()
	require.NotNil(t, gate)

	select {
	case <-gate.done:
		// expected: updater closed the gate despite the RPC error
	case <-time.After(2 * time.Second):
		t.Fatal("gate did not close within 2s despite an error-returning updater cycle")
	}
}

func TestFetchGate_ShutdownDoesNotCloseGate_ReadersWakeViaBgCtx(t *testing.T) {
	// Close must not close the current fetch-gate; readers select on both
	// gate.done and bgCtx.Done() and must take the bgCtx branch on shutdown,
	// returning Canceled rather than falling through to attempt a hash RPC
	// against a shutting-down connection.
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	tc := primedClient(t, s, 904, 0, make([]byte, 32))
	// Not calling t.Cleanup(tc.Close) — we call Close explicitly below.

	gate := tc.nextGate.Load()
	require.NotNil(t, gate)

	// Start a reader whose only wake path is the gate or bgCtx.
	done := make(chan *internalclient.Response, 1)
	go func() {
		done <- tc.GetLeafAndProofByHash(context.Background(), bytes.Repeat([]byte{0xEE}, 32))
	}()
	waitForGateCapture(t)

	// Close: bgCancel should wake the reader via bgCtx.Done().
	tc.Close()

	select {
	case resp := <-done:
		// Reader returned via bgCtx.Done() → Canceled from waitForFetchGate.
		require.Error(t, resp.Err)
		require.Equal(t, codes.Canceled, resp.Status)
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not wake after Close")
	}

	// Verify the gate itself remained un-closed by Close (bgCtx did the work).
	select {
	case <-gate.done:
		t.Fatal("Close must NOT close the fetch-gate; readers wake via bgCtx.Done()")
	default:
		// expected
	}
}

func TestFetchGate_FrozenHashMiss_ReturnsNotFoundWithoutGateWait(t *testing.T) {
	// Frozen tree with a hash miss must NOT wait on a gate (there is no
	// updater to close one). The hash path must short-circuit on t.frozen
	// and return NotFound directly.
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	conn := dialMock(t, s.Addr)
	cfg := cachedClientConfig{FrozenTreeIDs: map[int64]struct{}{905: {}}}
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 905, cfg)
	tc.v = client.NewLogVerifier(rfc6962.DefaultHasher)
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 1, RootHash: bytes.Repeat([]byte{0x01}, 32)}, signed: mkSLR(t, 1, bytes.Repeat([]byte{0x01}, 32))})
	tc.started.Store(true)
	t.Cleanup(tc.Close)

	s.Log.EXPECT().GetInclusionProofByHash(gomock.Any(), gomock.Any()).Return(
		nil, status.Error(codes.NotFound, "no such leaf"),
	).Times(1) // exactly one proof RPC — no retry after gate wait

	start := time.Now()
	resp := tc.GetLeafAndProofByHash(context.Background(), bytes.Repeat([]byte{0xDD}, 32))
	elapsed := time.Since(start)

	require.Error(t, resp.Err)
	require.Equal(t, codes.NotFound, resp.Status)
	require.Less(t, elapsed, 100*time.Millisecond, "frozen tree hash miss must not wait on any gate")
}

func TestFetchGate_HashMissStorm_OneGateCycleServesAll(t *testing.T) {
	// N concurrent hash-lookup readers all miss the empty cache. All capture
	// the same current gate and wait. A single simulated updater cycle
	// publishes the target and closes the gate; all N readers wake and retry.
	// Only one gate cycle is needed regardless of N — the fetch-gate primitive
	// naturally coalesces stale-miss readers onto the shared updater cadence.
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	newHash := bytes.Repeat([]byte{0x77}, 32)
	tc := primedClient(t, s, 906, 0, make([]byte, 32))
	t.Cleanup(tc.Close)

	// N concurrent readers each retry once against size=1; N proof + N leaf RPCs.
	const N = 20
	s.Log.EXPECT().GetInclusionProofByHash(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, r *trillian.GetInclusionProofByHashRequest) (*trillian.GetInclusionProofByHashResponse, error) {
			require.EqualValues(t, 1, r.TreeSize)
			return &trillian.GetInclusionProofByHashResponse{
				Proof: []*trillian.Proof{{LeafIndex: 0, Hashes: nil}},
			}, nil
		},
	).Times(N)
	s.Log.EXPECT().GetLeavesByRange(gomock.Any(), gomock.Any()).Return(
		&trillian.GetLeavesByRangeResponse{Leaves: []*trillian.LogLeaf{{MerkleLeafHash: newHash}}}, nil,
	).Times(N)

	var wg sync.WaitGroup
	errs := make(chan error, N)
	for range N {
		wg.Go(func() {
			resp := tc.GetLeafAndProofByHash(context.Background(), newHash)
			errs <- resp.Err
		})
	}

	waitForGateCapture(t)
	// One cycle publishes size=1 with newHash and closes the shared gate,
	// waking all N readers simultaneously.
	simulateUpdaterCycle(t, tc, 1, newHash)

	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e, "all N readers must succeed after the single gate cycle")
	}
}

func TestFetchGate_RealUpdater_WakesReaderAndPublishes(t *testing.T) {
	// End-to-end integration: a real updater goroutine polls Trillian, its
	// response advances the cache from 0 to 1 with the target hash, its
	// close(thisGate.done) wakes the waiting reader, and the reader's retry
	// finds the leaf. Exercises the Swap-then-RPC-then-publish-then-close
	// sequence without simulateUpdaterCycle shortcut.
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	newHash := bytes.Repeat([]byte{0xAB}, 32)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(
		&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: mkSLR(t, 1, newHash)}, nil,
	).AnyTimes()
	s.Log.EXPECT().GetInclusionProofByHash(gomock.Any(), gomock.Any()).Return(
		&trillian.GetInclusionProofByHashResponse{Proof: []*trillian.Proof{{LeafIndex: 0, Hashes: nil}}}, nil,
	).AnyTimes()
	s.Log.EXPECT().GetLeavesByRange(gomock.Any(), gomock.Any()).Return(
		&trillian.GetLeavesByRangeResponse{Leaves: []*trillian.LogLeaf{{MerkleLeafHash: newHash}}}, nil,
	).AnyTimes()

	conn := dialMock(t, s.Addr)
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 907, cachedClientConfig{
		PollInterval:   30 * time.Millisecond,
		RootRPCTimeout: time.Second,
	})
	tc.v = client.NewLogVerifier(rfc6962.DefaultHasher)
	// Seed empty snapshot so first hash lookup misses.
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0, RootHash: make([]byte, 32)}, signed: mkSLR(t, 0, make([]byte, 32))})
	tc.started.Store(true)
	tc.wg.Go(tc.updater)
	t.Cleanup(tc.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp := tc.GetLeafAndProofByHash(ctx, newHash)
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
}
