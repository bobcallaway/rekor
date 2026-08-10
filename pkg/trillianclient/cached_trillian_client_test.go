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
	signed := mkSLR(t, size, rootHash)
	tc.mu.Lock()
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: size, RootHash: rootHash}, signed: signed})
	tc.notifyWaiters(size)
	tc.mu.Unlock()
}

// waitForWaiters blocks until at least n callers have registered, or fails the
// test after a timeout. Replaces fragile time.Sleep registration barriers.
func waitForWaiters(t *testing.T, tc *cachedTrillianClient, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		tc.mu.Lock()
		got := tc.waitersHeap.Len()
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
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 42, Options{})
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

// mockServer starts a Trillian mock server and returns it along with its
// address, closing both when the test ends.
func mockServer(t *testing.T) (*testonly.MockServer, string) {
	t.Helper()
	mockCtl := gomock.NewController(t)
	t.Cleanup(mockCtl.Finish)
	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	t.Cleanup(closeFn)
	return s, s.Addr
}

func rootSize(t *testing.T, resp *internalclient.Response) uint64 {
	t.Helper()
	var got types.LogRootV1
	require.NoError(t, got.UnmarshalBinary(resp.GetLatestResult.SignedLogRoot.LogRoot))
	return got.TreeSize
}

func TestGetLatest_RefreshesStaleActiveRoot(t *testing.T) {
	tr := newLogTree(t, 2)
	s, addr := mockServer(t)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).
		Return(tr.resp(1, 2), nil).Times(1)

	tc := staleStartedClient(t, addr, 790, Options{MaxSTHStaleness: time.Second}, 1, tr.root(1))
	before := testutil.ToFloat64(metricRootRefresh.WithLabelValues(tc.treeIDStr, "success"))

	resp := tc.GetLatest(context.Background())
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
	require.EqualValues(t, 2, rootSize(t, resp))
	require.Equal(t, before+1, testutil.ToFloat64(metricRootRefresh.WithLabelValues(tc.treeIDStr, "success")))
}

func TestGetLatest_StaleRefreshFailureIsUnavailable(t *testing.T) {
	s, addr := mockServer(t)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).
		Return(nil, status.Error(codes.Unavailable, "boom")).Times(1)

	tc := staleStartedClient(t, addr, 793, Options{MaxSTHStaleness: time.Second}, 1, make([]byte, 32))
	before := testutil.ToFloat64(metricRootRefresh.WithLabelValues(tc.treeIDStr, "error"))

	resp := tc.GetLatest(context.Background())
	require.Error(t, resp.Err)
	require.Equal(t, codes.Unavailable, resp.Status)
	require.Equal(t, before+1, testutil.ToFloat64(metricRootRefresh.WithLabelValues(tc.treeIDStr, "error")))
}

// A Trillian slow enough that RootRPCTimeout fires is the brownout this whole
// path exists for. The underlying DeadlineExceeded must not reach the API layer,
// which reports it as HTTP 500 rather than a retryable 503.
func TestGetLatest_StaleRefreshTimeoutIsUnavailable(t *testing.T) {
	s, addr := mockServer(t)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, _ *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}).AnyTimes()

	tc := staleStartedClient(t, addr, 804, Options{
		MaxSTHStaleness: time.Second,
		RootRPCTimeout:  50 * time.Millisecond,
	}, 1, make([]byte, 32))

	resp := tc.GetLatest(context.Background())
	require.Error(t, resp.Err)
	require.Equal(t, codes.Unavailable, resp.Status)
	require.Equal(t, codes.Unavailable, status.Code(resp.Err), "Err's code must agree with Status")
}

// Coalescing alone does not bound a fast-failing Trillian: each attempt clears
// refreshInFlight before the next request arrives, so without the PollInterval
// floor the refresh rate would equal the request rate.
func TestGetLatest_StaleRefreshThrottlesAfterFastFailure(t *testing.T) {
	s, addr := mockServer(t)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).
		Return(nil, status.Error(codes.Unavailable, "boom")).Times(1)

	tc := staleStartedClient(t, addr, 802, Options{MaxSTHStaleness: time.Millisecond, PollInterval: time.Hour}, 1, make([]byte, 32))

	// Serial calls, each completing before the next begins — the shape that
	// defeats coalescing.
	for range 5 {
		require.Equal(t, codes.Unavailable, tc.GetLatest(context.Background()).Status)
	}
}

// Startup against a down Trillian is the worst case for init: every request in
// flight is a first-caller, and each attempt clears initInFlight before the next
// arrives, so coalescing alone would put init RPCs on a 1:1 footing with
// requests. Serial calls are the shape that defeats coalescing.
func TestEnsureStarted_ThrottlesAfterFastFailure(t *testing.T) {
	s, addr := mockServer(t)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).
		Return(nil, status.Error(codes.Unavailable, "boom")).Times(1)

	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(dialMock(t, addr)), 822, Options{PollInterval: time.Hour})
	t.Cleanup(tc.Close)

	for range 5 {
		require.Equal(t, codes.Unavailable, tc.GetLatest(context.Background()).Status)
	}
}

// A throttled init must not read as success: there is no cached root behind it,
// so a nil error would let the caller serve the zero-value snapshot as a real
// tree of size 0.
func TestEnsureStarted_ThrottledInitDoesNotServeEmptyTree(t *testing.T) {
	s, addr := mockServer(t)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).
		Return(nil, status.Error(codes.Unavailable, "boom")).Times(1)

	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(dialMock(t, addr)), 823, Options{PollInterval: time.Hour})
	t.Cleanup(tc.Close)

	require.Equal(t, codes.Unavailable, tc.GetLatest(context.Background()).Status)

	resp := tc.GetLatest(context.Background()) // throttled
	require.Equal(t, codes.Unavailable, resp.Status)
	require.Nil(t, resp.GetLatestResult)
	require.False(t, tc.started.Load())
}

// The point of the design: concurrent callers against a stale cache collapse
// onto a single RPC rather than stampeding Trillian.
func TestGetLatest_StaleRefreshCoalescesConcurrentCallers(t *testing.T) {
	tr := newLogTree(t, 2)
	release := make(chan struct{})
	s, addr := mockServer(t)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			<-release
			return tr.resp(1, 2), nil
		}).Times(1)

	tc := staleStartedClient(t, addr, 794, Options{MaxSTHStaleness: time.Second}, 1, tr.root(1))

	const callers = 16
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			resp := tc.GetLatest(context.Background())
			require.Equal(t, codes.OK, resp.Status)
		}()
	}
	// Give every caller time to arrive at the shared fetch before it completes.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
}

func TestGetLatest_CallerCancelDuringRefresh(t *testing.T) {
	tr := newLogTree(t, 2)
	release := make(chan struct{})
	s, addr := mockServer(t)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			<-release
			return tr.resp(1, 2), nil
		}).Times(1)

	tc := staleStartedClient(t, addr, 795, Options{MaxSTHStaleness: time.Second}, 1, tr.root(1))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *internalclient.Response, 1)
	go func() { done <- tc.GetLatest(ctx) }()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case resp := <-done:
		require.Equal(t, codes.Canceled, resp.Status)
	case <-time.After(2 * time.Second):
		t.Fatal("canceled caller did not return promptly")
	}

	// The shared fetch outlives the caller that started it and still publishes.
	close(release)
	require.Eventually(t, func() bool {
		return tc.snapshot.Load().(rootSnapshot).root.TreeSize == 2
	}, 2*time.Second, 5*time.Millisecond)
}

func TestGetLatest_CloseDuringRefresh(t *testing.T) {
	release := make(chan struct{})
	s, addr := mockServer(t)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			<-release
			return &trillian.GetLatestSignedLogRootResponse{SignedLogRoot: mkSLR(t, 2, make([]byte, 32))}, nil
		}).AnyTimes()

	// Unblock the handler only once the test is over, so the refresh RPC is
	// still on the wire while Close runs. Releasing it earlier would leave the
	// publish racing Close's stopCh rather than deterministically losing to it.
	defer close(release)

	tc := staleStartedClient(t, addr, 796, Options{MaxSTHStaleness: time.Second}, 1, make([]byte, 32))

	go tc.GetLatest(context.Background()) //nolint:errcheck // result is irrelevant; Close is under test
	time.Sleep(20 * time.Millisecond)

	closed := make(chan struct{})
	go func() { tc.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked on an in-flight refresh")
	}
	// bgCancel aborts the in-flight refresh, so it fails in fetchRoot and never
	// reaches publishRoot — the cached root is untouched under every
	// interleaving, including Close winning the race before the RPC is sent.
	require.EqualValues(t, 1, tc.snapshot.Load().(rootSnapshot).root.TreeSize)
}

// A refresh RPC can succeed while returning a root we refuse to trust. The
// timestamp is not stamped in that case, so GetLatest must still fail.
func TestGetLatest_StaleRefreshIntegrityAnomaly(t *testing.T) {
	s, addr := mockServer(t)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).
		Return(&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: mkSLR(t, 1, bytes.Repeat([]byte{0xbb}, 32))}, nil).Times(1)

	tc := staleStartedClient(t, addr, 797, Options{MaxSTHStaleness: time.Second}, 1, bytes.Repeat([]byte{0xaa}, 32))
	before := testutil.ToFloat64(metricRootIntegrityAnomaly.WithLabelValues(tc.treeIDStr))
	beforeRejected := testutil.ToFloat64(metricRootRefresh.WithLabelValues(tc.treeIDStr, "rejected"))

	resp := tc.GetLatest(context.Background())
	require.Equal(t, codes.Unavailable, resp.Status)
	require.Equal(t, before+1, testutil.ToFloat64(metricRootIntegrityAnomaly.WithLabelValues(tc.treeIDStr)))
	// The RPC succeeded, so this must not be counted as a refresh success.
	require.Equal(t, beforeRejected+1, testutil.ToFloat64(metricRootRefresh.WithLabelValues(tc.treeIDStr, "rejected")))
}

// A smaller returned root should never happen — the log does not move backwards
// — but the guard against it must not itself be a failure mode: the fetch still
// corroborated the cache, so it clears staleness while leaving the larger cached
// root in place.
func TestGetLatest_StaleRefreshBackwardsRoot(t *testing.T) {
	rootHash := bytes.Repeat([]byte{0x45}, 32)
	s, addr := mockServer(t)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).
		Return(&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: mkSLR(t, 3, rootHash)}, nil).Times(1)

	tc := staleStartedClient(t, addr, 798, Options{MaxSTHStaleness: time.Second}, 5, rootHash)

	resp := tc.GetLatest(context.Background())
	require.Equal(t, codes.OK, resp.Status)
	require.EqualValues(t, 5, rootSize(t, resp))
	require.False(t, tc.isStale())
}

func TestGetLatest_AllowsStaleFrozenRootWithoutRefresh(t *testing.T) {
	_, addr := mockServer(t) // no EXPECT: any RPC fails the controller
	tc := staleStartedClient(t, addr, 791, Options{
		MaxSTHStaleness: time.Second,
		FrozenTreeIDs:   map[int64]struct{}{791: {}},
	}, 1, make([]byte, 32))

	resp := tc.GetLatest(context.Background())
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
}

func TestGetLatest_FreshCacheIssuesNoRPC(t *testing.T) {
	_, addr := mockServer(t) // no EXPECT: any RPC fails the controller
	tc := staleStartedClient(t, addr, 799, Options{MaxSTHStaleness: time.Minute}, 1, make([]byte, 32))
	tc.stampRootFetch()

	resp := tc.GetLatest(context.Background())
	require.NoError(t, resp.Err)
	require.Equal(t, codes.OK, resp.Status)
}

func TestNewCachedTrillianClient_NormalizesConfig(t *testing.T) {
	for _, tt := range []struct {
		name            string
		in              Options
		pollInterval    time.Duration
		maxSTHStaleness time.Duration
	}{
		{
			name:            "zero defaults",
			in:              Options{},
			pollInterval:    DefaultPollInterval,
			maxSTHStaleness: successfulRootFetchMaxPollIntervals*DefaultPollInterval + DefaultRootRPCTimeout,
		},
		{
			// Cost is linear in 1/PollInterval and permanent; the benefit stops
			// at Trillian's sequencer interval. A typo must not bill 1000
			// RPCs/sec/shard forever.
			name:            "below the floor is clamped",
			in:              Options{PollInterval: time.Millisecond, RootRPCTimeout: time.Second},
			pollInterval:    MinPollInterval,
			maxSTHStaleness: successfulRootFetchMaxPollIntervals*MinPollInterval + time.Second,
		},
		{
			name:            "explicit values are respected",
			in:              Options{PollInterval: 500 * time.Millisecond, RootRPCTimeout: time.Second, MaxSTHStaleness: time.Minute},
			pollInterval:    500 * time.Millisecond,
			maxSTHStaleness: time.Minute,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tc := newCachedTrillianClient(nil, 830, tt.in)
			t.Cleanup(tc.Close)
			require.Equal(t, tt.pollInterval, tc.config.PollInterval)
			require.Equal(t, tt.maxSTHStaleness, tc.config.MaxSTHStaleness)
		})
	}
}

// The freshness bound is a property of the cached root, not of GetLatest. Every
// path that serves that root — or signs a proof against it — has to enforce it,
// or the bound is advertised and unenforced on three of four entry points.
func TestStaleCacheIsUnavailableOnEveryReadPath(t *testing.T) {
	for _, tt := range []struct {
		name string
		call func(*cachedTrillianClient) *internalclient.Response
	}{
		{"GetLatest", func(tc *cachedTrillianClient) *internalclient.Response {
			return tc.GetLatest(context.Background())
		}},
		{"GetLeafAndProofByHash", func(tc *cachedTrillianClient) *internalclient.Response {
			return tc.GetLeafAndProofByHash(context.Background(), bytes.Repeat([]byte{0x01}, 32))
		}},
		{"GetLeafAndProofByIndex", func(tc *cachedTrillianClient) *internalclient.Response {
			return tc.GetLeafAndProofByIndex(context.Background(), 0)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, addr := mockServer(t)
			// The refresh is the only RPC permitted: reaching a proof RPC against
			// an uncorroborated root is the failure this test exists to catch.
			s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).
				Return(nil, status.Error(codes.Unavailable, "boom")).Times(1)

			tc := staleStartedClient(t, addr, 820, Options{MaxSTHStaleness: time.Second}, 4, make([]byte, 32))
			resp := tt.call(tc)
			require.Equal(t, codes.Unavailable, resp.Status)
			require.Equal(t, codes.Unavailable, status.Code(resp.Err), "Err's code must agree with Status")
		})
	}
}

// AddLeaf gates before QueueLeaf, so a stale cache costs the caller an error
// rather than an entry that is in the log but reported as failed. The absent
// QueueLeaf expectation is the assertion: gomock fails the test if it is called.
func TestAddLeaf_StaleCacheDoesNotQueue(t *testing.T) {
	s, addr := mockServer(t)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).
		Return(nil, status.Error(codes.Unavailable, "boom")).Times(1)

	tc := staleStartedClient(t, addr, 821, Options{MaxSTHStaleness: time.Second}, 4, make([]byte, 32))
	resp := tc.AddLeaf(context.Background(), []byte("entry"))
	require.Equal(t, codes.Unavailable, resp.Status)
	require.Nil(t, resp.GetAddResult)
}

func TestPublishRoot_RefreshesSuccessfulFetchTimeAndMetric(t *testing.T) {
	const treeID = 792
	rootHash := bytes.Repeat([]byte{0x42}, 32)
	root := types.LogRootV1{TreeSize: 1, RootHash: rootHash}
	signed := mkSLR(t, 1, rootHash)
	tc := newCachedTrillianClient(nil, treeID, Options{})
	tc.snapshot.Store(rootSnapshot{root: root, signed: signed})
	tc.lastRootFetch.Store(time.Now().Add(-time.Hour).UnixNano())
	t.Cleanup(tc.Close)

	tc.publishRoot(root, signed)
	require.Less(t, tc.rootAge(), time.Second)
	require.Greater(t, testutil.ToFloat64(metricLastSuccessfulRootFetch.WithLabelValues(tc.treeIDStr)), float64(time.Now().Add(-time.Second).Unix()))
}

// Note: waiting for an advance via the background updater's fixed-cadence poll
// is exercised indirectly in other tests (AddLeaf), and is hard to
// deterministically simulate across environments with the mock server; we avoid
// a direct waitForInclusionWithMinSize wait test here.

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
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 9, Options{})
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
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 13, Options{})
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
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 21, Options{})
	// Pre-initialize
	tc.started.Store(true)
	tc.storeSnapshot(types.LogRootV1{TreeSize: 0, RootHash: make([]byte, 32)}, slr0)
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
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 99, Options{})
	t.Cleanup(tc.Close)

	resp := tc.GetLatest(context.Background())
	require.Error(t, resp.Err)
	require.Equal(t, codes.Unavailable, resp.Status)
}

func TestWaitForRootAtLeast_BroadcastWakesAll(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	tc := newCachedTrillianClient(nil, 100, Options{})
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
	cfg := Options{}
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
	tc := newCachedTrillianClient(nil, 303, Options{})
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
	stillWaiting := tc.waitersHeap.Len()
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
	tc := newCachedTrillianClient(nil, 404, Options{})
	tc.started.Store(true)
	// Provide a minimal signed root so GetLatest can return without NotFound,
	// and stamp it so readers never trip the staleness refresh (the client has
	// no gRPC connection).
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}, signed: mkSLR(t, 0, make([]byte, 32))})
	tc.stampRootFetch()
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
			tc.storeSnapshot(*lr, &trillian.SignedLogRoot{LogRoot: b})
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
	// within RootRPCTimeout. The init the tight caller abandoned keeps running,
	// so a later patient caller coalesces onto it rather than starting its own.
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			time.Sleep(100 * time.Millisecond)
			return &trillian.GetLatestSignedLogRootResponse{SignedLogRoot: mkSLR(t, 7, make([]byte, 32))}, nil
		},
	).Times(1) // the abandoning caller must not cause a second init RPC

	conn := dialMock(t, s.Addr)
	cfg := Options{}
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
	cfg := Options{RootRPCTimeout: 10 * time.Second} // long, so if Close waited on it the test would fail
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
	// RootRPCTimeout still bounds init when Trillian is genuinely slow, and the
	// resulting DeadlineExceeded is reported as Unavailable: a slow Trillian is
	// something to retry, not a server defect.
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
	cfg := Options{}
	cfg.RootRPCTimeout = 50 * time.Millisecond
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 607, cfg)
	t.Cleanup(tc.Close)

	start := time.Now()
	resp := tc.GetLatest(context.Background())
	elapsed := time.Since(start)

	require.Error(t, resp.Err)
	require.Equal(t, codes.Unavailable, resp.Status)
	require.False(t, tc.started.Load(), "started must remain false on init failure so retry is possible")
	require.Less(t, elapsed, 500*time.Millisecond, "init should give up near RootRPCTimeout, not hang")
}

// --- New tests for channel-per-caller and edge cases ---

func TestWaitForRootAtLeast_AlreadySatisfied(t *testing.T) {
	tc := newCachedTrillianClient(nil, 500, Options{})
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
	tc := newCachedTrillianClient(nil, 501, Options{})
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
		// Must carry codes.Canceled, not codes.Unknown: the API layer maps the
		// status code straight to HTTP, so a bare context error becomes a 500.
		require.Equal(t, codes.Canceled, status.Code(err))
	case <-time.After(500 * time.Millisecond):
		t.Fatal("waiter was not unblocked by context cancellation")
	}
}

// TestWaitForInclusion_ExpiredContext_ReportsDeadlineExceeded covers the loop
// guard in waitForInclusionWithMinSize. A bare ctx.Err() there is codes.Unknown,
// which the API layer renders as HTTP 500 for what is really a client timeout.
func TestWaitForInclusion_ExpiredContext_ReportsDeadlineExceeded(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	tc := newCachedTrillianClient(nil, 506, Options{})
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 5}})
	t.Cleanup(tc.Close)

	// Already past its deadline, so the guard trips before any proof RPC.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	resp := tc.waitForInclusionWithMinSize(ctx, bytes.Repeat([]byte{0x01}, 32), 1)
	require.Error(t, resp.Err)
	require.Equal(t, codes.DeadlineExceeded, resp.Status)
}

func TestClose_UnblocksAllWaiters(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	tc := newCachedTrillianClient(nil, 502, Options{})
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

// TestRemoveWaiter_AfterCloseDrain_NoPanic pins the contract between Close's
// drain and removeWaiter. Close closes every waiter channel and nils the heap;
// a waiter woken by that drain may still take its stopCh branch and call
// removeWaiter. Unless the drain clears index, that is a heap.Remove against a
// nil heap. TestClose_UnblocksAllWaiters only hits this branch by racing the
// select, so assert it directly.
func TestRemoveWaiter_AfterCloseDrain_NoPanic(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	tc := newCachedTrillianClient(nil, 505, Options{})
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})

	tc.mu.Lock()
	w := tc.registerWaiter(99)
	tc.mu.Unlock()

	tc.Close()

	tc.mu.Lock()
	require.Nil(t, tc.waitersHeap, "Close must drop the heap")
	require.Negative(t, w.index, "drain must mark drained waiters as removed")
	require.NotPanics(t, func() { tc.removeWaiter(w) })
	tc.mu.Unlock()
}

// TestWaitForRootAtLeast_AfterClose_NoPanic guards against a regression where a
// waitForRootAtLeast caller arriving after Close registered a waiter that
// nothing would ever signal. waitForRootAtLeast must observe stopCh under t.mu
// before registering and return codes.Canceled instead.
func TestWaitForRootAtLeast_AfterClose_NoPanic(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	tc := newCachedTrillianClient(nil, 504, Options{})
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})

	tc.Close()

	// Any request above the current size after Close must return Canceled
	// rather than blocking on a waiter no advance will ever satisfy.
	err := tc.waitForRootAtLeast(context.Background(), 999)
	require.Error(t, err)
	require.Equal(t, codes.Canceled, status.Code(err))
}

// TestClose_Idempotent guards against a regression where a second Close would
// panic on double-close of the waiter channels (the heap retained entries
// pointing at already-closed channels). Close must now be safe to invoke
// multiple times, including concurrently, and each caller must synchronize
// with the updater's exit before returning.
func TestClose_Idempotent(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	tc := newCachedTrillianClient(nil, 505, Options{})
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
	tc := newCachedTrillianClient(nil, 503, Options{})
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})
	t.Cleanup(tc.Close)

	tc.mu.Lock()
	w3 := tc.registerWaiter(3)
	w5 := tc.registerWaiter(5)
	w10 := tc.registerWaiter(10)
	tc.mu.Unlock()

	// Notify with size 5: should satisfy waiters for 3 and 5, but not 10
	tc.mu.Lock()
	tc.notifyWaiters(5)
	tc.mu.Unlock()

	// w3 and w5 should be closed (readable immediately)
	select {
	case <-w3.ch:
		// expected
	default:
		t.Fatal("waiter for size 3 should have been notified")
	}
	select {
	case <-w5.ch:
		// expected
	default:
		t.Fatal("waiter for size 5 should have been notified")
	}

	// w10 should NOT be closed
	select {
	case <-w10.ch:
		t.Fatal("waiter for size 10 should NOT have been notified")
	default:
		// expected
	}

	tc.mu.Lock()
	require.Equal(t, 1, tc.waitersHeap.Len())
	require.Equal(t, uint64(10), tc.waitersHeap[0].size)
	tc.mu.Unlock()
}

func TestRemoveWaiter_Cleanup(t *testing.T) {
	tc := newCachedTrillianClient(nil, 504, Options{})
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})
	t.Cleanup(tc.Close)

	tc.mu.Lock()
	w5 := tc.registerWaiter(5)
	w10 := tc.registerWaiter(10)
	require.Equal(t, 2, tc.waitersHeap.Len())

	tc.removeWaiter(w5)
	require.Equal(t, 1, tc.waitersHeap.Len())
	require.Same(t, w10, tc.waitersHeap[0])

	// Removing an already-removed waiter is a no-op, not a heap corruption.
	tc.removeWaiter(w5)
	require.Equal(t, 1, tc.waitersHeap.Len())
	require.Same(t, w10, tc.waitersHeap[0])
	tc.mu.Unlock()
}

// TestWaiterHeap_OrderingUnderShuffledSizes registers waiters at deliberately
// shuffled target sizes and asserts notifyWaiters wakes exactly the correct
// prefix at each threshold. Exercises the min-heap ordering property.
func TestWaiterHeap_OrderingUnderShuffledSizes(t *testing.T) {
	tc := newCachedTrillianClient(nil, 510, Options{})
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})
	t.Cleanup(tc.Close)

	// Register waiters at sizes chosen to force multiple heap re-siftings.
	sizes := []uint64{50, 10, 100, 20, 5, 75, 30, 1, 60, 40}
	waiters := make([]*waiterItem, len(sizes))
	tc.mu.Lock()
	for i, sz := range sizes {
		waiters[i] = tc.registerWaiter(sz)
	}
	require.Equal(t, len(sizes), tc.waitersHeap.Len())
	tc.mu.Unlock()

	// Step 1: notify size 25 — wakes 1, 5, 10, 20 (4 waiters), leaves 6.
	tc.mu.Lock()
	tc.notifyWaiters(25)
	require.Equal(t, 6, tc.waitersHeap.Len())
	tc.mu.Unlock()

	for i, sz := range sizes {
		select {
		case <-waiters[i].ch:
			require.LessOrEqual(t, sz, uint64(25), "only waiters with size ≤ 25 should be closed")
		default:
			require.Greater(t, sz, uint64(25), "waiters with size > 25 should still be open")
		}
	}

	// Step 2: notify size 60 — wakes 30, 40, 50, 60 (4 more), leaves 2 (75, 100).
	tc.mu.Lock()
	tc.notifyWaiters(60)
	require.Equal(t, 2, tc.waitersHeap.Len())
	tc.mu.Unlock()

	for i, sz := range sizes {
		if sz > 25 {
			select {
			case <-waiters[i].ch:
				require.LessOrEqual(t, sz, uint64(60), "only waiters with size ≤ 60 should now be closed")
			default:
				require.Greater(t, sz, uint64(60))
			}
		}
	}

	// Step 3: notify size 1000 — drain everything.
	tc.mu.Lock()
	tc.notifyWaiters(1000)
	require.Zero(t, tc.waitersHeap.Len())
	tc.mu.Unlock()
}

// TestRemoveWaiter_MidHeap_PreservesInvariants removes a waiter that is not
// at the root of the heap, then verifies subsequent notify still wakes the
// correct set. Regression guard for a broken heap.Remove index-tracking.
func TestRemoveWaiter_MidHeap_PreservesInvariants(t *testing.T) {
	tc := newCachedTrillianClient(nil, 511, Options{})
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: 0}})
	t.Cleanup(tc.Close)

	tc.mu.Lock()
	// Push in an order that puts size 50 somewhere in the interior of the heap.
	w10 := tc.registerWaiter(10)
	w50 := tc.registerWaiter(50)
	w20 := tc.registerWaiter(20)
	w60 := tc.registerWaiter(60)
	w30 := tc.registerWaiter(30)

	// Remove an interior waiter (size 50 will not be at index 0 given size 10 is smallest).
	require.NotZero(t, w50.index, "size 50 should not be the heap root here")
	tc.removeWaiter(w50)
	require.Equal(t, 4, tc.waitersHeap.Len())

	// Notify size 35 — wakes 10, 20, 30. Leaves 60. 50 was removed and must not fire.
	tc.notifyWaiters(35)
	tc.mu.Unlock()

	for _, tt := range []struct {
		w      *waiterItem
		wake   bool
		reason string
	}{
		{w10, true, "size 10 ≤ 35"},
		{w20, true, "size 20 ≤ 35"},
		{w30, true, "size 30 ≤ 35"},
		{w60, false, "size 60 > 35"},
	} {
		select {
		case <-tt.w.ch:
			require.True(t, tt.wake, tt.reason)
		default:
			require.False(t, tt.wake, tt.reason)
		}
	}
	// w50 was removed, so it must not have been closed by notify.
	select {
	case <-w50.ch:
		t.Fatal("removed waiter (size 50) must not be closed by notify")
	default:
	}

	tc.mu.Lock()
	require.Equal(t, 1, tc.waitersHeap.Len()) // only size 60 remains
	require.Same(t, w60, tc.waitersHeap[0])
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
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 600, Options{PollInterval: 20 * time.Millisecond})
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
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 601, Options{
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

// TestClientManager_ConcurrentGetClientAndClose exercises the shutdown flag
// from both sides at once. It previously required getConn to take clientMu
// while holding connMu, the reverse of the order Close uses; the flag is now
// atomic so neither path nests the two mutexes.
func TestClientManager_ConcurrentGetClientAndClose(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	cm := NewClientManager(Options{DefaultGRPC: GRPCConfig{Address: s.Addr, Port: 0}})

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			// Either a client or a shutting-down error is fine; a deadlock,
			// a race, or a nil client is not.
			c, err := cm.GetClient(int64(i % 4))
			if err == nil {
				require.NotNil(t, c)
			} else {
				require.Contains(t, err.Error(), "shutting down")
			}
		})
	}
	wg.Go(func() { require.NoError(t, cm.Close()) })
	wg.Wait()

	_, err = cm.GetClient(0)
	require.Error(t, err)
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

	require.True(t, cm.shutdown.Load())
	cm.clientMu.RLock()
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
	frozenCfg := Options{}
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
	frozenCfg := Options{}
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
// fetch-gate to fire should drive it with driveUpdaterCycles.
//
// The root is stamped as just-fetched. Every cached read path gates on
// ensureFresh, so an unstamped client would divert into a staleness refresh no
// mock expects. Tests that want the stale path use staleStartedClient.
func primedClient(t *testing.T, s *testonly.MockServer, treeID int64, size uint64, rootHash []byte) *cachedTrillianClient {
	t.Helper()
	conn := dialMock(t, s.Addr)
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), treeID, Options{})
	tc.storeSnapshot(types.LogRootV1{TreeSize: size, RootHash: rootHash}, mkSLR(t, size, rootHash))
	tc.started.Store(true)
	return tc
}

// updaterCycle mimics one updater poll cycle: Swap in a fresh gate for the NEXT
// cycle, publish root if non-nil, then close the PREVIOUS gate so readers that
// captured it wake. A nil root is a no-advance poll — the gate still closes.
func updaterCycle(tc *cachedTrillianClient, root *types.LogRootV1, signed *trillian.SignedLogRoot) {
	prev := tc.nextGate.Swap(&fetchGate{done: make(chan struct{})})
	if root != nil {
		tc.publishRoot(*root, signed)
	}
	close(prev.done)
}

// simulateUpdaterCycle runs exactly one cycle publishing the given root (size 0
// means no advance). Use it only when the reader is already parked on the gate;
// otherwise use driveUpdaterCycles.
func simulateUpdaterCycle(t *testing.T, tc *cachedTrillianClient, size uint64, rootHash []byte) {
	t.Helper()
	root, signed := cycleRoot(t, size, rootHash)
	updaterCycle(tc, root, signed)
}

func cycleRoot(t *testing.T, size uint64, rootHash []byte) (*types.LogRootV1, *trillian.SignedLogRoot) {
	t.Helper()
	if size == 0 {
		return nil, nil
	}
	return &types.LogRootV1{TreeSize: size, RootHash: rootHash}, mkSLR(t, size, rootHash)
}

// driveUpdaterCycles runs updater cycles in the background until the returned
// stop func is called. This replaces a sleep-based "wait for the reader to
// capture the gate" barrier: a cycle that runs before the reader's Load is
// harmless — publishRoot leaves the snapshot untouched for a non-advancing
// root — so the loop simply repeats until the gate the reader actually
// captured gets closed.
func driveUpdaterCycles(t *testing.T, tc *cachedTrillianClient, size uint64, rootHash []byte) (stop func()) {
	t.Helper()
	root, signed := cycleRoot(t, size, rootHash)
	stopped := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			updaterCycle(tc, root, signed)
			select {
			case <-stopped:
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	})
	return func() {
		close(stopped)
		wg.Wait()
	}
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

// A proof with no leaf is malformed rather than absent, and must not be
// dereferenced: reading MerkleLeafHash off the nil leaf panics the handler.
func TestGetLeafAndProofByIndex_ProofWithNilLeaf(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	tc := primedClient(t, s, 812, 1, make([]byte, 32))
	t.Cleanup(tc.Close)

	s.Log.EXPECT().GetEntryAndProof(gomock.Any(), gomock.Any()).Return(
		&trillian.GetEntryAndProofResponse{Proof: &trillian.Proof{LeafIndex: 0}}, nil,
	).Times(1)

	resp := tc.GetLeafAndProofByIndex(context.Background(), 0)
	require.Equal(t, codes.Internal, resp.Status)
	require.ErrorContains(t, resp.Err, "no leaf")
}

// A proof for a different leaf than the one requested verifies fine on its own
// terms — it is a genuine proof, just for the wrong entry. Only comparing it
// against the requested index catches the substitution.
func TestGetLeafAndProofByIndex_ProofForWrongIndex(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	s, closeFn, err := testonly.NewMockServer(mockCtl)
	require.NoError(t, err)
	defer closeFn()

	tc := primedClient(t, s, 813, 5, make([]byte, 32))
	t.Cleanup(tc.Close)

	s.Log.EXPECT().GetEntryAndProof(gomock.Any(), gomock.Any()).Return(
		&trillian.GetEntryAndProofResponse{
			Leaf:  &trillian.LogLeaf{MerkleLeafHash: bytes.Repeat([]byte{0x66}, 32)},
			Proof: &trillian.Proof{LeafIndex: 3},
		}, nil,
	).Times(1)

	resp := tc.GetLeafAndProofByIndex(context.Background(), 0)
	require.Equal(t, codes.Internal, resp.Status)
	require.ErrorContains(t, resp.Err, "index 0 was requested")
}

func TestReadAfterWrite_ByIndex_OutOfRange_GateAdvanceThenSucceeds(t *testing.T) {
	// Cache says empty; reader captures the gate. Background updater cycles
	// publish size=1 with the target root and close the gate. Reader wakes,
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

	// Only GetEntryAndProof — the "root RPC" is replaced by driveUpdaterCycles.
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
	defer driveUpdaterCycles(t, tc, 1, newHash)()

	select {
	case resp := <-done:
		require.NoError(t, resp.Err)
		require.Equal(t, codes.OK, resp.Status)
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not complete after updater cycles")
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
	defer driveUpdaterCycles(t, tc, 10, bytes.Repeat([]byte{0x22}, 32))()

	select {
	case resp := <-done:
		require.Error(t, resp.Err)
		require.Equal(t, codes.NotFound, resp.Status)
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not complete after updater cycles")
	}
}

func TestReadAfterWrite_ByIndex_NegativeInvalidArg(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	// No mock server, no client conn — negative check must reject BEFORE
	// ensureStarted, so no init RPC is triggered.
	tc := newCachedTrillianClient(nil, 803, Options{})
	t.Cleanup(tc.Close)

	resp := tc.GetLeafAndProofByIndex(context.Background(), -1)
	require.Error(t, resp.Err)
	require.Equal(t, codes.InvalidArgument, resp.Status)
}

func TestReadAfterWrite_ByHash_MissWaitsForGateThenSucceeds(t *testing.T) {
	// Cache says empty; reader's initial proof attempt short-circuits inside
	// getProofByHashWithRoot on TreeSize==0 and returns NotFound (no RPC).
	// Reader captures the fetch-gate. Background updater cycles publish
	// size=1 with the target hash and close the gate. Reader wakes, retries
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
	defer driveUpdaterCycles(t, tc, 1, newHash)()

	select {
	case resp := <-done:
		require.NoError(t, resp.Err)
		require.Equal(t, codes.OK, resp.Status)
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not complete after updater cycles")
	}
}

func TestReadAfterWrite_ByHash_GateFiresWithoutAdvance_NotFoundWithoutRetry(t *testing.T) {
	// First proof call at cached size 1: NotFound. Reader captures the gate. The
	// updater cycles keep the tree at size 1 but still close the gate — a real
	// "same-size poll", which must not strand waiters. The reader wakes, sees
	// the tree did not move, and returns the miss it already has: a second query
	// at the same size is answered from the same leaf set and cannot differ.
	// One proof RPC, and no loop.
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
	).Times(1)

	unknownHash := bytes.Repeat([]byte{0x55}, 32)
	done := make(chan *internalclient.Response, 1)
	go func() {
		done <- tc.GetLeafAndProofByHash(context.Background(), unknownHash)
	}()
	// No-advance cycles: the gate still closes, so the reader wakes. Size 0
	// skips publishRoot entirely.
	defer driveUpdaterCycles(t, tc, 0, nil)()

	select {
	case resp := <-done:
		require.Error(t, resp.Err)
		require.Equal(t, codes.NotFound, resp.Status)
		require.EqualValues(t, 1, proofCalls.Load(), "an unchanged tree cannot answer differently; the retry is pure waste")
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not complete after updater cycles")
	}
}

func TestPublishRoot_MonotonicAgainstDelayedPollerResponse(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	// No RPCs — publishRoot exercised directly to verify monotonic guard
	// against out-of-order publishes from concurrent updater+refresh.
	tc := newCachedTrillianClient(nil, 860, Options{})
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

	// Delayed "poller" tries to publish size 5 — the snapshot must not regress.
	// An updater poll and an on-demand refresh can be in flight at once and
	// complete out of order, so a late response can carry an older size than one
	// already published. The fetch is still stamped: it is evidence the log is
	// alive even though it is not evidence of a new tree state.
	require.False(t, tc.publishRoot(types.LogRootV1{TreeSize: 5, RootHash: hash5}, mkSLR(t, 5, hash5)))

	snap := tc.snapshot.Load().(rootSnapshot)
	require.EqualValues(t, 10, snap.root.TreeSize, "snapshot must not regress")
	require.True(t, bytes.Equal(hash10, snap.root.RootHash))
}

func TestPublishRoot_IntegrityAnomaly_NotPublished(t *testing.T) {
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, append([]goleak.Option{opt}, grpcDialIgnores...)...) })
	tc := newCachedTrillianClient(nil, 861, Options{})
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
	tc := newCachedTrillianClient(nil, 900, Options{})
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

func TestFetchGate_InstalledEvenForFrozenTree(t *testing.T) {
	// Frozen trees have no updater to swap or close the gate, and the read
	// paths branch out on t.frozen before they would touch it. The gate is
	// still installed so that nextGate is never nil for any caller.
	cfg := Options{FrozenTreeIDs: map[int64]struct{}{901: {}}}
	tc := newCachedTrillianClient(nil, 901, cfg)
	t.Cleanup(tc.Close)

	require.NotNil(t, tc.nextGate.Load(), "nextGate must never be nil")
}

func TestFetchGate_SimulateCycle_ClosesPreviousInstallsNext(t *testing.T) {
	// Direct verification of the Swap-and-close invariant: after one
	// simulated cycle, the previously-observed gate must be closed and
	// nextGate must point to a distinct, still-open gate.
	tc := newCachedTrillianClient(nil, 902, Options{})
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
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 903, Options{
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
	// Close: bgCancel wakes the reader via bgCtx.Done(). No barrier is needed —
	// a reader that reaches the gate after Close sees an already-canceled bgCtx
	// and takes the same branch.
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
	cfg := Options{FrozenTreeIDs: map[int64]struct{}{905: {}}}
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
	// N concurrent hash-lookup readers miss the empty cache and park on the
	// fetch-gate. Updater cycles publish the target and close the gate; every
	// reader parked on a given gate wakes together and retries. The point is
	// that no reader issues a root RPC of its own: the fetch-gate coalesces
	// stale-miss readers onto the shared updater cadence, so the cost of the
	// storm is bounded by that cadence rather than by N.
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

	// Each cycle publishes size=1 with newHash and closes the gate it replaced,
	// waking every reader parked on that gate at once.
	stop := driveUpdaterCycles(t, tc, 1, newHash)
	wg.Wait()
	stop()
	close(errs)
	for e := range errs {
		require.NoError(t, e, "all N readers must succeed once the gate closes")
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
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(conn), 907, Options{
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
