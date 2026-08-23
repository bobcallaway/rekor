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
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/trillian"
	"github.com/google/trillian/testonly"
	"github.com/google/trillian/types"
	internalclient "github.com/sigstore/rekor/internal/trillianclient"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newMockLog(t *testing.T) (*testonly.MockServer, trillian.TrillianLogClient) {
	t.Helper()
	ctl := gomock.NewController(t)
	s, closeServer, err := testonly.NewMockServer(ctl)
	require.NoError(t, err)
	t.Cleanup(closeServer)
	return s, trillian.NewTrillianLogClient(dialMock(t, s.Addr))
}

func snapshotSize(t *testing.T, resp *trillian.GetLatestSignedLogRootResponse) uint64 {
	t.Helper()
	var root types.LogRootV1
	require.NoError(t, root.UnmarshalBinary(resp.SignedLogRoot.LogRoot))
	return root.TreeSize
}

func TestCachedClientServesOneFetchedRoot(t *testing.T) {
	s, logClient := newMockLog(t)
	var calls atomic.Int32
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(context.Context, *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			calls.Add(1)
			return &trillian.GetLatestSignedLogRootResponse{SignedLogRoot: mkSLR(t, 7, make([]byte, 32))}, nil
		},
	).Times(1)

	tc := newCachedTrillianClient(logClient, 42, cacheOptions{pollInterval: time.Hour})
	t.Cleanup(tc.Close)
	for range 20 {
		resp := tc.GetLatest(context.Background())
		require.Equal(t, codes.OK, resp.Status)
		require.EqualValues(t, 7, snapshotSize(t, resp.GetLatestResult))
	}
	require.EqualValues(t, 1, calls.Load())
}

func TestCachedClientFrozenTreeFetchesOnce(t *testing.T) {
	s, logClient := newMockLog(t)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(
		&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: mkSLR(t, 3, make([]byte, 32))}, nil,
	).Times(1)

	tc := newCachedTrillianClient(logClient, 42, cacheOptions{pollInterval: time.Millisecond, frozen: true})
	resp := tc.GetLatest(context.Background())
	require.Equal(t, codes.OK, resp.Status)
	time.Sleep(5 * time.Millisecond)
	tc.Close()
}

func TestCachedClientRejectsConflictingRoot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tc := &cachedTrillianClient{
		opts:     cacheOptions{frozen: true}.withDefaults(),
		metrics:  newCachedClientMetrics(42),
		nextPoll: &pollResult{done: make(chan struct{})},
		stop:     cancel,
		stopped:  ctx,
	}

	_, err := tc.publish(rootSnapshot{root: types.LogRootV1{TreeSize: 1, RootHash: []byte("first")}})
	require.NoError(t, err)
	_, err = tc.publish(rootSnapshot{root: types.LogRootV1{TreeSize: 1, RootHash: []byte("second")}})
	require.Error(t, err)
	require.Equal(t, codes.DataLoss, status.Code(err))
}

func TestCachedClientDoesNotRefreshOnOlderRoot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tc := &cachedTrillianClient{
		opts:     cacheOptions{}.withDefaults(),
		metrics:  newCachedClientMetrics(43),
		nextPoll: &pollResult{done: make(chan struct{})},
		stop:     cancel,
		stopped:  ctx,
	}
	tc.snapshot.Store(&rootSnapshot{root: types.LogRootV1{TreeSize: 2, RootHash: []byte("newer")}})
	tc.lastSuccess.Store(123)

	published, err := tc.publish(rootSnapshot{root: types.LogRootV1{TreeSize: 1, RootHash: []byte("older")}})
	require.NoError(t, err)
	require.False(t, published)
	require.EqualValues(t, 123, tc.lastSuccess.Load())
	require.EqualValues(t, 2, tc.snapshot.Load().root.TreeSize)
}

func TestCachedClientCloseUnblocksInitialization(t *testing.T) {
	s, logClient := newMockLog(t)
	called := make(chan struct{})
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, _ *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			close(called)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	).Times(1)

	tc := newCachedTrillianClient(logClient, 42, cacheOptions{rootTimeout: time.Hour})
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp := tc.GetLatest(context.Background())
		require.Equal(t, codes.Canceled, resp.Status)
	}()
	<-called
	tc.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("GetLatest remained blocked after Close")
	}
	tc.Close()
}

func TestPollResultIsShared(t *testing.T) {
	const callers = 16
	result := &pollResult{done: make(chan struct{})}
	tc := &cachedTrillianClient{nextPoll: result, stopped: context.Background()}

	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			require.NoError(t, tc.waitForPoll(context.Background()))
		}()
	}
	close(result.done)
	wg.Wait()
}

func TestSizeWaitersWakeInOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tc := &cachedTrillianClient{
		opts:     cacheOptions{}.withDefaults(),
		metrics:  newCachedClientMetrics(42),
		nextPoll: &pollResult{done: make(chan struct{})},
		stop:     cancel,
		stopped:  ctx,
	}
	tc.snapshot.Store(&rootSnapshot{root: types.LogRootV1{TreeSize: 1}})
	tc.lastSuccess.Store(cacheClockNow())

	wake2 := make(chan error, 1)
	wake3 := make(chan error, 1)
	go func() { wake2 <- tc.waitForSize(context.Background(), 2) }()
	go func() { wake3 <- tc.waitForSize(context.Background(), 3) }()
	require.Eventually(t, func() bool {
		tc.mu.Lock()
		defer tc.mu.Unlock()
		return tc.waiters.waiterCount() == 2 && len(tc.waiters.heap) == 2
	}, time.Second, time.Millisecond)

	_, err := tc.publish(rootSnapshot{root: types.LogRootV1{TreeSize: 2}})
	require.NoError(t, err)
	require.NoError(t, <-wake2)
	select {
	case <-wake3:
		t.Fatal("waiter for size 3 woke at size 2")
	default:
	}

	_, err = tc.publish(rootSnapshot{root: types.LogRootV1{TreeSize: 3}})
	require.NoError(t, err)
	require.NoError(t, <-wake3)
	cancel()
}

func TestSizeWaitersShareTargetBucket(t *testing.T) {
	var waiters sizeWaiters
	first := waiters.add(10)
	second := waiters.add(10)
	third := waiters.add(20)
	require.Same(t, first, second)
	require.NotSame(t, first, third)
	require.Equal(t, 3, waiters.waiterCount())
	require.Len(t, waiters.heap, 2)

	waiters.release(first)
	require.Equal(t, 2, waiters.waiterCount())
	require.Len(t, waiters.heap, 2)
	ready := waiters.satisfy(10)
	require.Equal(t, []*sizeBucket{second}, ready)
	require.Equal(t, 1, waiters.waiterCount())
	require.Len(t, waiters.heap, 1)
}

func TestCachedClientBoundsPendingAndProofWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tc := &cachedTrillianClient{
		metrics: newCachedClientMetrics(44),
		pending: make(chan struct{}, 1),
		proofs:  make(chan struct{}, 2),
		stopped: ctx,
	}

	require.NoError(t, tc.acquirePending(context.Background()))
	require.Equal(t, codes.ResourceExhausted, status.Code(tc.acquirePending(context.Background())))
	tc.releasePending()

	require.NoError(t, tc.acquireProof(context.Background()))
	require.NoError(t, tc.acquireProof(context.Background()))
	proofCtx, proofCancel := context.WithCancel(context.Background())
	proofCancel()
	require.Equal(t, codes.Canceled, status.Code(tc.acquireProof(proofCtx)))
	tc.releaseProof()
	tc.releaseProof()
}

func TestCachedClientCloseUnblocksSizeWaiters(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tc := &cachedTrillianClient{
		opts:     cacheOptions{}.withDefaults(),
		metrics:  newCachedClientMetrics(45),
		nextPoll: &pollResult{done: make(chan struct{})},
		stop:     cancel,
		stopped:  ctx,
	}
	tc.snapshot.Store(&rootSnapshot{root: types.LogRootV1{TreeSize: 1}})
	tc.lastSuccess.Store(cacheClockNow())

	done := make(chan error, 1)
	go func() { done <- tc.waitForSize(context.Background(), 2) }()
	require.Eventually(t, func() bool {
		tc.mu.Lock()
		defer tc.mu.Unlock()
		return tc.waiters.waiterCount() == 1
	}, time.Second, time.Millisecond)

	tc.Close()
	require.Equal(t, codes.Canceled, status.Code(<-done))
	tc.Close()
}

func TestCachedAddWaitsForSharedRootAdvance(t *testing.T) {
	tree := newLogTree(t, 1)
	hash := tree.leafHash(0)
	s, logClient := newMockLog(t)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(tree.response(0, 0), nil).Times(1)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(tree.response(0, 1), nil).Times(1)

	queued := make(chan struct{})
	s.Log.EXPECT().QueueLeaf(gomock.Any(), gomock.Any()).DoAndReturn(
		func(context.Context, *trillian.QueueLeafRequest) (*trillian.QueueLeafResponse, error) {
			close(queued)
			return &trillian.QueueLeafResponse{QueuedLeaf: &trillian.QueuedLogLeaf{Leaf: &trillian.LogLeaf{MerkleLeafHash: hash}}}, nil
		},
	).Times(1)
	s.Log.EXPECT().GetInclusionProofByHash(gomock.Any(), gomock.Any()).Return(
		&trillian.GetInclusionProofByHashResponse{Proof: []*trillian.Proof{{LeafIndex: 0, Hashes: tree.inclusion(0, 1)}}}, nil,
	).Times(1)
	s.Log.EXPECT().GetLeavesByRange(gomock.Any(), gomock.Any()).Return(
		&trillian.GetLeavesByRangeResponse{Leaves: []*trillian.LogLeaf{{LeafIndex: 0, MerkleLeafHash: hash}}}, nil,
	).Times(1)

	tc := newCachedTrillianClient(logClient, 42, cacheOptions{pollInterval: time.Hour})
	t.Cleanup(tc.Close)
	require.Equal(t, codes.OK, tc.GetLatest(context.Background()).Status)

	done := make(chan *internalclient.Response, 1)
	go func() { done <- tc.AddLeaf(context.Background(), []byte("leaf-0")) }()
	<-queued
	require.NoError(t, tc.poll())
	resp := <-done
	require.Equal(t, codes.OK, resp.Status)
	require.NotNil(t, resp.GetLeafAndProofResult)
}
