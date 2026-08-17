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
		opts:    cacheOptions{frozen: true}.withDefaults(),
		changed: make(chan struct{}),
		polled:  make(chan struct{}),
		stop:    cancel,
		stopped: ctx,
	}

	_, err := tc.publish(rootSnapshot{root: types.LogRootV1{TreeSize: 1, RootHash: []byte("first")}})
	require.NoError(t, err)
	_, err = tc.publish(rootSnapshot{root: types.LogRootV1{TreeSize: 1, RootHash: []byte("second")}})
	require.Error(t, err)
	require.Equal(t, codes.DataLoss, status.Code(err))
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

func TestCachedHashMissesShareTheNextRootPoll(t *testing.T) {
	const callers = 16
	tree := newLogTree(t, 1)
	s, logClient := newMockLog(t)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(tree.response(0, 1), nil).Times(1)
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(tree.response(1, 1), nil).Times(1)

	allMissed := make(chan struct{})
	var misses atomic.Int32
	s.Log.EXPECT().GetInclusionProofByHash(gomock.Any(), gomock.Any()).DoAndReturn(
		func(context.Context, *trillian.GetInclusionProofByHashRequest) (*trillian.GetInclusionProofByHashResponse, error) {
			if misses.Add(1) == callers {
				close(allMissed)
			}
			return nil, status.Error(codes.NotFound, "not found")
		},
	).Times(callers)

	tc := newCachedTrillianClient(logClient, 42, cacheOptions{pollInterval: time.Hour})
	t.Cleanup(tc.Close)
	require.Equal(t, codes.OK, tc.GetLatest(context.Background()).Status)

	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			resp := tc.GetLeafAndProofByHash(context.Background(), []byte("missing"))
			require.Equal(t, codes.NotFound, resp.Status)
		}()
	}
	<-allMissed
	require.NoError(t, tc.poll())
	wg.Wait()
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
