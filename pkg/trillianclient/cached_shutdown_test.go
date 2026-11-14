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
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/trillian"
	internalclient "github.com/sigstore/rekor/internal/trillianclient"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCachedClientRejectsWorkAfterClose(t *testing.T) {
	tree := newLogTree(t, 1)
	// No RPCs are configured: closed clients must reject locally, even with a
	// cached root and free admission slots.
	tc := newManuallyPolledClient(nil, cacheOptions{})
	_, err := tc.publish(rootSnapshot{root: mustRoot(t, tree, 1)})
	require.NoError(t, err)
	tc.Close()

	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		want := codes.Unavailable
		if canceled {
			cancel()
			want = codes.Canceled
		}
		for _, resp := range []*internalclient.Response{
			tc.GetLatest(ctx),
			tc.AddLeaf(ctx, []byte("leaf-0")),
			tc.GetLeafAndProofByHash(ctx, tree.leafHash(0)),
			tc.GetLeafAndProofByIndex(ctx, 0),
		} {
			require.Equal(t, want, resp.Status)
			require.Equal(t, want, status.Code(resp.Err))
		}
		require.Equal(t, want, status.Code(tc.acquirePending(ctx)))
		require.Equal(t, want, status.Code(tc.acquireProof(ctx)))
		require.Equal(t, want, status.Code(tc.waitForPoll(ctx)))
		require.Equal(t, want, status.Code(tc.waitForSize(ctx, 1)))
		cancel()
	}
	require.Empty(t, tc.pending)
	require.Empty(t, tc.proofs)
}

func TestCachedShutdownNormalizesInFlightPoll(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		backend := &controlledLogClient{}
		backend.latest = func(ctx context.Context, _ *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			<-ctx.Done()
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		tc := newManuallyPolledClient(backend, cacheOptions{rootTimeout: time.Hour})
		defer tc.Close()
		result := tc.nextPoll
		done := make(chan error, 1)
		go func() { done <- tc.poll() }()
		synctest.Wait()
		tc.Close()
		require.ErrorIs(t, <-done, errClientClosed)
		<-result.done
		// Both the poll result and stopped channel can wake callers; either
		// path must report Unavailable rather than the poll's Canceled error.
		require.ErrorIs(t, result.err, errClientClosed)
		require.Equal(t, codes.Unavailable, tc.GetLatest(context.Background()).Status)
	})
}

func TestCachedAddShutdownPreservesCallerCancellation(t *testing.T) {
	for _, reason := range []string{"close", "cancel", "deadline"} {
		t.Run(reason, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				tree := newLogTree(t, 1)
				backend := &controlledLogClient{}
				backend.latest = func(context.Context, *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
					return tree.response(0, 0), nil
				}
				backend.queue = func(context.Context, *trillian.QueueLeafRequest) (*trillian.QueueLeafResponse, error) {
					return &trillian.QueueLeafResponse{QueuedLeaf: &trillian.QueuedLogLeaf{Leaf: testIntegratedLeaf(tree, 0)}}, nil
				}
				tc := newManuallyPolledClient(backend, cacheOptions{maxRootAge: time.Hour})
				defer tc.Close()
				require.NoError(t, tc.poll())
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				done := make(chan *internalclient.Response, 1)
				go func() { done <- tc.AddLeaf(ctx, []byte("leaf-0")) }()
				synctest.Wait()
				tc.mu.Lock()
				require.Equal(t, 1, tc.waiters.waiterCount())
				tc.mu.Unlock()
				want := codes.Unavailable
				switch reason {
				case "close":
					tc.Close()
					require.NoError(t, ctx.Err())
				case "cancel":
					cancel()
					want = codes.Canceled
				case "deadline":
					time.Sleep(time.Second)
					want = codes.DeadlineExceeded
				}
				resp := <-done
				require.Equal(t, want, resp.Status)
				require.Equal(t, want, status.Code(resp.Err))
				require.NotNil(t, resp.GetAddResult)
				require.Empty(t, tc.pending)
				require.Zero(t, tc.waiters.waiterCount())
			})
		})
	}
}
