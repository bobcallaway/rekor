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
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/trillian"
	internalclient "github.com/sigstore/rekor/internal/trillianclient"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The only growth happens during QueueLeaf: subsequent proof misses must be
// recoverable without another root advance or a per-write root RPC.
func newQuietLogWriter(t *testing.T, opts cacheOptions) (*cachedTrillianClient, *controlledLogClient, *logTree) {
	t.Helper()
	tree := newLogTree(t, 1)
	backend := &controlledLogClient{}
	backend.latest = func(context.Context, *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
		return tree.response(0, 0), nil
	}
	tc := newManuallyPolledClient(backend, opts)
	require.NoError(t, tc.poll())
	backend.latest = func(context.Context, *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
		panic("proof retry must not fetch a root")
	}
	backend.queue = func(context.Context, *trillian.QueueLeafRequest) (*trillian.QueueLeafResponse, error) {
		_, err := tc.publish(rootSnapshot{root: mustRoot(t, tree, 1), signed: tree.response(0, 1).SignedLogRoot})
		if err != nil {
			return nil, err
		}
		return &trillian.QueueLeafResponse{QueuedLeaf: &trillian.QueuedLogLeaf{Leaf: testIntegratedLeaf(tree, 0)}}, nil
	}
	backend.leaves = func(context.Context, *trillian.GetLeavesByRangeRequest) (*trillian.GetLeavesByRangeResponse, error) {
		return &trillian.GetLeavesByRangeResponse{Leaves: []*trillian.LogLeaf{testIntegratedLeaf(tree, 0)}}, nil
	}
	return tc, backend, tree
}

func TestCachedAddRetriesProofMissWithoutGrowth(t *testing.T) {
	for _, empty := range []bool{false, true} {
		name := "NotFound"
		if empty {
			name = "empty proof"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				tc, backend, tree := newQuietLogWriter(t, cacheOptions{proofConcurrency: 1, maxProofWaiters: 1})
				defer tc.Close()
				var calls atomic.Int32
				backend.inclusion = func(_ context.Context, req *trillian.GetInclusionProofByHashRequest) (*trillian.GetInclusionProofByHashResponse, error) {
					if req.TreeSize != 1 {
						return nil, status.Error(codes.Internal, "unexpected tree size")
					}
					if calls.Add(1) <= 2 {
						if empty {
							return &trillian.GetInclusionProofByHashResponse{}, nil
						}
						return nil, status.Error(codes.NotFound, "transient miss")
					}
					return &trillian.GetInclusionProofByHashResponse{Proof: []*trillian.Proof{{LeafIndex: 0, Hashes: tree.inclusion(0, 1)}}}, nil
				}
				done := make(chan *internalclient.Response, 1)
				go func() { done <- tc.AddLeaf(context.Background(), []byte("leaf-0")) }()
				synctest.Wait()
				require.EqualValues(t, 1, calls.Load())
				require.Empty(t, tc.proofs) // Waiting for the retry does not hold proof capacity.
				require.Len(t, tc.pending, 1)
				retryAfter := tc.opts.addLeafRetryAfter()
				require.Equal(t, time.Second, retryAfter)
				time.Sleep(retryAfter - time.Millisecond)
				synctest.Wait()
				require.EqualValues(t, 1, calls.Load())
				time.Sleep(time.Millisecond)
				synctest.Wait()
				require.EqualValues(t, 2, calls.Load())

				// A retry must acquire capacity again, even though this write was
				// admitted before the competing proof operation started.
				require.NoError(t, tc.acquireProof(context.Background()))
				time.Sleep(retryAfter)
				synctest.Wait()
				require.EqualValues(t, 2, calls.Load())
				require.Len(t, tc.proofWaiters, 1)
				tc.releaseProof()
				resp := <-done
				requireVerifiedRead(t, resp, tree, 0, 1)
				require.NotNil(t, resp.GetAddResult)
				require.EqualValues(t, 3, calls.Load())
				require.Empty(t, tc.pending)
				require.Empty(t, tc.proofs)
				require.Empty(t, tc.proofWaiters)
				require.Zero(t, tc.waiters.waiterCount())
			})
		})
	}
}

func TestCachedAddProofRetryStops(t *testing.T) {
	for _, reason := range []string{"cancel", "deadline", "close", "stale", "backend error", "overload"} {
		t.Run(reason, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				opts := cacheOptions{proofConcurrency: 1, maxProofWaiters: 1}
				if reason == "stale" {
					opts.maxRootAge = 250 * time.Millisecond
				}
				tc, backend, _ := newQuietLogWriter(t, opts)
				defer tc.Close()
				var calls atomic.Int32
				backend.inclusion = func(context.Context, *trillian.GetInclusionProofByHashRequest) (*trillian.GetInclusionProofByHashResponse, error) {
					if calls.Add(1) > 1 && reason == "backend error" {
						return nil, status.Error(codes.Unavailable, "backend down")
					}
					return nil, status.Error(codes.NotFound, "transient miss")
				}
				deadline := time.Hour
				if reason == "deadline" {
					deadline = 250 * time.Millisecond
				}
				ctx, cancel := context.WithTimeout(context.Background(), deadline)
				defer cancel()
				done := make(chan *internalclient.Response, 1)
				go func() { done <- tc.AddLeaf(ctx, []byte("leaf-0")) }()
				synctest.Wait()
				require.EqualValues(t, 1, calls.Load())
				want := codes.Unavailable
				wantCalls := int32(1)
				switch reason {
				case "cancel":
					cancel()
					want = codes.Canceled
				case "deadline":
					time.Sleep(deadline)
					want = codes.DeadlineExceeded
				case "close":
					tc.Close()
				case "stale":
					time.Sleep(opts.maxRootAge)
				case "backend error":
					time.Sleep(tc.opts.addLeafRetryAfter())
					wantCalls = 2
				case "overload":
					require.NoError(t, tc.acquireProof(context.Background()))
					defer tc.releaseProof()
					waiting := make(chan error, 1)
					waitCtx, stopWaiting := context.WithCancel(context.Background())
					defer stopWaiting()
					go func() { waiting <- tc.acquireProof(waitCtx) }()
					synctest.Wait()
					time.Sleep(tc.opts.addLeafRetryAfter())
					synctest.Wait()
					stopWaiting()
					require.Equal(t, codes.Canceled, status.Code(<-waiting))
					want = codes.ResourceExhausted
				}
				resp := <-done
				require.Equal(t, want, resp.Status)
				require.Equal(t, want, status.Code(resp.Err))
				require.NotNil(t, resp.GetAddResult)
				require.Equal(t, wantCalls, calls.Load())
				require.Empty(t, tc.pending)
				require.Zero(t, tc.waiters.waiterCount())
			})
		})
	}
}
