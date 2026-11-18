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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	internalclient "github.com/sigstore/rekor/internal/trillianclient"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCachedLookupMissExpiresDuringStalledPolls(t *testing.T) {
	for _, byHash := range []bool{false, true} {
		name := "index"
		if byHash {
			name = "hash"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				tree := newLogTree(t, 1)
				var polls atomic.Int32
				backend := &controlledLogClient{}
				backend.latest = func(ctx context.Context, _ *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
					if polls.Add(1) == 1 {
						return tree.response(0, 1), nil
					}
					<-ctx.Done()
					return nil, ctx.Err()
				}
				backend.inclusion = func(context.Context, *trillian.GetInclusionProofByHashRequest) (*trillian.GetInclusionProofByHashResponse, error) {
					return nil, status.Error(codes.NotFound, "not integrated")
				}
				tc := newCachedTrillianClient(backend, 47, cacheOptions{
					pollInterval: DefaultPollInterval,
					rootTimeout:  5 * time.Second,
					maxRootAge:   2 * time.Second,
				})
				defer tc.Close()
				synctest.Wait()
				time.Sleep(150 * time.Millisecond)
				require.EqualValues(t, 2, polls.Load()) // The second poll is already stalled.
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan *internalclient.Response, 1)
				go func() {
					if byHash {
						done <- tc.GetLeafAndProofByHash(ctx, []byte("absent"))
					} else {
						done <- tc.GetLeafAndProofByIndex(ctx, 1)
					}
				}()
				synctest.Wait()
				time.Sleep(tc.opts.maxRootAge - 150*time.Millisecond + time.Millisecond)
				synctest.Wait()
				require.Equal(t, codes.Unavailable, tc.GetLatest(context.Background()).Status)
				select {
				case result := <-done:
					require.Equal(t, codes.Unavailable, result.Status)
					require.ErrorContains(t, result.Err, "stale")
				default:
					t.Fatal("lookup remained blocked after cached root expiry")
				}
			})
		})
	}
}

func TestCachedPollWaitHonorsFreshnessExtension(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tree := newLogTree(t, 1)
		refresh := make(chan struct{})
		calls := 0
		backend := &controlledLogClient{}
		backend.latest = func(context.Context, *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			calls++
			if calls == 2 {
				<-refresh
			}
			return tree.response(0, 1), nil
		}
		tc := newManuallyPolledClient(backend, cacheOptions{maxRootAge: time.Second})
		defer tc.Close()
		require.NoError(t, tc.poll())
		polled := make(chan error, 1)
		go func() { polled <- tc.poll() }()
		synctest.Wait()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- tc.waitForPoll(ctx) }()
		synctest.Wait()
		time.Sleep(750 * time.Millisecond)
		close(refresh)
		require.NoError(t, <-polled) // Same size, but fresh; waiter still wants the next poll.
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("waiter ignored a successful freshness extension")
		default:
		}
		time.Sleep(501 * time.Millisecond)
		synctest.Wait()
		select {
		case err := <-done:
			require.Equal(t, codes.Unavailable, status.Code(err))
		default:
			t.Fatal("waiter did not expire after the extended freshness window")
		}
	})
}

func TestCachedPollWaitCancellation(t *testing.T) {
	for _, reason := range []string{"cancel", "deadline", "close"} {
		t.Run(reason, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				tc := newManuallyPolledClient(nil, cacheOptions{maxRootAge: time.Hour})
				defer tc.Close()
				tc.lastSuccess.Store(cacheClockNow())
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- tc.waitForPoll(ctx) }()
				synctest.Wait()
				want := codes.Canceled
				switch reason {
				case "cancel":
					cancel()
				case "deadline":
					time.Sleep(time.Second)
					want = codes.DeadlineExceeded
				case "close":
					tc.Close()
					want = codes.Unavailable
				}
				require.Equal(t, want, status.Code(<-done))
			})
		})
	}
}

func TestCachedProofQueueBoundsReadsAndDecouplesWrites(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tree := newLogTree(t, 2)
		size := uint64(1)
		backend := &controlledLogClient{}
		backend.latest = func(_ context.Context, req *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			return tree.response(uint64(req.FirstTreeSize), size), nil //nolint:gosec // Small test tree.
		}
		tc := newManuallyPolledClient(backend, cacheOptions{proofConcurrency: 1, maxProofWaiters: 1})
		defer tc.Close()
		require.NoError(t, tc.poll())
		backend.queue = func(context.Context, *trillian.QueueLeafRequest) (*trillian.QueueLeafResponse, error) {
			size = 2
			require.NoError(t, tc.poll())
			return &trillian.QueueLeafResponse{QueuedLeaf: &trillian.QueuedLogLeaf{Leaf: testIntegratedLeaf(tree, 1)}}, nil
		}
		backend.inclusion = func(_ context.Context, req *trillian.GetInclusionProofByHashRequest) (*trillian.GetInclusionProofByHashResponse, error) {
			return &trillian.GetInclusionProofByHashResponse{Proof: []*trillian.Proof{{LeafIndex: 1, Hashes: tree.inclusion(1, uint64(req.TreeSize))}}}, nil //nolint:gosec
		}
		backend.leaves = func(context.Context, *trillian.GetLeavesByRangeRequest) (*trillian.GetLeavesByRangeResponse, error) {
			return &trillian.GetLeavesByRangeResponse{Leaves: []*trillian.LogLeaf{testIntegratedLeaf(tree, 1)}}, nil
		}
		rejectedBefore := testutil.ToFloat64(tc.metrics.proofsRejected)
		histogram := tc.metrics.proofWaitDuration.(prometheus.Histogram)
		before := &dto.Metric{}
		require.NoError(t, histogram.Write(before))
		require.NoError(t, tc.acquireProof(context.Background()))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- tc.acquireProof(ctx) }()
		synctest.Wait()
		require.Len(t, tc.proofWaiters, 1)
		require.EqualValues(t, 1, testutil.ToFloat64(tc.metrics.proofWaiters))
		for _, result := range []*internalclient.Response{
			tc.GetLeafAndProofByIndex(context.Background(), 0),
			tc.GetLeafAndProofByHash(context.Background(), tree.leafHash(0)),
		} {
			require.Equal(t, codes.ResourceExhausted, result.Status)
			require.ErrorIs(t, result.Err, internalclient.ErrProofQueueFull)
		}
		require.Equal(t, rejectedBefore+2, testutil.ToFloat64(tc.metrics.proofsRejected))

		// An already-submitted write bypasses the read waiter cap and waits for
		// proof concurrency rather than failing post-commit with ErrProofQueueFull.
		writeDone := make(chan *internalclient.Response, 1)
		go func() { writeDone <- tc.AddLeaf(context.Background(), []byte("leaf-1")) }()
		synctest.Wait()
		require.Len(t, tc.pending, 1)
		require.Len(t, tc.proofWaiters, 1) // Read waiter channel is unaffected.
		require.EqualValues(t, 2, testutil.ToFloat64(tc.metrics.proofWaiters))
		require.Equal(t, rejectedBefore+2, testutil.ToFloat64(tc.metrics.proofsRejected))

		time.Sleep(100 * time.Millisecond)
		cancel()
		require.Equal(t, codes.Canceled, status.Code(<-done))
		require.Empty(t, tc.proofWaiters)
		require.EqualValues(t, 1, testutil.ToFloat64(tc.metrics.proofWaiters))
		after := &dto.Metric{}
		require.NoError(t, histogram.Write(after))
		require.Equal(t, before.GetHistogram().GetSampleCount()+1, after.GetHistogram().GetSampleCount())
		require.InDelta(t, .1, after.GetHistogram().GetSampleSum()-before.GetHistogram().GetSampleSum(), .000001)

		// Releasing proof capacity lets the queued write complete with a verified proof.
		tc.releaseProof()
		write := <-writeDone
		requireVerifiedRead(t, write, tree, 1, 2)
		require.NotNil(t, write.GetAddResult)
		require.Empty(t, tc.pending)
		require.Zero(t, testutil.ToFloat64(tc.metrics.proofs))
		require.Zero(t, testutil.ToFloat64(tc.metrics.proofWaiters))

		// Canceled read waiters return queue capacity; releasing a running
		// operation then admits the replacement without exceeding the active limit.
		require.NoError(t, tc.acquireProof(context.Background()))
		go func() { done <- tc.acquireProof(context.Background()) }()
		synctest.Wait()
		require.Len(t, tc.proofWaiters, 1)
		tc.releaseProof()
		require.NoError(t, <-done)
		require.Len(t, tc.proofs, 1)
		require.Empty(t, tc.proofWaiters)
		tc.releaseProof()
		require.Zero(t, testutil.ToFloat64(tc.metrics.proofs))
		require.Zero(t, testutil.ToFloat64(tc.metrics.proofWaiters))
	})
}

func TestCachedWriteBurstDrainsWithoutPostCommitOverload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			burst            = 12
			proofConcurrency = 2
			maxProofWaiters  = 1
		)
		tree := newLogTree(t, burst)
		size := uint64(0)
		var activeProofs, maxActiveProofs atomic.Int32
		byHash := make(map[string]*trillian.LogLeaf, burst)
		for i := range burst {
			leaf := testIntegratedLeaf(tree, uint64(i))
			byHash[string(leaf.MerkleLeafHash)] = leaf
		}

		backend := &controlledLogClient{}
		backend.latest = func(_ context.Context, req *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			return tree.response(uint64(req.FirstTreeSize), size), nil //nolint:gosec
		}
		backend.queue = func(_ context.Context, req *trillian.QueueLeafRequest) (*trillian.QueueLeafResponse, error) {
			for _, leaf := range byHash {
				if string(leaf.LeafValue) == string(req.Leaf.LeafValue) {
					return &trillian.QueueLeafResponse{QueuedLeaf: &trillian.QueuedLogLeaf{Leaf: leaf}}, nil
				}
			}
			return nil, status.Error(codes.Internal, "unexpected leaf")
		}
		backend.inclusion = func(_ context.Context, req *trillian.GetInclusionProofByHashRequest) (*trillian.GetInclusionProofByHashResponse, error) {
			cur := activeProofs.Add(1)
			defer activeProofs.Add(-1)
			for {
				prev := maxActiveProofs.Load()
				if cur <= prev || maxActiveProofs.CompareAndSwap(prev, cur) {
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
			leaf := byHash[string(req.LeafHash)]
			return &trillian.GetInclusionProofByHashResponse{
				Proof: []*trillian.Proof{{LeafIndex: leaf.LeafIndex, Hashes: tree.inclusion(uint64(leaf.LeafIndex), uint64(req.TreeSize))}}, //nolint:gosec
			}, nil
		}
		backend.leaves = func(_ context.Context, req *trillian.GetLeavesByRangeRequest) (*trillian.GetLeavesByRangeResponse, error) {
			return &trillian.GetLeavesByRangeResponse{Leaves: []*trillian.LogLeaf{testIntegratedLeaf(tree, uint64(req.StartIndex))}}, nil //nolint:gosec
		}

		tc := newManuallyPolledClient(backend, cacheOptions{
			maxPending:       burst,
			proofConcurrency: proofConcurrency,
			maxProofWaiters:  maxProofWaiters,
		})
		defer tc.Close()
		require.NoError(t, tc.poll())
		rejectedBefore := testutil.ToFloat64(tc.metrics.proofsRejected)

		results := make(chan *internalclient.Response, burst)
		for i := range burst {
			leaf := testIntegratedLeaf(tree, uint64(i))
			go func() { results <- tc.AddLeaf(context.Background(), leaf.LeafValue) }()
		}
		synctest.Wait()
		require.Len(t, tc.pending, burst)
		require.Equal(t, burst, tc.waiters.waiterCount())

		// One root advance wakes all 12 writers simultaneously, far exceeding
		// proofConcurrency + maxProofWaiters (3). Every write must succeed
		// while backend proof concurrency stays bounded at 2.
		size = burst
		require.NoError(t, tc.poll())
		for range burst {
			resp := <-results
			require.Equal(t, codes.OK, resp.Status)
			require.NoError(t, resp.Err)
			require.NotNil(t, resp.GetAddResult)
			require.NotNil(t, resp.GetLeafAndProofResult)
		}
		require.EqualValues(t, proofConcurrency, maxActiveProofs.Load())
		require.Equal(t, rejectedBefore, testutil.ToFloat64(tc.metrics.proofsRejected))
		require.Empty(t, tc.pending)
		require.Empty(t, tc.proofs)
		require.Empty(t, tc.proofWaiters)
		require.Zero(t, testutil.ToFloat64(tc.metrics.proofWaiters))
	})
}

func TestCachedWriteProofWaitStops(t *testing.T) {
	for _, reason := range []string{"cancel", "deadline", "close", "stale"} {
		t.Run(reason, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				tc := newManuallyPolledClient(nil, cacheOptions{
					proofConcurrency: 1,
					maxProofWaiters:  1,
					maxRootAge:       time.Second,
				})
				defer tc.Close()
				tc.lastSuccess.Store(cacheClockNow())
				require.NoError(t, tc.acquireProof(context.Background()))
				defer tc.releaseProof()

				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- tc.acquireWriteProof(ctx) }()
				synctest.Wait()
				require.Empty(t, tc.proofWaiters)
				require.EqualValues(t, 1, testutil.ToFloat64(tc.metrics.proofWaiters))

				want := codes.Unavailable
				switch reason {
				case "cancel":
					cancel()
					want = codes.Canceled
				case "deadline":
					// Keep the root fresh past the caller deadline so deadline wins.
					time.Sleep(750 * time.Millisecond)
					tc.lastSuccess.Store(cacheClockNow())
					time.Sleep(750 * time.Millisecond)
					tc.lastSuccess.Store(cacheClockNow())
					time.Sleep(500 * time.Millisecond)
					want = codes.DeadlineExceeded
				case "close":
					tc.Close()
				case "stale":
					// Freshness extension delays expiry; staleness expires once it stops.
					time.Sleep(750 * time.Millisecond)
					tc.lastSuccess.Store(cacheClockNow())
					time.Sleep(500 * time.Millisecond)
					synctest.Wait()
					select {
					case err := <-done:
						t.Fatalf("expired despite freshness extension: %v", err)
					default:
					}
					time.Sleep(501 * time.Millisecond)
				}
				err := <-done
				require.Equal(t, want, status.Code(err))
				if reason == "stale" {
					require.ErrorContains(t, err, "stale")
				}
				require.Zero(t, testutil.ToFloat64(tc.metrics.proofWaiters))
			})
		})
	}
}

func TestCachedProofQueueDeadlineAndShutdown(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		name := "deadline"
		if shutdown {
			name = "close"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				tc := newManuallyPolledClient(nil, cacheOptions{proofConcurrency: 1, maxProofWaiters: 1})
				defer tc.Close()
				require.NoError(t, tc.acquireProof(context.Background()))
				defer tc.releaseProof()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- tc.acquireProof(ctx) }()
				synctest.Wait()
				require.Len(t, tc.proofWaiters, 1)
				want := codes.DeadlineExceeded
				if shutdown {
					tc.Close()
					want = codes.Unavailable
				} else {
					time.Sleep(time.Second)
				}
				require.Equal(t, want, status.Code(<-done))
				require.Empty(t, tc.proofWaiters)
				require.Zero(t, testutil.ToFloat64(tc.metrics.proofWaiters))
			})
		})
	}
}
