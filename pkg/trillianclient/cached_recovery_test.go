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
	"fmt"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	internalclient "github.com/sigstore/rekor/internal/trillianclient"
	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// controlledLogClient keeps RPCs inside the synctest bubble, so Wait can
// distinguish blocked callers from work still running without network timing.
// Unconfigured RPCs panic rather than silently succeeding.
type controlledLogClient struct {
	trillian.TrillianLogClient
	latest    func(context.Context, *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error)
	inclusion func(context.Context, *trillian.GetInclusionProofByHashRequest) (*trillian.GetInclusionProofByHashResponse, error)
	entry     func(context.Context, *trillian.GetEntryAndProofRequest) (*trillian.GetEntryAndProofResponse, error)
	queue     func(context.Context, *trillian.QueueLeafRequest) (*trillian.QueueLeafResponse, error)
	leaves    func(context.Context, *trillian.GetLeavesByRangeRequest) (*trillian.GetLeavesByRangeResponse, error)
}

func (c *controlledLogClient) GetLatestSignedLogRoot(ctx context.Context, req *trillian.GetLatestSignedLogRootRequest, _ ...grpc.CallOption) (*trillian.GetLatestSignedLogRootResponse, error) {
	return c.latest(ctx, req)
}

func (c *controlledLogClient) GetInclusionProofByHash(ctx context.Context, req *trillian.GetInclusionProofByHashRequest, _ ...grpc.CallOption) (*trillian.GetInclusionProofByHashResponse, error) {
	return c.inclusion(ctx, req)
}

func (c *controlledLogClient) GetEntryAndProof(ctx context.Context, req *trillian.GetEntryAndProofRequest, _ ...grpc.CallOption) (*trillian.GetEntryAndProofResponse, error) {
	return c.entry(ctx, req)
}

func (c *controlledLogClient) QueueLeaf(ctx context.Context, req *trillian.QueueLeafRequest, _ ...grpc.CallOption) (*trillian.QueueLeafResponse, error) {
	return c.queue(ctx, req)
}

func (c *controlledLogClient) GetLeavesByRange(ctx context.Context, req *trillian.GetLeavesByRangeRequest, _ ...grpc.CallOption) (*trillian.GetLeavesByRangeResponse, error) {
	return c.leaves(ctx, req)
}

// newManuallyPolledClient exercises the real poll/fetch/publish path without
// starting the updater. Each test chooses exactly when an RPC starts.
func newManuallyPolledClient(c trillian.TrillianLogClient, opts cacheOptions) *cachedTrillianClient {
	ctx, cancel := context.WithCancel(context.Background())
	opts = opts.withDefaults()
	return &cachedTrillianClient{
		directTrillianClient: newDirectTrillianClient(c, 47),
		verifier:             client.NewLogVerifier(rfc6962.DefaultHasher),
		opts:                 opts,
		metrics:              newCachedClientMetrics(47),
		nextPoll:             &pollResult{done: make(chan struct{})},
		pending:              make(chan struct{}, opts.maxPending),
		proofs:               make(chan struct{}, opts.proofConcurrency),
		stop:                 cancel,
		stopped:              ctx,
	}
}

func testIntegratedLeaf(tree *logTree, index uint64) *trillian.LogLeaf {
	return &trillian.LogLeaf{
		LeafIndex:      int64(index), //nolint:gosec // Test trees have at most six leaves.
		MerkleLeafHash: tree.leafHash(index),
		LeafValue:      fmt.Appendf(nil, "leaf-%d", index),
	}
}

func requireVerifiedRead(t *testing.T, response *internalclient.Response, tree *logTree, index, size uint64) {
	t.Helper()
	require.NoError(t, response.Err)
	require.Equal(t, codes.OK, response.Status)
	result := response.GetLeafAndProofResult
	require.NotNil(t, result)
	require.NotNil(t, result.Leaf)
	require.NotNil(t, result.Proof)
	require.EqualValues(t, index, result.Leaf.LeafIndex)
	require.Equal(t, result.Leaf.LeafIndex, result.Proof.LeafIndex)
	require.Equal(t, rfc6962.DefaultHasher.HashLeaf(result.Leaf.LeafValue), result.Leaf.MerkleLeafHash)
	root, err := internalclient.UnmarshalLogRoot(result.SignedLogRoot.LogRoot)
	require.NoError(t, err)
	require.Equal(t, size, root.TreeSize)
	require.Equal(t, tree.root(size), root.RootHash)
	verifier := client.NewLogVerifier(rfc6962.DefaultHasher)
	require.NoError(t, verifier.VerifyInclusionByHash(&root, result.Leaf.MerkleLeafHash, result.Proof))
}

func TestCachedClientStaleRootRejectionAndRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tree := newLogTree(t, 1)
		calls := 0
		backend := &controlledLogClient{}
		backend.latest = func(_ context.Context, req *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			calls++
			if calls == 1 {
				require.Zero(t, req.FirstTreeSize)
				return tree.response(0, 1), nil
			}
			require.EqualValues(t, 1, req.FirstTreeSize)
			if calls == 2 {
				return nil, status.Error(codes.Unavailable, "backend down")
			}
			return tree.response(1, 1), nil
		}
		backend.entry = func(_ context.Context, req *trillian.GetEntryAndProofRequest) (*trillian.GetEntryAndProofResponse, error) {
			require.EqualValues(t, 1, req.TreeSize)
			return &trillian.GetEntryAndProofResponse{Leaf: testIntegratedLeaf(tree, 0), Proof: &trillian.Proof{LeafIndex: 0, Hashes: tree.inclusion(0, 1)}}, nil
		}
		tc := newManuallyPolledClient(backend, cacheOptions{maxRootAge: time.Second})
		defer tc.Close()
		require.NoError(t, tc.poll())
		require.Equal(t, codes.OK, tc.GetLatest(context.Background()).Status)
		before := tc.snapshot.Load()
		lastSuccess := tc.lastSuccess.Load()

		time.Sleep(2 * time.Second) // Virtual time: no wall-clock sleep.
		stale := tc.GetLatest(context.Background())
		require.Equal(t, codes.Unavailable, stale.Status)
		require.Contains(t, stale.Err.Error(), "stale")
		require.Nil(t, stale.GetLatestResult)
		// Neither read path may issue a proof RPC while the root is stale.
		require.Equal(t, codes.Unavailable, tc.GetLeafAndProofByIndex(context.Background(), 0).Status)
		require.Equal(t, codes.Unavailable, tc.GetLeafAndProofByHash(context.Background(), tree.leafHash(0)).Status)
		require.Error(t, tc.poll())
		require.Same(t, before, tc.snapshot.Load())
		require.Equal(t, lastSuccess, tc.lastSuccess.Load())
		require.Equal(t, codes.Unavailable, tc.GetLatest(context.Background()).Status)

		// An unchanged, successfully observed root must also restore freshness.
		require.NoError(t, tc.poll())
		require.Same(t, before, tc.snapshot.Load())
		require.Greater(t, tc.lastSuccess.Load(), lastSuccess)
		require.Equal(t, codes.OK, tc.GetLatest(context.Background()).Status)
		requireVerifiedRead(t, tc.GetLeafAndProofByIndex(context.Background(), 0), tree, 0, 1)
		require.Equal(t, 3, calls)
	})
}

func TestCachedClientPollRejectsInvalidConsistencyProof(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tree := newLogTree(t, 4)
		invalid := tree.response(2, 4)
		invalid.Proof.Hashes = [][]byte{make([]byte, 32)}
		calls := 0
		backend := &controlledLogClient{}
		backend.latest = func(_ context.Context, req *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			calls++
			if calls == 1 {
				return tree.response(0, 2), nil
			}
			// A rejected update must not become the trust anchor of the next RPC.
			require.EqualValues(t, 2, req.FirstTreeSize)
			if calls == 2 {
				return invalid, nil
			}
			return tree.response(2, 4), nil
		}
		tc := newManuallyPolledClient(backend, cacheOptions{maxRootAge: time.Hour})
		defer tc.Close()
		require.NoError(t, tc.poll())
		before := tc.snapshot.Load()
		lastSuccess := tc.lastSuccess.Load()
		waiting := make(chan error, 1)
		go func() { waiting <- tc.waitForSize(context.Background(), 4) }()
		synctest.Wait()
		require.Equal(t, 1, tc.waiters.waiterCount())
		time.Sleep(time.Second)

		err := tc.poll()
		require.ErrorContains(t, err, "verify root update")
		require.Same(t, before, tc.snapshot.Load())
		require.Equal(t, lastSuccess, tc.lastSuccess.Load())
		require.EqualValues(t, 2, snapshotSize(t, tc.GetLatest(context.Background()).GetLatestResult))
		synctest.Wait()
		select {
		case <-waiting:
			t.Fatal("invalid root woke the size waiter")
		default:
		}

		require.NoError(t, tc.poll())
		require.NoError(t, <-waiting)
		require.EqualValues(t, 4, snapshotSize(t, tc.GetLatest(context.Background()).GetLatestResult))
		require.Greater(t, tc.lastSuccess.Load(), lastSuccess)
		require.Zero(t, tc.waiters.waiterCount())
		require.Equal(t, 3, calls)
	})
}

func TestCachedClientConcurrentLookupMissesSharePoll(t *testing.T) {
	for _, byHash := range []bool{true, false} {
		name := "index"
		if byHash {
			name = "hash"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const callers = 16
				tree := newLogTree(t, 2)
				pollStarted := make(chan struct{})
				releasePoll := make(chan struct{})
				var polls, misses, reads atomic.Int32
				backend := &controlledLogClient{}
				backend.latest = func(ctx context.Context, req *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
					if polls.Add(1) == 1 {
						return tree.response(0, 1), nil
					}
					if req.FirstTreeSize != 1 {
						return nil, status.Errorf(codes.Internal, "unexpected trust anchor %d", req.FirstTreeSize)
					}
					close(pollStarted)
					select {
					case <-releasePoll:
						return tree.response(1, 2), nil
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				backend.inclusion = func(_ context.Context, req *trillian.GetInclusionProofByHashRequest) (*trillian.GetInclusionProofByHashResponse, error) {
					if req.TreeSize == 1 {
						misses.Add(1)
						return nil, status.Error(codes.NotFound, "not in cached tree")
					}
					if req.TreeSize != 2 {
						return nil, status.Errorf(codes.Internal, "unexpected proof size %d", req.TreeSize)
					}
					reads.Add(1)
					return &trillian.GetInclusionProofByHashResponse{Proof: []*trillian.Proof{{LeafIndex: 1, Hashes: tree.inclusion(1, 2)}}}, nil
				}
				backend.leaves = func(context.Context, *trillian.GetLeavesByRangeRequest) (*trillian.GetLeavesByRangeResponse, error) {
					return &trillian.GetLeavesByRangeResponse{Leaves: []*trillian.LogLeaf{testIntegratedLeaf(tree, 1)}}, nil
				}
				backend.entry = func(_ context.Context, req *trillian.GetEntryAndProofRequest) (*trillian.GetEntryAndProofResponse, error) {
					if req.TreeSize != 2 || req.LeafIndex != 1 {
						return nil, status.Error(codes.Internal, "unexpected entry request")
					}
					reads.Add(1)
					return &trillian.GetEntryAndProofResponse{Leaf: testIntegratedLeaf(tree, 1), Proof: &trillian.Proof{LeafIndex: 1, Hashes: tree.inclusion(1, 2)}}, nil
				}
				tc := newManuallyPolledClient(backend, cacheOptions{})
				defer tc.Close()
				require.NoError(t, tc.poll())
				lookup := func(ctx context.Context) *internalclient.Response {
					if byHash {
						return tc.GetLeafAndProofByHash(ctx, tree.leafHash(1))
					}
					return tc.GetLeafAndProofByIndex(ctx, 1)
				}
				results := make(chan *internalclient.Response, callers)
				for range callers {
					go func() { results <- lookup(context.Background()) }()
				}
				canceledCtx, cancel := context.WithCancel(context.Background())
				defer cancel()
				canceled := make(chan *internalclient.Response, 1)
				go func() { canceled <- lookup(canceledCtx) }()
				synctest.Wait()
				require.EqualValues(t, 1, polls.Load(), "misses must not fetch individual roots")
				if byHash {
					require.EqualValues(t, callers+1, misses.Load())
				}
				cancel()
				require.Equal(t, codes.Canceled, (<-canceled).Status)

				polled := make(chan error, 1)
				go func() { polled <- tc.poll() }()
				<-pollStarted
				synctest.Wait()
				select {
				case <-results:
					t.Fatal("lookup completed before the shared poll")
				default:
				}
				require.EqualValues(t, 2, polls.Load())
				close(releasePoll)
				require.NoError(t, <-polled)
				for range callers {
					requireVerifiedRead(t, <-results, tree, 1, 2)
				}
				require.EqualValues(t, 2, polls.Load(), "all misses must share a single refresh")
				require.EqualValues(t, callers, reads.Load())
			})
		})
	}
}

func TestCachedAddsAcrossSeveralRootAdvances(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const writers = 6
		tree := newLogTree(t, writers)
		indices := make(map[string]uint64, writers)
		for i := range uint64(writers) {
			indices[string(tree.leafHash(i))] = i
		}
		var queued, leaves atomic.Int32
		var proofs [writers + 1]atomic.Int32
		var trustedSizes []int64
		backend := &controlledLogClient{}
		backend.latest = func(_ context.Context, req *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
			trustedSizes = append(trustedSizes, req.FirstTreeSize)
			switch len(trustedSizes) {
			case 1:
				return tree.response(0, 0), nil
			case 2:
				return tree.response(0, 2), nil
			case 3:
				return tree.response(2, 4), nil
			case 4:
				return tree.response(4, 6), nil
			default:
				return nil, status.Error(codes.Internal, "unexpected root RPC")
			}
		}
		backend.queue = func(_ context.Context, req *trillian.QueueLeafRequest) (*trillian.QueueLeafResponse, error) {
			queued.Add(1)
			return &trillian.QueueLeafResponse{QueuedLeaf: &trillian.QueuedLogLeaf{Leaf: &trillian.LogLeaf{MerkleLeafHash: rfc6962.DefaultHasher.HashLeaf(req.Leaf.LeafValue)}}}, nil
		}
		backend.inclusion = func(_ context.Context, req *trillian.GetInclusionProofByHashRequest) (*trillian.GetInclusionProofByHashResponse, error) {
			index, ok := indices[string(req.LeafHash)]
			if !ok || req.TreeSize < 1 || req.TreeSize > writers {
				return nil, status.Error(codes.Internal, "unexpected proof request")
			}
			proofs[req.TreeSize].Add(1)
			if index >= uint64(req.TreeSize) {
				return nil, status.Error(codes.NotFound, "not yet integrated")
			}
			return &trillian.GetInclusionProofByHashResponse{Proof: []*trillian.Proof{{LeafIndex: int64(index), Hashes: tree.inclusion(index, uint64(req.TreeSize))}}}, nil //nolint:gosec // Test indices are bounded above.
		}
		backend.leaves = func(_ context.Context, req *trillian.GetLeavesByRangeRequest) (*trillian.GetLeavesByRangeResponse, error) {
			leaves.Add(1)
			return &trillian.GetLeavesByRangeResponse{Leaves: []*trillian.LogLeaf{testIntegratedLeaf(tree, uint64(req.StartIndex))}}, nil //nolint:gosec // Test indices are nonnegative.
		}
		tc := newManuallyPolledClient(backend, cacheOptions{maxPending: writers, proofConcurrency: 2})
		defer tc.Close()
		require.NoError(t, tc.poll())
		results := make([]chan *internalclient.Response, writers)
		for i := range writers {
			results[i] = make(chan *internalclient.Response, 1)
			go func() { results[i] <- tc.AddLeaf(context.Background(), fmt.Appendf(nil, "leaf-%d", i)) }()
		}
		synctest.Wait()
		require.EqualValues(t, writers, queued.Load())
		require.Equal(t, writers, tc.waiters.waiterCount())
		require.Len(t, tc.waiters.heap, 1)

		for _, size := range []uint64{2, 4, 6} {
			require.NoError(t, tc.poll())
			synctest.Wait()
			for i := size - 2; i < size; i++ {
				response := <-results[i]
				requireVerifiedRead(t, response, tree, i, size)
				require.NotNil(t, response.GetAddResult)
				require.Same(t, response.GetLeafAndProofResult.Leaf, response.GetAddResult.QueuedLeaf.Leaf)
			}
			for i := size; i < writers; i++ {
				select {
				case <-results[i]:
					t.Fatalf("writer %d completed at tree size %d", i, size)
				default:
				}
			}
			remaining := writers - int(size)
			require.Equal(t, remaining, tc.waiters.waiterCount())
			require.Len(t, tc.pending, remaining)
			if remaining > 0 {
				require.Len(t, tc.waiters.heap, 1)
				require.Equal(t, size+1, tc.waiters.heap[0].size)
			}
		}
		require.Equal(t, []int64{0, 0, 2, 4}, trustedSizes)
		require.EqualValues(t, 6, proofs[2].Load())
		require.EqualValues(t, 4, proofs[4].Load())
		require.EqualValues(t, 2, proofs[6].Load())
		require.EqualValues(t, writers, leaves.Load())
		require.Empty(t, tc.waiters.heap)
		require.Empty(t, tc.proofs)
	})
}
