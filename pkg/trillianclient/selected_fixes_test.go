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
	"github.com/google/trillian/client"
	"github.com/google/trillian/client/backoff"
	"github.com/google/trillian/types"
	internalclient "github.com/sigstore/rekor/internal/trillianclient"
	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/grpc/codes"
)

func TestVerifiedReadsRejectUnboundLeaf(t *testing.T) {
	tree := newLogTree(t, 2)
	snap := rootSnapshot{root: mustRoot(t, tree, 2), signed: mkSLR(t, 2, tree.root(2))}
	verifier := client.NewLogVerifier(rfc6962.DefaultHasher)
	for _, name := range []string{"value", "index", "hash", "nil"} {
		t.Run(name, func(t *testing.T) {
			leaf := testIntegratedLeaf(tree, 0)
			switch name {
			case "value":
				leaf.LeafValue = []byte("leaf-1")
			case "index":
				leaf.LeafIndex = 1
			case "hash":
				leaf.MerkleLeafHash = tree.leafHash(1)
			case "nil":
				leaf = nil
			}
			proof := &trillian.Proof{LeafIndex: 0, Hashes: tree.inclusion(0, 2)}
			backend := &controlledLogClient{
				entry: func(context.Context, *trillian.GetEntryAndProofRequest) (*trillian.GetEntryAndProofResponse, error) {
					return &trillian.GetEntryAndProofResponse{Leaf: leaf, Proof: proof}, nil
				},
				leaves: func(context.Context, *trillian.GetLeavesByRangeRequest) (*trillian.GetLeavesByRangeResponse, error) {
					return &trillian.GetLeavesByRangeResponse{Leaves: []*trillian.LogLeaf{leaf}}, nil
				},
			}
			got := getEntryAndProof(context.Background(), backend, verifier, 47, 0, snap)
			require.Error(t, got.Err)
			got = getLeafForProof(context.Background(), backend, 47, 0, tree.leafHash(0), proof, snap.signed)
			require.Equal(t, codes.Internal, got.Status)
		})
	}
}

func TestProofResponseMissingOrNilProof(t *testing.T) {
	tree := newLogTree(t, 1)
	snap := rootSnapshot{root: mustRoot(t, tree, 1), signed: mkSLR(t, 1, tree.root(1))}
	for _, tt := range []struct {
		name   string
		proofs []*trillian.Proof
		code   codes.Code
	}{{"empty", nil, codes.NotFound}, {"nil element", []*trillian.Proof{nil}, codes.Internal}} {
		t.Run(tt.name, func(t *testing.T) {
			backend := &controlledLogClient{inclusion: func(context.Context, *trillian.GetInclusionProofByHashRequest) (*trillian.GetInclusionProofByHashResponse, error) {
				return &trillian.GetInclusionProofByHashResponse{Proof: tt.proofs}, nil
			}}
			got := getProofByHash(context.Background(), backend, client.NewLogVerifier(rfc6962.DefaultHasher), 47, tree.leafHash(0), snap)
			require.Equal(t, tt.code, got.Status)
		})
	}
}

func TestAddRejectsWrongQueuedHash(t *testing.T) {
	tree := newLogTree(t, 2)
	for _, cached := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "cached"}[cached], func(t *testing.T) {
			backend := &controlledLogClient{queue: func(context.Context, *trillian.QueueLeafRequest) (*trillian.QueueLeafResponse, error) {
				return &trillian.QueueLeafResponse{QueuedLeaf: &trillian.QueuedLogLeaf{Leaf: testIntegratedLeaf(tree, 1)}}, nil
			}}
			var tc internalclient.Client = newDirectTrillianClient(backend, 47)
			if cached {
				c := newManuallyPolledClient(backend, cacheOptions{})
				t.Cleanup(c.Close)
				_, err := c.publish(rootSnapshot{root: mustRoot(t, tree, 0), signed: mkSLR(t, 0, tree.root(0))})
				require.NoError(t, err)
				tc = c
			}
			got := tc.AddLeaf(context.Background(), []byte("leaf-0"))
			require.Equal(t, codes.Internal, got.Status)
			require.NotNil(t, got.GetAddResult)
		})
	}
}

func TestDirectAddRejectsMissingQueuedLeaf(t *testing.T) {
	for _, resp := range []*trillian.QueueLeafResponse{nil, {}, {QueuedLeaf: &trillian.QueuedLogLeaf{}}} {
		backend := &controlledLogClient{queue: func(context.Context, *trillian.QueueLeafRequest) (*trillian.QueueLeafResponse, error) {
			return resp, nil
		}}
		require.Equal(t, codes.Internal, newDirectTrillianClient(backend, 47).AddLeaf(context.Background(), []byte("leaf-0")).Status)
	}
}

func TestProofAdmissionUsesRootPublishedWhileWaiting(t *testing.T) {
	for _, kind := range []string{"hash", "index"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				tree := newLogTree(t, 2)
				backend := &controlledLogClient{
					inclusion: func(_ context.Context, req *trillian.GetInclusionProofByHashRequest) (*trillian.GetInclusionProofByHashResponse, error) {
						require.EqualValues(t, 2, req.TreeSize)
						return &trillian.GetInclusionProofByHashResponse{Proof: []*trillian.Proof{{LeafIndex: 0, Hashes: tree.inclusion(0, 2)}}}, nil
					},
					leaves: func(context.Context, *trillian.GetLeavesByRangeRequest) (*trillian.GetLeavesByRangeResponse, error) {
						return &trillian.GetLeavesByRangeResponse{Leaves: []*trillian.LogLeaf{testIntegratedLeaf(tree, 0)}}, nil
					},
					entry: func(_ context.Context, req *trillian.GetEntryAndProofRequest) (*trillian.GetEntryAndProofResponse, error) {
						require.EqualValues(t, 2, req.TreeSize)
						return &trillian.GetEntryAndProofResponse{Proof: &trillian.Proof{LeafIndex: 0, Hashes: tree.inclusion(0, 2)}, Leaf: testIntegratedLeaf(tree, 0)}, nil
					},
				}
				tc := newManuallyPolledClient(backend, cacheOptions{proofConcurrency: 1})
				t.Cleanup(tc.Close)
				old := rootSnapshot{root: mustRoot(t, tree, 1), signed: mkSLR(t, 1, tree.root(1))}
				_, err := tc.publish(old)
				require.NoError(t, err)
				require.NoError(t, tc.acquireProof(context.Background()))
				done := make(chan *internalclient.Response, 1)
				var used rootSnapshot
				go func() {
					if kind == "hash" {
						var resp *internalclient.Response
						resp, used = tc.leafAndProofForHash(context.Background(), tree.leafHash(0), old)
						done <- resp
					} else {
						done <- tc.GetLeafAndProofByIndex(context.Background(), 0)
					}
				}()
				synctest.Wait()
				require.Len(t, tc.proofWaiters, 1)
				_, err = tc.publish(rootSnapshot{root: mustRoot(t, tree, 2), signed: mkSLR(t, 2, tree.root(2))})
				require.NoError(t, err)
				tc.releaseProof()
				synctest.Wait()
				requireVerifiedRead(t, <-done, tree, 0, 2)
				if kind == "hash" {
					require.EqualValues(t, 2, used.root.TreeSize)
				}
				require.Empty(t, tc.proofWaiters)
				require.Empty(t, tc.proofs)
			})
		})
	}
}

func TestPollRetryCapRespectsFreshnessAndInterval(t *testing.T) {
	defaults := cacheOptions{}.withDefaults()
	require.Equal(t, 3300*time.Millisecond, defaults.maxRootAge) // Preserve the existing freshness policy.
	for _, o := range []cacheOptions{defaults, {pollInterval: time.Millisecond, maxRootAge: time.Second}, {pollInterval: time.Second, maxRootAge: time.Minute}, {pollInterval: time.Minute, maxRootAge: time.Second}} {
		b := backoff.Backoff{Min: o.pollInterval, Max: o.retryMax(), Factor: 2, Jitter: true}
		for range 30 {
			delay := b.Duration()
			require.GreaterOrEqual(t, delay, o.pollInterval)
			require.Less(t, delay, 2*o.retryMax())
		}
		if o.pollInterval <= o.maxRootAge/4 {
			require.LessOrEqual(t, 2*o.retryMax(), o.maxRootAge/2)
		}
	}
}

func mustRoot(t *testing.T, tree *logTree, size uint64) types.LogRootV1 {
	t.Helper()
	return types.LogRootV1{TreeSize: size, RootHash: tree.root(size)}
}
