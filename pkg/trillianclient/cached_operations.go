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
	"encoding/hex"
	"fmt"

	"github.com/google/trillian"
	internalclient "github.com/sigstore/rekor/internal/trillianclient"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func responseError(err error) *internalclient.Response {
	return &internalclient.Response{Status: status.Code(err), Err: err}
}

func (t *cachedTrillianClient) waitForSize(ctx context.Context, size uint64) error {
	snap, err := t.current(ctx)
	if err != nil {
		return err
	}
	if snap.root.TreeSize >= size {
		return nil
	}
	if t.opts.frozen {
		return status.Errorf(codes.NotFound, "tree has size %d, want at least %d", snap.root.TreeSize, size)
	}

	t.mu.Lock()
	// publish updates the snapshot and heap under this lock. Recheck so an
	// advance between current and Lock cannot be missed.
	if snap := t.snapshot.Load(); snap != nil && snap.root.TreeSize >= size {
		t.mu.Unlock()
		return nil
	}
	w := t.addSizeWaiter(size)
	t.mu.Unlock()

	select {
	case <-w.done:
		return nil
	case <-ctx.Done():
		t.mu.Lock()
		t.removeSizeWaiter(w)
		t.mu.Unlock()
		return status.FromContextError(ctx.Err()).Err()
	case <-t.stopped.Done():
		t.mu.Lock()
		t.removeSizeWaiter(w)
		t.mu.Unlock()
		return status.Error(codes.Canceled, "trillian client closed")
	}
}

// waitForPoll waits for a root RPC which starts after this function reads the
// current generation. It is used after a lookup miss: all callers share the
// updater's next RPC instead of issuing one RPC per miss.
func (t *cachedTrillianClient) waitForPoll(ctx context.Context) error {
	t.mu.Lock()
	result := t.nextPoll
	t.mu.Unlock()
	select {
	case <-result.done:
		return result.err
	case <-ctx.Done():
		return status.FromContextError(ctx.Err()).Err()
	case <-t.stopped.Done():
		return status.Error(codes.Canceled, "trillian client closed")
	}
}

func (t *cachedTrillianClient) AddLeaf(ctx context.Context, value []byte) *internalclient.Response {
	before, err := t.current(ctx)
	if err != nil {
		return responseError(err)
	}
	queued, err := t.client.QueueLeaf(ctx, &trillian.QueueLeafRequest{
		LogId: t.logID,
		Leaf:  &trillian.LogLeaf{LeafValue: value},
	})
	if err != nil {
		return &internalclient.Response{Status: status.Code(err), Err: err, GetAddResult: queued}
	}
	if queued == nil || queued.QueuedLeaf == nil || queued.QueuedLeaf.Leaf == nil {
		return &internalclient.Response{Status: codes.Internal, Err: fmt.Errorf("trillian returned no queued leaf")}
	}
	if s := queued.QueuedLeaf.Status; s != nil && s.Code != int32(codes.OK) {
		return &internalclient.Response{Status: codes.OK, GetAddResult: queued}
	}

	hash := queued.QueuedLeaf.Leaf.MerkleLeafHash
	if err := t.waitForSize(ctx, before.root.TreeSize+1); err != nil {
		return &internalclient.Response{Status: status.Code(err), Err: err, GetAddResult: queued}
	}
	for {
		snap, err := t.current(ctx)
		if err != nil {
			return &internalclient.Response{Status: status.Code(err), Err: err, GetAddResult: queued}
		}
		proof := getProofByHash(ctx, t.client, t.verifier, t.logID, hash, snap)
		if proof.Err == nil {
			leaf := t.leafForHash(ctx, hash, proof)
			if leaf.Err != nil {
				leaf.GetAddResult = queued
				return leaf
			}
			queued.QueuedLeaf.Leaf = leaf.GetLeafAndProofResult.Leaf
			leaf.GetAddResult = queued
			return leaf
		}
		if status.Code(proof.Err) != codes.NotFound {
			proof.GetAddResult = queued
			return proof
		}
		if err := t.waitForSize(ctx, snap.root.TreeSize+1); err != nil {
			return &internalclient.Response{Status: status.Code(err), Err: err, GetAddResult: queued}
		}
	}
}

func (t *cachedTrillianClient) leafForHash(ctx context.Context, hash []byte, proof *internalclient.Response) *internalclient.Response {
	proofs := proof.GetProofResult.Proof
	if len(proofs) != 1 {
		err := fmt.Errorf("expected 1 proof for %s, got %d", hex.EncodeToString(hash), len(proofs))
		return responseError(err)
	}
	return getLeafForProof(ctx, t.client, t.logID, proofs[0].LeafIndex, hash, proofs[0], proof.GetProofResult.SignedLogRoot)
}

func (t *cachedTrillianClient) GetLeafAndProofByHash(ctx context.Context, hash []byte) *internalclient.Response {
	snap, err := t.current(ctx)
	if err != nil {
		return responseError(err)
	}
	proof := getProofByHash(ctx, t.client, t.verifier, t.logID, hash, snap)
	if proof.Err != nil && !t.opts.frozen {
		code := status.Code(proof.Err)
		if code == codes.NotFound || code == codes.OutOfRange {
			if err := t.waitForPoll(ctx); err != nil {
				return responseError(err)
			}
			next, err := t.current(ctx)
			if err != nil {
				return responseError(err)
			}
			if next.root.TreeSize > snap.root.TreeSize {
				proof = getProofByHash(ctx, t.client, t.verifier, t.logID, hash, next)
			}
		}
	}
	if proof.Err != nil {
		return responseError(proof.Err)
	}
	return t.leafForHash(ctx, hash, proof)
}

func (t *cachedTrillianClient) GetLeafAndProofByIndex(ctx context.Context, index int64) *internalclient.Response {
	if index < 0 {
		return responseError(status.Errorf(codes.InvalidArgument, "negative leaf index %d", index))
	}
	snap, err := t.current(ctx)
	if err != nil {
		return responseError(err)
	}
	if uint64(index) < snap.root.TreeSize {
		return getEntryAndProof(ctx, t.client, t.verifier, t.logID, index, snap)
	}
	if t.opts.frozen {
		return responseError(status.Errorf(codes.NotFound, "leaf index %d is outside tree size %d", index, snap.root.TreeSize))
	}
	if err := t.waitForPoll(ctx); err != nil {
		return responseError(err)
	}
	snap, err = t.current(ctx)
	if err != nil {
		return responseError(err)
	}
	if uint64(index) >= snap.root.TreeSize {
		return responseError(status.Errorf(codes.NotFound, "leaf index %d is outside tree size %d", index, snap.root.TreeSize))
	}
	return getEntryAndProof(ctx, t.client, t.verifier, t.logID, index, snap)
}
