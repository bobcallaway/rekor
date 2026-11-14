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
	"encoding/hex"
	"fmt"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/types"
	internalclient "github.com/sigstore/rekor/internal/trillianclient"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// rootSnapshot keeps the root used to verify a proof with the serialized root
// returned alongside that proof.
type rootSnapshot struct {
	root   types.LogRootV1
	signed *trillian.SignedLogRoot
}

// checkQueuedLeaf binds the hash used to find an integrated entry to the bytes
// submitted by the caller.
func checkQueuedLeaf(value []byte, leaf *trillian.LogLeaf) error {
	if leaf == nil {
		return status.Error(codes.Internal, "trillian returned no queued leaf")
	}
	if want := rfc6962.DefaultHasher.HashLeaf(value); !bytes.Equal(leaf.MerkleLeafHash, want) {
		return status.Errorf(codes.Internal, "trillian queued leaf hash %x, want %x", leaf.MerkleLeafHash, want)
	}
	return nil
}

// checkLeaf binds the body and position Rekor signs to the verified leaf hash.
func checkLeaf(leaf *trillian.LogLeaf, index int64, hash []byte) error {
	if leaf == nil {
		return status.Error(codes.Internal, "trillian returned a nil leaf")
	}
	if leaf.LeafIndex != index {
		return status.Errorf(codes.Internal, "trillian returned leaf index %d, want %d", leaf.LeafIndex, index)
	}
	if !bytes.Equal(leaf.MerkleLeafHash, hash) {
		return status.Errorf(codes.Internal, "leaf hash mismatch: expected %x, got %x", hash, leaf.MerkleLeafHash)
	}
	if !bytes.Equal(rfc6962.DefaultHasher.HashLeaf(leaf.LeafValue), hash) {
		return status.Errorf(codes.Internal, "leaf value at index %d does not match leaf hash %x", index, hash)
	}
	return nil
}

func getProofByHash(ctx context.Context, c trillian.TrillianLogClient, verifier *client.LogVerifier, logID int64, hash []byte, snap rootSnapshot) *internalclient.Response {
	if snap.root.TreeSize == 0 {
		return &internalclient.Response{
			Status: codes.NotFound,
			Err:    status.Error(codes.NotFound, "tree is empty"),
		}
	}

	resp, err := c.GetInclusionProofByHash(ctx, &trillian.GetInclusionProofByHashRequest{
		LogId:    logID,
		LeafHash: hash,
		TreeSize: int64(snap.root.TreeSize), //nolint:gosec
	})
	if err != nil {
		return &internalclient.Response{Status: status.Code(err), Err: err}
	}
	if resp == nil {
		err := fmt.Errorf("trillian returned no proof for hash %s", hex.EncodeToString(hash))
		return &internalclient.Response{Status: status.Code(err), Err: err}
	}
	if len(resp.Proof) == 0 {
		return responseError(status.Errorf(codes.NotFound, "no proof for hash %x in tree size %d", hash, snap.root.TreeSize))
	}
	for _, proof := range resp.Proof {
		if proof == nil {
			return responseError(status.Error(codes.Internal, "trillian returned a nil proof"))
		}
		if err := verifier.VerifyInclusionByHash(&snap.root, hash, proof); err != nil {
			return &internalclient.Response{Status: status.Code(err), Err: err}
		}
	}
	return &internalclient.Response{
		Status: codes.OK,
		GetProofResult: &trillian.GetInclusionProofByHashResponse{
			Proof:         resp.Proof,
			SignedLogRoot: snap.signed,
		},
	}
}

func getLeafForProof(ctx context.Context, c trillian.TrillianLogClient, logID, index int64, hash []byte, proof *trillian.Proof, signed *trillian.SignedLogRoot) *internalclient.Response {
	resp, err := c.GetLeavesByRange(ctx, &trillian.GetLeavesByRangeRequest{
		LogId:      logID,
		StartIndex: index,
		Count:      1,
	})
	if err != nil {
		return &internalclient.Response{Status: status.Code(err), Err: err}
	}
	if resp == nil || len(resp.Leaves) == 0 {
		err := fmt.Errorf("no leaf returned for index %d", index)
		return &internalclient.Response{Status: codes.NotFound, Err: err}
	}
	if len(resp.Leaves) != 1 {
		err := fmt.Errorf("multiple leaves returned for index %d", index)
		return &internalclient.Response{Status: codes.FailedPrecondition, Err: err}
	}
	leaf := resp.Leaves[0]
	if err := checkLeaf(leaf, index, hash); err != nil {
		return &internalclient.Response{Status: status.Code(err), Err: err}
	}
	return &internalclient.Response{
		Status: codes.OK,
		GetLeafAndProofResult: &trillian.GetEntryAndProofResponse{
			Proof:         proof,
			Leaf:          leaf,
			SignedLogRoot: signed,
		},
	}
}

func getEntryAndProof(ctx context.Context, c trillian.TrillianLogClient, verifier *client.LogVerifier, logID, index int64, snap rootSnapshot) *internalclient.Response {
	resp, err := c.GetEntryAndProof(ctx, &trillian.GetEntryAndProofRequest{
		LogId:     logID,
		LeafIndex: index,
		TreeSize:  int64(snap.root.TreeSize), //nolint:gosec
	})
	if err != nil {
		return &internalclient.Response{Status: status.Code(err), Err: err}
	}
	if resp == nil || resp.Proof == nil {
		return &internalclient.Response{Status: codes.NotFound, Err: fmt.Errorf("trillian returned no proof for index %d", index)}
	}
	if resp.Leaf == nil {
		return &internalclient.Response{Status: codes.Internal, Err: fmt.Errorf("trillian returned a proof with no leaf for index %d", index)}
	}
	if resp.Proof.LeafIndex != index {
		return &internalclient.Response{Status: codes.Internal, Err: fmt.Errorf("trillian returned a proof for index %d, want %d", resp.Proof.LeafIndex, index)}
	}
	if err := checkLeaf(resp.Leaf, index, resp.Leaf.MerkleLeafHash); err != nil {
		return responseError(err)
	}
	if err := verifier.VerifyInclusionByHash(&snap.root, resp.Leaf.MerkleLeafHash, resp.Proof); err != nil {
		return &internalclient.Response{Status: status.Code(err), Err: err}
	}
	return &internalclient.Response{
		Status: codes.OK,
		GetLeafAndProofResult: &trillian.GetEntryAndProofResponse{
			Proof:         resp.Proof,
			Leaf:          resp.Leaf,
			SignedLogRoot: snap.signed,
		},
	}
}
