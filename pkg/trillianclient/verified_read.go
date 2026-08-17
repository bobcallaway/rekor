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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// rootSnapshot keeps the root used to verify a proof with the serialized root
// returned alongside that proof.
type rootSnapshot struct {
	root   types.LogRootV1
	signed *trillian.SignedLogRoot
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
	for _, proof := range resp.Proof {
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
	if !bytes.Equal(leaf.MerkleLeafHash, hash) {
		err := fmt.Errorf("leaf hash mismatch: expected %v, got %v", hex.EncodeToString(hash), hex.EncodeToString(leaf.MerkleLeafHash))
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
