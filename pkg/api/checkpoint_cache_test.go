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

package api

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/require"
)

type countingSigner struct {
	signature.Signer
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
	signErr error
	once    sync.Once
}

func (s *countingSigner) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	s.calls.Add(1)
	if s.entered != nil {
		s.once.Do(func() { close(s.entered) })
	}
	if s.release != nil {
		<-s.release
	}
	if s.signErr != nil {
		return nil, s.signErr
	}
	return s.Signer.SignMessage(message, opts...)
}

func newCountingSigner(t *testing.T) *countingSigner {
	t.Helper()
	signer, _, err := signature.NewDefaultECDSASignerVerifier()
	require.NoError(t, err)
	return &countingSigner{Signer: signer}
}

func TestCheckpointCacheCoalescesConcurrentSigning(t *testing.T) {
	signer := newCountingSigner(t)
	signer.entered = make(chan struct{})
	signer.release = make(chan struct{})
	cache := newCheckpointCache(8)
	root := sha256.Sum256([]byte("root"))

	const callers = 32
	results := make(chan string, callers)
	errs := make(chan error, callers)
	for range callers {
		go func() {
			checkpoint, err := cache.sign(context.Background(), "rekor.example", 42, 7, root[:], signer)
			results <- checkpoint
			errs <- err
		}()
	}
	<-signer.entered
	close(signer.release)

	var first string
	for range callers {
		require.NoError(t, <-errs)
		checkpoint := <-results
		if first == "" {
			first = checkpoint
		}
		require.Equal(t, first, checkpoint)
	}
	require.EqualValues(t, 1, signer.calls.Load())
}

func TestCheckpointCacheUsesBoundedFIFO(t *testing.T) {
	signer := newCountingSigner(t)
	cache := newCheckpointCache(2)
	roots := [3][sha256.Size]byte{
		sha256.Sum256([]byte("a")),
		sha256.Sum256([]byte("b")),
		sha256.Sum256([]byte("c")),
	}

	for _, index := range []int{0, 1, 0, 2, 0} {
		_, err := cache.sign(context.Background(), "rekor.example", 42, uint64(index+1), roots[index][:], signer)
		require.NoError(t, err)
	}
	// The third call hits. Adding C then evicts the oldest completed root A,
	// so the final A is signed again.
	require.EqualValues(t, 4, signer.calls.Load())
	require.Len(t, cache.entries, 2)
}

func TestCheckpointCacheRejectsInvalidRootHash(t *testing.T) {
	signer := newCountingSigner(t)
	_, err := newCheckpointCache(2).sign(context.Background(), "rekor.example", 42, 1, []byte("short"), signer)
	require.Error(t, err)
	require.Zero(t, signer.calls.Load())
}

func TestCheckpointCacheDoesNotRetainSigningFailure(t *testing.T) {
	signer := newCountingSigner(t)
	signer.signErr = errors.New("kms unavailable")
	cache := newCheckpointCache(2)
	root := sha256.Sum256([]byte("root"))

	for range 2 {
		_, err := cache.sign(context.Background(), "rekor.example", 42, 1, root[:], signer)
		require.ErrorContains(t, err, "kms unavailable")
	}
	require.EqualValues(t, 2, signer.calls.Load())
	require.Empty(t, cache.entries)
}
