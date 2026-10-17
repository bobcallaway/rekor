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
	"testing/synctest"
	"time"

	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/require"
)

type countingSigner struct {
	signature.Signer
	calls    atomic.Int32
	entered  chan struct{}
	release  chan struct{}
	contexts chan context.Context
	signErr  error
	once     sync.Once
}

func (s *countingSigner) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	s.calls.Add(1)
	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}
	if s.contexts != nil {
		s.contexts <- ctx
	}
	if s.entered != nil {
		s.once.Do(func() { close(s.entered) })
	}
	if s.release != nil {
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
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
	cache := newCheckpointCache(8, 0)
	t.Cleanup(cache.close)
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
	cache := newCheckpointCache(2, 0)
	t.Cleanup(cache.close)
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
	cache := newCheckpointCache(2, 0)
	t.Cleanup(cache.close)
	_, err := cache.sign(context.Background(), "rekor.example", 42, 1, []byte("short"), signer)
	require.Error(t, err)
	require.Zero(t, signer.calls.Load())
}

func TestCheckpointCacheDoesNotRetainSigningFailure(t *testing.T) {
	signer := newCountingSigner(t)
	signer.signErr = errors.New("kms unavailable")
	cache := newCheckpointCache(2, 0)
	t.Cleanup(cache.close)
	root := sha256.Sum256([]byte("root"))

	for range 2 {
		_, err := cache.sign(context.Background(), "rekor.example", 42, 1, root[:], signer)
		require.ErrorContains(t, err, "kms unavailable")
	}
	require.EqualValues(t, 2, signer.calls.Load())
	require.Empty(t, cache.entries)
}

func TestCheckpointCacheCallerCancellationDoesNotCancelSigning(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		signer := newCountingSigner(t)
		signer.entered = make(chan struct{})
		signer.release = make(chan struct{})
		signer.contexts = make(chan context.Context, 1)
		cache := newCheckpointCache(8, time.Minute)
		defer cache.close()
		root := sha256.Sum256([]byte("root"))
		originalRoot := root
		leaderCtx, cancelLeader := context.WithCancel(context.Background())
		defer cancelLeader()
		leader := make(chan error, 1)
		go func() {
			_, err := cache.sign(leaderCtx, "rekor.example", 42, 7, root[:], signer)
			leader <- err
		}()
		<-signer.entered
		signingCtx := <-signer.contexts
		deadline, ok := signingCtx.Deadline()
		require.True(t, ok)
		require.Equal(t, time.Minute, time.Until(deadline))

		followerCtx, cancelFollower := context.WithCancel(context.Background())
		defer cancelFollower()
		follower := make(chan error, 1)
		go func() {
			_, err := cache.sign(followerCtx, "rekor.example", 42, 7, root[:], signer)
			follower <- err
		}()
		type result struct {
			checkpoint string
			err        error
		}
		healthy := make(chan result, 1)
		go func() {
			value, err := cache.sign(context.Background(), "rekor.example", 42, 7, root[:], signer)
			healthy <- result{value, err}
		}()
		synctest.Wait()

		cancelFollower()
		require.ErrorIs(t, <-follower, context.Canceled)
		cancelLeader()
		require.ErrorIs(t, <-leader, context.Canceled)
		require.NoError(t, signingCtx.Err())
		select {
		case <-healthy:
			t.Fatal("healthy caller returned before signing completed")
		default:
		}

		// A returning caller may reuse its input buffer while shared work runs.
		clear(root[:])
		close(signer.release)
		got := <-healthy
		require.NoError(t, got.err)
		var checkpoint util.SignedCheckpoint
		require.NoError(t, checkpoint.UnmarshalText([]byte(got.checkpoint)))
		require.Equal(t, originalRoot[:], checkpoint.Hash)
		cached, err := cache.sign(context.Background(), "rekor.example", 42, 7, originalRoot[:], signer)
		require.NoError(t, err)
		require.Equal(t, got.checkpoint, cached)
		require.EqualValues(t, 1, signer.calls.Load())
	})
}

func TestCheckpointCacheSigningTimeoutAllowsRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		signer := newCountingSigner(t)
		signer.release = make(chan struct{})
		cache := newCheckpointCache(8, time.Second)
		defer cache.close()
		root := sha256.Sum256([]byte("root"))
		start := time.Now()
		_, err := cache.sign(context.Background(), "rekor.example", 42, 7, root[:], signer)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Equal(t, time.Second, time.Since(start))
		require.Empty(t, cache.entries)

		close(signer.release)
		_, err = cache.sign(context.Background(), "rekor.example", 42, 7, root[:], signer)
		require.NoError(t, err)
		require.EqualValues(t, 2, signer.calls.Load())
	})
}

func TestCheckpointCacheCloseCancelsSigning(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		signer := newCountingSigner(t)
		signer.entered = make(chan struct{})
		signer.release = make(chan struct{})
		signer.contexts = make(chan context.Context, 1)
		cache := newCheckpointCache(8, time.Minute)
		defer cache.close()
		root := sha256.Sum256([]byte("root"))
		done := make(chan error, 1)
		go func() {
			_, err := cache.sign(context.Background(), "rekor.example", 42, 7, root[:], signer)
			done <- err
		}()
		<-signer.entered
		signingCtx := <-signer.contexts
		cache.close()
		require.ErrorIs(t, <-done, context.Canceled)
		require.ErrorIs(t, signingCtx.Err(), context.Canceled)
		synctest.Wait()
		require.Empty(t, cache.entries)
		_, err := cache.sign(context.Background(), "rekor.example", 42, 7, root[:], signer)
		require.ErrorIs(t, err, context.Canceled)
		require.EqualValues(t, 1, signer.calls.Load())
	})
}

func TestCheckpointCacheDisabledUsesCallerContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		signer := newCountingSigner(t)
		signer.entered = make(chan struct{})
		signer.release = make(chan struct{})
		signer.contexts = make(chan context.Context, 1)
		cache := newCheckpointCache(0, time.Minute)
		defer cache.close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		root := sha256.Sum256([]byte("root"))
		done := make(chan error, 1)
		go func() {
			_, err := cache.sign(ctx, "rekor.example", 42, 7, root[:], signer)
			done <- err
		}()
		<-signer.entered
		require.Same(t, ctx, <-signer.contexts)
		cancel()
		require.ErrorIs(t, <-done, context.Canceled)
		require.Empty(t, cache.entries)
	})
}
