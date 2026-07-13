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

package util

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
)

// countingSigner wraps a signature.Signer and tallies SignMessage invocations
// so tests can assert cache hit/miss behavior. When err is non-nil, SignMessage
// returns it without touching the underlying signer or incrementing the counter.
type countingSigner struct {
	inner signature.Signer
	calls atomic.Int64
	err   error
}

func (c *countingSigner) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	if c.err != nil {
		return nil, c.err
	}
	c.calls.Add(1)
	return c.inner.SignMessage(message, opts...)
}

func (c *countingSigner) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return c.inner.PublicKey(opts...)
}

func newCountingSigner(t *testing.T) *countingSigner {
	t.Helper()
	inner, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	return &countingSigner{inner: inner}
}

func TestSignedCheckpointCache_HitAvoidsSignerCall(t *testing.T) {
	ctx := context.Background()
	s := newCountingSigner(t)
	cache := NewSignedCheckpointCache("rekor.localhost", 10)

	hash := sha256.Sum256([]byte("root"))
	first, outcome, err := cache.GetOrSign(ctx, 1, 42, hash[:], s)
	if err != nil {
		t.Fatalf("first GetOrSign: %v", err)
	}
	if outcome != OutcomeSigned {
		t.Fatalf("first call: expected OutcomeSigned, got %v", outcome)
	}
	second, outcome, err := cache.GetOrSign(ctx, 1, 42, hash[:], s)
	if err != nil {
		t.Fatalf("second GetOrSign: %v", err)
	}
	if outcome != OutcomeCacheHit {
		t.Fatalf("second call: expected OutcomeCacheHit, got %v", outcome)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("cached bytes differ from first sign")
	}
	if got := s.calls.Load(); got != 1 {
		t.Fatalf("signer invocations: got %d, want 1", got)
	}
}

func TestSignedCheckpointCache_DistinctTuplesEachSign(t *testing.T) {
	ctx := context.Background()
	s := newCountingSigner(t)
	cache := NewSignedCheckpointCache("rekor.localhost", 10)

	tuples := []struct {
		treeID int64
		size   uint64
		hash   [32]byte
	}{
		{1, 10, sha256.Sum256([]byte("a"))},
		{1, 11, sha256.Sum256([]byte("b"))}, // same tree, different size/hash
		{2, 10, sha256.Sum256([]byte("a"))}, // same size/hash, different tree
	}
	for _, tup := range tuples {
		if _, _, err := cache.GetOrSign(ctx, tup.treeID, tup.size, tup.hash[:], s); err != nil {
			t.Fatalf("GetOrSign: %v", err)
		}
	}
	if got := s.calls.Load(); got != int64(len(tuples)) {
		t.Fatalf("signer invocations: got %d, want %d", got, len(tuples))
	}
}

func TestSignedCheckpointCache_CapacityEvictsLRU(t *testing.T) {
	ctx := context.Background()
	s := newCountingSigner(t)
	cache := NewSignedCheckpointCache("rekor.localhost", 2)

	hashA := sha256.Sum256([]byte("a"))
	hashB := sha256.Sum256([]byte("b"))
	hashC := sha256.Sum256([]byte("c"))

	// Fill: A, B. Then C evicts A (least recently used).
	for _, h := range [][32]byte{hashA, hashB, hashC} {
		if _, _, err := cache.GetOrSign(ctx, 1, 1, h[:], s); err != nil {
			t.Fatalf("GetOrSign: %v", err)
		}
	}
	if got := s.calls.Load(); got != 3 {
		t.Fatalf("after fill: got %d signs, want 3", got)
	}
	// Re-query A should miss (evicted) and re-sign.
	_, outcome, err := cache.GetOrSign(ctx, 1, 1, hashA[:], s)
	if err != nil {
		t.Fatalf("GetOrSign A after eviction: %v", err)
	}
	if outcome != OutcomeSigned {
		t.Fatalf("expected OutcomeSigned after eviction, got %v", outcome)
	}
	if got := s.calls.Load(); got != 4 {
		t.Fatalf("after re-query A: got %d signs, want 4", got)
	}
}

func TestSignedCheckpointCache_DisabledAlwaysSigns(t *testing.T) {
	ctx := context.Background()
	s := newCountingSigner(t)
	cache := NewSignedCheckpointCache("rekor.localhost", 0)

	hash := sha256.Sum256([]byte("root"))
	for i := range 3 {
		bytesOut, outcome, err := cache.GetOrSign(ctx, 1, 42, hash[:], s)
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if outcome != OutcomeSigned {
			t.Fatalf("iter %d: disabled cache must always report OutcomeSigned, got %v", i, outcome)
		}
		// Sanity: output must still be a well-formed signed checkpoint.
		sc := SignedCheckpoint{}
		if err := sc.UnmarshalText(bytesOut); err != nil {
			t.Fatalf("iter %d: unmarshal: %v", i, err)
		}
	}
	if got := s.calls.Load(); got != 3 {
		t.Fatalf("disabled cache: got %d signs, want 3", got)
	}
}

func TestSignedCheckpointCache_SigningErrorNotCached(t *testing.T) {
	ctx := context.Background()
	s := newCountingSigner(t)
	cache := NewSignedCheckpointCache("rekor.localhost", 10)

	hash := sha256.Sum256([]byte("root"))
	wantErr := errors.New("kms unavailable")
	s.err = wantErr

	if _, _, err := cache.GetOrSign(ctx, 1, 42, hash[:], s); !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped signing error, got %v", err)
	}

	// Recover the signer; the next call must reach it (i.e., prior error was not cached).
	s.err = nil
	if _, outcome, err := cache.GetOrSign(ctx, 1, 42, hash[:], s); err != nil {
		t.Fatalf("GetOrSign after recovery: %v", err)
	} else if outcome != OutcomeSigned {
		t.Fatalf("expected OutcomeSigned after prior error was not cached, got %v", outcome)
	}
	if got := s.calls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 successful sign; got %d", got)
	}
}

// blockingSigner sleeps in SignMessage until unblock is called, simulating a
// slow KMS call so multiple goroutines pile up behind the single-flight
// leader.
type blockingSigner struct {
	inner   signature.Signer
	calls   atomic.Int64
	release chan struct{}
	entered chan struct{} // closed when the first SignMessage begins
	once    sync.Once
}

func (b *blockingSigner) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	b.calls.Add(1)
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return b.inner.SignMessage(message, opts...)
}

func (b *blockingSigner) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return b.inner.PublicKey(opts...)
}

func TestSignedCheckpointCache_CoalescesConcurrentMisses(t *testing.T) {
	ctx := context.Background()
	inner, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	b := &blockingSigner{
		inner:   inner,
		release: make(chan struct{}),
		entered: make(chan struct{}),
	}
	cache := NewSignedCheckpointCache("rekor.localhost", 10)
	hash := sha256.Sum256([]byte("root"))

	const N = 20
	results := make([]SignOutcome, N)
	var wg sync.WaitGroup
	wg.Add(N)
	for i := range N {
		go func() {
			defer wg.Done()
			_, outcome, err := cache.GetOrSign(ctx, 1, 42, hash[:], b)
			if err != nil {
				t.Errorf("goroutine %d: %v", i, err)
				return
			}
			results[i] = outcome
		}()
	}

	// Wait until the leader is actually inside SignMessage, then give the
	// followers time to pile up on sf.Do before releasing.
	<-b.entered
	time.Sleep(50 * time.Millisecond)
	close(b.release)
	wg.Wait()

	if got := b.calls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 signer invocation across %d concurrent callers, got %d", N, got)
	}
	var signed, coalesced int
	for _, o := range results {
		switch o {
		case OutcomeSigned:
			signed++
		case OutcomeCoalesced:
			coalesced++
		default:
			t.Errorf("unexpected outcome %v (want signed or coalesced)", o)
		}
	}
	if signed != 1 {
		t.Errorf("expected exactly 1 leader (OutcomeSigned), got %d", signed)
	}
	if coalesced != N-1 {
		t.Errorf("expected %d coalesced followers, got %d", N-1, coalesced)
	}
}
