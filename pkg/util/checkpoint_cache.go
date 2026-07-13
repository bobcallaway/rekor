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
	"context"
	"fmt"

	"github.com/jellydator/ttlcache/v3"
	"github.com/sigstore/sigstore/pkg/signature"
	"golang.org/x/sync/singleflight"
)

type checkpointCacheKey struct {
	TreeID int64
	Size   uint64
	Hash   string
}

func (k checkpointCacheKey) sfKey() string {
	return fmt.Sprintf("%d/%d/%s", k.TreeID, k.Size, k.Hash)
}

// SignOutcome describes how GetOrSign satisfied a request. Values double as
// Prometheus label values, so adding a new outcome only requires adding a
// constant.
type SignOutcome string

const (
	// OutcomeSigned means the caller (or the cache is disabled) invoked the
	// signer directly.
	OutcomeSigned SignOutcome = "sign"
	// OutcomeCacheHit means the caller was served from the cache without
	// invoking the signer or waiting on another goroutine.
	OutcomeCacheHit SignOutcome = "cache_hit"
	// OutcomeCoalesced means the caller was a single-flight follower: another
	// concurrent request signed and the caller received that result without
	// making its own KMS call.
	OutcomeCoalesced SignOutcome = "coalesced"
)

// SignedCheckpointCache dedups checkpoint signatures within a single process
// by caching the serialized bytes returned from CreateAndSignCheckpoint,
// keyed by (treeID, size, hash). The checkpoint note content is fully
// determined by that tuple plus the hostname the cache was constructed with,
// so returning a previously produced signature is safe and avoids a redundant
// signer call. Concurrent misses on the same key are coalesced via
// single-flight so at most one signer invocation is in flight per key.
//
// A cache constructed with capacity 0 is a permanent no-op: every GetOrSign
// call falls through to CreateAndSignCheckpoint.
type SignedCheckpointCache struct {
	hostname string
	cache    *ttlcache.Cache[checkpointCacheKey, []byte]
	sf       singleflight.Group
}

// NewSignedCheckpointCache returns a bounded LRU-evicting cache bound to a
// fixed hostname (captured at construction to avoid a per-call lookup). A
// capacity of 0 disables caching but still returns a usable cache that signs
// on every call.
func NewSignedCheckpointCache(hostname string, capacity uint64) *SignedCheckpointCache {
	c := &SignedCheckpointCache{hostname: hostname}
	if capacity > 0 {
		c.cache = ttlcache.New(
			ttlcache.WithCapacity[checkpointCacheKey, []byte](capacity),
		)
	}
	return c
}

// GetOrSign returns a signed checkpoint for the given tuple. On a cache miss
// it invokes the signer under single-flight so concurrent misses on the same
// key coalesce into one KMS call. The returned SignOutcome reports how the
// result was produced (see the OutcomeX constants). Signing errors are
// propagated to every caller waiting on the same key and never stored, so the
// next request retries fresh.
func (c *SignedCheckpointCache) GetOrSign(ctx context.Context, treeID int64, size uint64, hash []byte, signer signature.Signer) ([]byte, SignOutcome, error) {
	if c.cache == nil {
		scBytes, err := CreateAndSignCheckpoint(ctx, c.hostname, treeID, size, hash, signer)
		return scBytes, OutcomeSigned, err
	}
	key := checkpointCacheKey{TreeID: treeID, Size: size, Hash: string(hash)}
	if item := c.cache.Get(key); item != nil {
		return item.Value(), OutcomeCacheHit, nil
	}

	// signed becomes true only if this goroutine's closure actually runs the
	// signer (i.e. it was the single-flight leader and the inner cache
	// re-check missed). Followers' closures never execute, so their `signed`
	// stays false.
	var signed bool
	v, err, _ := c.sf.Do(key.sfKey(), func() (any, error) {
		// Re-check the cache in case another goroutine populated it between
		// our outer Get and entry into sf.Do.
		if item := c.cache.Get(key); item != nil {
			return item.Value(), nil
		}
		signed = true
		// Detach the sign RPC from the caller's context so a client hangup
		// doesn't cancel the KMS call for the followers still waiting on it.
		// The underlying KMS client has its own timeout / retry controls
		// (rekor_server.signer.gcpkms.timeout / .retries).
		signCtx := context.WithoutCancel(ctx)
		scBytes, signErr := CreateAndSignCheckpoint(signCtx, c.hostname, treeID, size, hash, signer)
		if signErr != nil {
			return nil, signErr
		}
		c.cache.Set(key, scBytes, ttlcache.NoTTL)
		return scBytes, nil
	})

	outcome := OutcomeCoalesced
	if signed {
		outcome = OutcomeSigned
	}
	if err != nil {
		return nil, outcome, err
	}
	return v.([]byte), outcome, nil
}
