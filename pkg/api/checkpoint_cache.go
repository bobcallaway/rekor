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
	"fmt"
	"sync"
	"time"

	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	DefaultCheckpointCacheEntries       = 128
	DefaultCheckpointSigningConcurrency = 32
	DefaultCheckpointSigningTimeout     = 30 * time.Second
)

var errCheckpointSigningFull = errors.New("too many checkpoints are being signed")

type checkpointKey struct {
	treeID   int64
	treeSize uint64
	rootHash [sha256.Size]byte
}

type checkpointCall struct {
	done  chan struct{}
	value string
	err   error
}

// checkpointCache coalesces concurrent signatures for an exact verified root
// and retains recent results. Trillian roots advance sequentially, so a fixed
// FIFO ring is both cheaper and more useful here than a pointer-heavy LRU.
type checkpointCache struct {
	mu          sync.Mutex
	ctx         context.Context
	stop        context.CancelFunc
	signTimeout time.Duration

	maxEntries int
	maxSigning int
	inFlight   int
	entries    map[checkpointKey]*checkpointCall
	completed  []checkpointKey
	nextEvict  int
}

func newCheckpointCache(maxEntries int, signTimeout time.Duration, maxSigning int) *checkpointCache {
	if maxEntries < 0 {
		maxEntries = DefaultCheckpointCacheEntries
	}
	if signTimeout <= 0 {
		signTimeout = DefaultCheckpointSigningTimeout
	}
	if maxSigning <= 0 {
		maxSigning = DefaultCheckpointSigningConcurrency
	}
	ctx, stop := context.WithCancel(context.Background())
	return &checkpointCache{
		ctx:         ctx,
		stop:        stop,
		signTimeout: signTimeout,
		maxEntries:  maxEntries,
		maxSigning:  maxSigning,
		entries:     make(map[checkpointKey]*checkpointCall, maxEntries),
		completed:   make([]checkpointKey, 0, maxEntries),
	}
}

func (c *checkpointCache) close() {
	if c != nil {
		c.stop()
	}
}

func makeCheckpointKey(treeID int64, treeSize uint64, rootHash []byte) (checkpointKey, error) {
	if len(rootHash) != sha256.Size {
		return checkpointKey{}, fmt.Errorf("checkpoint root hash has length %d, want %d", len(rootHash), sha256.Size)
	}
	key := checkpointKey{treeID: treeID, treeSize: treeSize}
	copy(key.rootHash[:], rootHash)
	return key, nil
}

func (c *checkpointCache) sign(ctx context.Context, hostname string, treeID int64, treeSize uint64, rootHash []byte, signer signature.Signer) (string, error) {
	if c == nil || c.maxEntries == 0 {
		return createCheckpoint(ctx, hostname, treeID, treeSize, rootHash, signer)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := c.ctx.Err(); err != nil {
		return "", err
	}
	key, err := makeCheckpointKey(treeID, treeSize, rootHash)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	call := c.entries[key]
	if call != nil {
		checkpointCacheRequests.WithLabelValues("hit").Inc()
	} else {
		if c.inFlight >= c.maxSigning {
			c.mu.Unlock()
			checkpointCacheRequests.WithLabelValues("rejected").Inc()
			return "", errCheckpointSigningFull
		}
		c.inFlight++
		checkpointCacheRequests.WithLabelValues("miss").Inc()
		call = &checkpointCall{done: make(chan struct{})}
		c.entries[key] = call
		// Shared work belongs to the cache, not to the first request. Copy
		// the hash via key so it remains owned after that request returns.
		signCtx, cancel := context.WithTimeout(c.ctx, c.signTimeout)
		go func() {
			defer cancel()
			c.complete(signCtx, key, call, hostname, signer)
		}()
	}
	c.mu.Unlock()

	// The initiating caller waits just like every subsequent caller, so
	// cancellation never holds it until the shared signing operation ends.
	select {
	case <-call.done:
		return call.value, call.err
	case <-ctx.Done():
		return "", ctx.Err()
	case <-c.ctx.Done():
		return "", c.ctx.Err()
	}
}

func (c *checkpointCache) complete(ctx context.Context, key checkpointKey, call *checkpointCall, hostname string, signer signature.Signer) {
	call.value, call.err = createCheckpoint(ctx, hostname, key.treeID, key.treeSize, key.rootHash[:], signer)
	if err := ctx.Err(); err != nil {
		call.value, call.err = "", err
	}

	c.mu.Lock()
	c.inFlight--
	if call.err != nil {
		delete(c.entries, key)
		checkpointCacheRequests.WithLabelValues("sign_error").Inc()
	} else if len(c.completed) < c.maxEntries {
		c.completed = append(c.completed, key)
	} else {
		delete(c.entries, c.completed[c.nextEvict])
		c.completed[c.nextEvict] = key
		c.nextEvict = (c.nextEvict + 1) % c.maxEntries
	}
	close(call.done)
	c.mu.Unlock()
}

func createCheckpoint(ctx context.Context, hostname string, treeID int64, treeSize uint64, rootHash []byte, signer signature.Signer) (string, error) {
	checkpoint, err := util.CreateAndSignCheckpoint(ctx, hostname, treeID, treeSize, rootHash, signer)
	if err != nil {
		return "", err
	}
	return string(checkpoint), nil
}
