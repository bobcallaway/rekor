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
	"fmt"
	"sync"

	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature"
)

const DefaultCheckpointCacheEntries = 128

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
	mu sync.Mutex

	maxEntries int
	entries    map[checkpointKey]*checkpointCall
	completed  []checkpointKey
	nextEvict  int
}

func newCheckpointCache(maxEntries int) *checkpointCache {
	if maxEntries < 0 {
		maxEntries = DefaultCheckpointCacheEntries
	}
	return &checkpointCache{
		maxEntries: maxEntries,
		entries:    make(map[checkpointKey]*checkpointCall, maxEntries),
		completed:  make([]checkpointKey, 0, maxEntries),
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
	key, err := makeCheckpointKey(treeID, treeSize, rootHash)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	if call := c.entries[key]; call != nil {
		checkpointCacheRequests.WithLabelValues("hit").Inc()
		c.mu.Unlock()
		select {
		case <-call.done:
			return call.value, call.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	checkpointCacheRequests.WithLabelValues("miss").Inc()
	call := &checkpointCall{done: make(chan struct{})}
	c.entries[key] = call
	c.mu.Unlock()

	call.value, call.err = createCheckpoint(ctx, hostname, treeID, treeSize, rootHash, signer)

	c.mu.Lock()
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
	return call.value, call.err
}

func createCheckpoint(ctx context.Context, hostname string, treeID int64, treeSize uint64, rootHash []byte, signer signature.Signer) (string, error) {
	checkpoint, err := util.CreateAndSignCheckpoint(ctx, hostname, treeID, treeSize, rootHash, signer)
	if err != nil {
		return "", err
	}
	return string(checkpoint), nil
}
