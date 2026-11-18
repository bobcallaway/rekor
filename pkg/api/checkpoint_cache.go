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
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/signer"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/gcp"
)

const (
	DefaultCheckpointCacheEntries       = 128
	DefaultCheckpointSigningConcurrency = 32
	DefaultCheckpointSigningTimeout     = 30 * time.Second
	maxSigningDuration                  = time.Duration(1<<63 - 1)
)

// gcpKMSSigningBudget returns the total per-call timeout budget configured for
// GCP KMS retries, or 0 if the signer is not GCP KMS or has no per-call timeout.
func gcpKMSSigningBudget(sc signer.SigningConfig) time.Duration {
	if !strings.HasPrefix(sc.SigningSchemeOrKeyPath, gcp.ReferenceScheme) || sc.GCPKMSTimeout == 0 {
		return 0
	}
	maxSec := uint64(maxSigningDuration / time.Second)
	if uint64(sc.GCPKMSRetries) >= maxSec {
		return maxSigningDuration
	}
	attempts := uint64(sc.GCPKMSRetries) + 1
	timeoutSec := uint64(sc.GCPKMSTimeout)
	if timeoutSec > maxSec/attempts {
		return maxSigningDuration
	}
	return time.Duration(timeoutSec*attempts) * time.Second
}

// resolveCheckpointSigningTimeout derives the effective shared checkpoint
// signing timeout. When configured is <= 0, it defaults to at least
// DefaultCheckpointSigningTimeout and expands to cover any larger configured
// GCP KMS retry budget. When configured is positive but shorter than that
// budget while checkpoint caching is enabled, the explicit value is preserved
// and a startup warning is logged.
func resolveCheckpointSigningTimeout(configured time.Duration, sc signer.SigningConfig, cacheEnabled bool) time.Duration {
	budget := gcpKMSSigningBudget(sc)
	if configured <= 0 {
		if budget > DefaultCheckpointSigningTimeout {
			return budget
		}
		return DefaultCheckpointSigningTimeout
	}
	if cacheEnabled && budget > configured {
		log.Logger.Warnw("checkpoint signing timeout is shorter than configured GCP KMS retry budget; shared checkpoint signing may time out before retries finish",
			"checkpointSigningTimeout", configured,
			"gcpKMSTimeoutSeconds", sc.GCPKMSTimeout,
			"gcpKMSRetries", sc.GCPKMSRetries,
			"gcpKMSBudget", budget,
		)
	}
	return configured
}

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
	completed := false
	defer func() {
		if r := recover(); r != nil {
			call.value = ""
			call.err = fmt.Errorf("checkpoint signing panicked: %v", r)
			log.Logger.Errorw("checkpoint signing panicked", "treeID", key.treeID, "treeSize", key.treeSize, "panic", r, "stack", string(debug.Stack()))
		} else if !completed {
			call.value = ""
			call.err = errors.New("checkpoint signing terminated unexpectedly")
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
	}()

	call.value, call.err = createCheckpoint(ctx, hostname, key.treeID, key.treeSize, key.rootHash[:], signer)
	if err := ctx.Err(); err != nil {
		call.value, call.err = "", err
	}
	completed = true
}

func createCheckpoint(ctx context.Context, hostname string, treeID int64, treeSize uint64, rootHash []byte, signer signature.Signer) (string, error) {
	checkpoint, err := util.CreateAndSignCheckpoint(ctx, hostname, treeID, treeSize, rootHash, signer)
	if err != nil {
		return "", err
	}
	return string(checkpoint), nil
}
