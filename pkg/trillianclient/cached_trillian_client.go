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
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/types"
	internalclient "github.com/sigstore/rekor/internal/trillianclient"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	DefaultPollInterval = 100 * time.Millisecond
	DefaultRootTimeout  = 3 * time.Second
)

type cacheOptions struct {
	pollInterval time.Duration
	rootTimeout  time.Duration
	maxRootAge   time.Duration
	frozen       bool
}

type pollResult struct {
	done chan struct{}
	err  error
}

func (o cacheOptions) withDefaults() cacheOptions {
	if o.pollInterval <= 0 {
		o.pollInterval = DefaultPollInterval
	}
	if o.rootTimeout <= 0 {
		o.rootTimeout = DefaultRootTimeout
	}
	if o.maxRootAge <= 0 {
		o.maxRootAge = o.rootTimeout + 3*o.pollInterval
	}
	return o
}

// cachedTrillianClient retains one verified root and refreshes it in the
// background. The embedded direct client supplies operations which do not use
// a root; root-dependent operations are overridden below.
type cachedTrillianClient struct {
	*directTrillianClient
	verifier *client.LogVerifier
	opts     cacheOptions

	snapshot    atomic.Pointer[rootSnapshot]
	lastSuccess atomic.Int64

	mu       sync.Mutex
	polled   chan struct{}
	pollErr  error
	nextPoll *pollResult
	waiters  sizeWaiters

	stop    context.CancelFunc
	stopped context.Context
	wg      sync.WaitGroup
}

func newCachedTrillianClient(c trillian.TrillianLogClient, logID int64, opts cacheOptions) *cachedTrillianClient {
	ctx, cancel := context.WithCancel(context.Background())
	t := &cachedTrillianClient{
		directTrillianClient: newDirectTrillianClient(c, logID),
		verifier:             client.NewLogVerifier(rfc6962.DefaultHasher),
		opts:                 opts.withDefaults(),
		polled:               make(chan struct{}),
		nextPoll:             &pollResult{done: make(chan struct{})},
		stop:                 cancel,
		stopped:              ctx,
	}
	t.wg.Add(1)
	go t.update()
	return t
}

func (t *cachedTrillianClient) ensureRoot(ctx context.Context) error {
	for {
		if t.snapshot.Load() != nil {
			return nil
		}

		t.mu.Lock()
		polled := t.polled
		t.mu.Unlock()
		select {
		case <-polled:
			if t.snapshot.Load() != nil {
				return nil
			}
			t.mu.Lock()
			err := t.pollErr
			t.mu.Unlock()
			if err != nil {
				return err
			}
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		case <-t.stopped.Done():
			return status.Error(codes.Canceled, "trillian client closed")
		}
	}
}

func (t *cachedTrillianClient) fetchRoot(ctx context.Context) (rootSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, t.opts.rootTimeout)
	defer cancel()

	var trusted types.LogRootV1
	if snap := t.snapshot.Load(); snap != nil {
		trusted = snap.root
	}
	resp, err := t.client.GetLatestSignedLogRoot(ctx, &trillian.GetLatestSignedLogRootRequest{
		LogId:         t.logID,
		FirstTreeSize: int64(trusted.TreeSize), //nolint:gosec
	})
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return rootSnapshot{}, status.Error(codes.Unavailable, "timed out fetching signed log root")
		}
		return rootSnapshot{}, err
	}
	if resp == nil || resp.SignedLogRoot == nil {
		return rootSnapshot{}, fmt.Errorf("trillian returned no signed log root")
	}
	root, err := internalclient.UnmarshalLogRoot(resp.SignedLogRoot.LogRoot)
	if err != nil {
		return rootSnapshot{}, err
	}
	if trusted.TreeSize > 0 && root.TreeSize > trusted.TreeSize {
		if _, err := t.verifier.VerifyRoot(&trusted, resp.SignedLogRoot, resp.GetProof().GetHashes()); err != nil {
			return rootSnapshot{}, fmt.Errorf("verify root update: %w", err)
		}
	}
	return rootSnapshot{root: root, signed: resp.SignedLogRoot}, nil
}

// publish installs a newer snapshot and wakes only waiters it satisfies.
func (t *cachedTrillianClient) publish(next rootSnapshot) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	old := t.snapshot.Load()
	if old != nil {
		switch {
		case next.root.TreeSize < old.root.TreeSize:
			t.lastSuccess.Store(time.Now().UnixNano())
			return false, nil
		case next.root.TreeSize == old.root.TreeSize:
			if !bytes.Equal(next.root.RootHash, old.root.RootHash) {
				return false, status.Errorf(codes.DataLoss, "root hash changed at tree size %d", next.root.TreeSize)
			}
			t.lastSuccess.Store(time.Now().UnixNano())
			return false, nil
		}
	}

	copy := next
	t.snapshot.Store(&copy)
	t.lastSuccess.Store(time.Now().UnixNano())
	t.notifySizeWaiters(next.root.TreeSize)
	return true, nil
}

func (t *cachedTrillianClient) update() {
	defer t.wg.Done()
	ticker := time.NewTicker(t.opts.pollInterval)
	defer ticker.Stop()

	for {
		err := t.poll()
		if err != nil && t.stopped.Err() == nil {
			log.Logger.Debugw("failed to update cached Trillian root", "treeID", t.logID, "err", err)
		}
		if err == nil && t.opts.frozen {
			return
		}

		select {
		case <-t.stopped.Done():
			return
		case <-ticker.C:
		}
	}
}

func (t *cachedTrillianClient) poll() error {
	t.mu.Lock()
	result := t.nextPoll
	t.nextPoll = &pollResult{done: make(chan struct{})}
	t.mu.Unlock()

	snap, err := t.fetchRoot(t.stopped)
	if err == nil {
		_, err = t.publish(snap)
	}

	t.mu.Lock()
	t.pollErr = err
	result.err = err
	close(t.polled)
	close(result.done)
	t.polled = make(chan struct{})
	t.mu.Unlock()
	return err
}

func (t *cachedTrillianClient) current(ctx context.Context) (rootSnapshot, error) {
	if err := t.ensureRoot(ctx); err != nil {
		return rootSnapshot{}, err
	}
	snap := t.snapshot.Load()
	if snap == nil {
		return rootSnapshot{}, status.Error(codes.Unavailable, "signed log root is not initialized")
	}
	if !t.opts.frozen && time.Since(time.Unix(0, t.lastSuccess.Load())) > t.opts.maxRootAge {
		return rootSnapshot{}, status.Error(codes.Unavailable, "cached signed log root is stale")
	}
	return *snap, nil
}

func (t *cachedTrillianClient) GetLatest(ctx context.Context) *internalclient.Response {
	snap, err := t.current(ctx)
	if err != nil {
		return &internalclient.Response{Status: status.Code(err), Err: err}
	}
	return &internalclient.Response{
		Status: codes.OK,
		GetLatestResult: &trillian.GetLatestSignedLogRootResponse{
			SignedLogRoot: snap.signed,
		},
	}
}

func (t *cachedTrillianClient) Close() {
	t.stop()
	t.wg.Wait()
}
