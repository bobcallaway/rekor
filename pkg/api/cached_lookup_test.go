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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/google/trillian"
	trilliantypes "github.com/google/trillian/types"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/entries"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/signer"
	"github.com/sigstore/rekor/pkg/trillianclient"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type shardLog struct {
	leaves     [][]byte
	leafHashes [][]byte
	roots      [][]byte
	hashes     map[compact.NodeID][]byte
	size       uint64
}

func newShardLog(t *testing.T, payloads ...[]byte) *shardLog {
	t.Helper()
	s := &shardLog{
		leaves:     make([][]byte, len(payloads)),
		leafHashes: make([][]byte, len(payloads)),
		roots:      make([][]byte, len(payloads)+1),
		hashes:     make(map[compact.NodeID][]byte),
		size:       uint64(len(payloads)),
	}
	r := (&compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}).NewEmptyRange(0)
	s.roots[0] = rfc6962.DefaultHasher.EmptyRoot()
	for i, p := range payloads {
		s.leaves[i] = p
		s.leafHashes[i] = rfc6962.DefaultHasher.HashLeaf(p)
		require.NoError(t, r.Append(s.leafHashes[i], func(id compact.NodeID, h []byte) {
			s.hashes[id] = h
		}))
		root, err := r.GetRootHash(nil)
		require.NoError(t, err)
		s.roots[i+1] = root
	}
	return s
}

func (s *shardLog) nodeHashes(t *testing.T, nodes proof.Nodes) [][]byte {
	t.Helper()
	out := make([][]byte, len(nodes.IDs))
	for i, id := range nodes.IDs {
		out[i] = s.hashes[id]
	}
	h, err := nodes.Rehash(out, rfc6962.DefaultHasher.HashChildren)
	require.NoError(t, err)
	return h
}

func (s *shardLog) signedRoot(t *testing.T, size uint64) *trillian.SignedLogRoot {
	t.Helper()
	encoded, err := (&trilliantypes.LogRootV1{TreeSize: size, RootHash: s.roots[size]}).MarshalBinary()
	require.NoError(t, err)
	return &trillian.SignedLogRoot{LogRoot: encoded}
}

func (s *shardLog) inclusion(t *testing.T, idx, size uint64) [][]byte {
	t.Helper()
	nodes, err := proof.Inclusion(idx, size)
	require.NoError(t, err)
	return s.nodeHashes(t, nodes)
}

func (s *shardLog) consistency(t *testing.T, from, to uint64) [][]byte {
	t.Helper()
	if from == 0 || from == to {
		return nil
	}
	nodes, err := proof.Consistency(from, to)
	require.NoError(t, err)
	return s.nodeHashes(t, nodes)
}

func (s *shardLog) leaf(idx int) *trillian.LogLeaf {
	return &trillian.LogLeaf{
		LeafValue:          s.leaves[idx],
		MerkleLeafHash:     s.leafHashes[idx],
		LeafIndex:          int64(idx),
		IntegrateTimestamp: timestamppb.New(time.Unix(1700000000, 0)),
	}
}

type multiShardTrillianServer struct {
	trillian.UnimplementedTrillianLogServer
	t      *testing.T
	mu     sync.Mutex
	shards map[int64]*shardLog

	latestCalls    map[int64]*atomic.Int32
	inclusionCalls map[int64]*atomic.Int32
	onInclusion    func(logID int64, treeSize int64, hash []byte)
}

func newMultiShardTrillianServer(t *testing.T, shards map[int64]*shardLog) *multiShardTrillianServer {
	t.Helper()
	latestCalls := make(map[int64]*atomic.Int32, len(shards))
	inclusionCalls := make(map[int64]*atomic.Int32, len(shards))
	for id := range shards {
		latestCalls[id] = &atomic.Int32{}
		inclusionCalls[id] = &atomic.Int32{}
	}
	return &multiShardTrillianServer{
		t:              t,
		shards:         shards,
		latestCalls:    latestCalls,
		inclusionCalls: inclusionCalls,
	}
}

func (s *multiShardTrillianServer) setSize(treeID int64, size uint64) {
	s.mu.Lock()
	s.shards[treeID].size = size
	s.mu.Unlock()
}

func (s *multiShardTrillianServer) GetLatestSignedLogRoot(_ context.Context, req *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
	s.latestCalls[req.LogId].Add(1)
	s.mu.Lock()
	shard := s.shards[req.LogId]
	size := shard.size
	s.mu.Unlock()
	resp := &trillian.GetLatestSignedLogRootResponse{
		SignedLogRoot: shard.signedRoot(s.t, size),
	}
	if req.FirstTreeSize > 0 && uint64(req.FirstTreeSize) < size { //nolint:gosec
		resp.Proof = &trillian.Proof{Hashes: shard.consistency(s.t, uint64(req.FirstTreeSize), size)} //nolint:gosec
	}
	return resp, nil
}

func (s *multiShardTrillianServer) GetInclusionProofByHash(_ context.Context, req *trillian.GetInclusionProofByHashRequest) (*trillian.GetInclusionProofByHashResponse, error) {
	s.inclusionCalls[req.LogId].Add(1)
	if s.onInclusion != nil {
		s.onInclusion(req.LogId, req.TreeSize, req.LeafHash)
	}
	s.mu.Lock()
	shard := s.shards[req.LogId]
	s.mu.Unlock()
	for i := range int(req.TreeSize) {
		if string(shard.leafHashes[i]) == string(req.LeafHash) {
			return &trillian.GetInclusionProofByHashResponse{
				SignedLogRoot: shard.signedRoot(s.t, uint64(req.TreeSize)), //nolint:gosec
				Proof:         []*trillian.Proof{{LeafIndex: int64(i), Hashes: shard.inclusion(s.t, uint64(i), uint64(req.TreeSize))}}, //nolint:gosec
			}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "leaf not found")
}

func (s *multiShardTrillianServer) GetLeavesByRange(_ context.Context, req *trillian.GetLeavesByRangeRequest) (*trillian.GetLeavesByRangeResponse, error) {
	s.mu.Lock()
	shard := s.shards[req.LogId]
	size := shard.size
	s.mu.Unlock()
	if req.StartIndex < 0 || uint64(req.StartIndex) >= size { //nolint:gosec
		return &trillian.GetLeavesByRangeResponse{}, nil
	}
	return &trillian.GetLeavesByRangeResponse{
		Leaves: []*trillian.LogLeaf{shard.leaf(int(req.StartIndex))},
	}, nil
}

func (s *multiShardTrillianServer) GetEntryAndProof(_ context.Context, req *trillian.GetEntryAndProofRequest) (*trillian.GetEntryAndProofResponse, error) {
	s.mu.Lock()
	shard := s.shards[req.LogId]
	s.mu.Unlock()
	if req.LeafIndex < 0 || req.LeafIndex >= req.TreeSize {
		return nil, status.Error(codes.OutOfRange, "index out of range")
	}
	return &trillian.GetEntryAndProofResponse{
		SignedLogRoot: shard.signedRoot(s.t, uint64(req.TreeSize)), //nolint:gosec
		Proof:         &trillian.Proof{LeafIndex: req.LeafIndex, Hashes: shard.inclusion(s.t, uint64(req.LeafIndex), uint64(req.TreeSize))}, //nolint:gosec
		Leaf:          shard.leaf(int(req.LeafIndex)),
	}, nil
}

func setupShardedCachedAPI(t *testing.T, activeID, inactiveID int64, activeShard, inactiveShard *shardLog, pollInterval time.Duration) *multiShardTrillianServer {
	t.Helper()
	shards := map[int64]*shardLog{activeID: activeShard}
	var inactiveCfgPath string
	frozen := map[int64]struct{}{}
	if inactiveShard != nil {
		shards[inactiveID] = inactiveShard
		frozen[inactiveID] = struct{}{}
		inactiveCfgPath = filepath.Join(t.TempDir(), "sharding.yaml")
		cfg := fmt.Sprintf("- treeID: %d\n  treeLength: %d\n", inactiveID, inactiveShard.size)
		require.NoError(t, os.WriteFile(inactiveCfgPath, []byte(cfg), 0o600))
	}

	srv := newMultiShardTrillianServer(t, shards)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	grpcServer := grpc.NewServer()
	trillian.RegisterTrillianLogServer(grpcServer, srv)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)

	host, portString, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.ParseUint(portString, 10, 16)
	require.NoError(t, err)

	manager := trillianclient.NewCachedClientManager(nil, trillianclient.GRPCConfig{Address: host, Port: uint16(port)}, trillianclient.CacheConfig{
		PollInterval:  pollInterval,
		MaxRootAge:    10 * time.Second,
		FrozenTreeIDs: frozen,
	})
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	ranges, err := sharding.NewLogRanges(context.Background(), inactiveCfgPath, activeID, signer.SigningConfig{SigningSchemeOrKeyPath: "memory"})
	require.NoError(t, err)
	roots, err := ranges.CompleteInitialization(context.Background(), manager)
	require.NoError(t, err)

	cachedCheckpoints := make(map[int64]string)
	for _, r := range ranges.GetInactive() {
		cp, err := util.CreateAndSignCheckpoint(context.Background(), "rekor.test", r.TreeID, uint64(r.TreeLength), roots[r.TreeID].RootHash, r.Signer) //nolint:gosec
		require.NoError(t, err)
		cachedCheckpoints[r.TreeID] = string(cp)
	}

	// Prime the active client's initial root so tests control subsequent polls.
	activeClient, err := manager.GetClient(activeID)
	require.NoError(t, err)
	require.Equal(t, codes.OK, activeClient.GetLatest(context.Background()).Status)

	previous := api
	api = &API{
		trillianClientManager: manager,
		logRanges:             ranges,
		checkpointCache:       newCheckpointCache(16, 0, 0),
		cachedCheckpoints:     cachedCheckpoints,
		checkpointHostname:    "rekor.test",
	}
	t.Cleanup(func() {
		api.checkpointCache.close()
		api = previous
	})
	return srv
}

func TestPlainUUIDInactiveShardAvoidsActiveRefresh(t *testing.T) {
	const (
		inactiveID int64 = 48001
		activeID   int64 = 48002
	)
	inactiveShard := newShardLog(t, []byte(`{"kind":"inactive-entry"}`))
	activeShard := newShardLog(t, []byte(`{"kind":"active-entry"}`))
	// Long poll interval: waiting for a refresh would exceed the 500ms request deadline.
	srv := setupShardedCachedAPI(t, activeID, inactiveID, activeShard, inactiveShard, 2*time.Second)

	inactiveUUID := hex.EncodeToString(inactiveShard.leafHashes[0])
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/log/entries/"+inactiveUUID, nil).WithContext(ctx)
	resp := GetLogEntryByUUIDHandler(entries.GetLogEntryByUUIDParams{HTTPRequest: req, EntryUUID: inactiveUUID})

	recorder := httptest.NewRecorder()
	resp.WriteResponse(recorder, runtime.JSONProducer())
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.EqualValues(t, 1, srv.inclusionCalls[activeID].Load(), "active shard should only be probed once without refresh")
	require.EqualValues(t, 1, srv.inclusionCalls[inactiveID].Load())
}

func TestPlainUUIDActiveShardRefreshesOnRecentWrite(t *testing.T) {
	const (
		inactiveID int64 = 48003
		activeID   int64 = 48004
	)
	inactiveShard := newShardLog(t, []byte(`{"kind":"inactive-entry"}`))
	activeShard := newShardLog(t, []byte(`{"kind":"active-0"}`), []byte(`{"kind":"active-1"}`))
	activeShard.size = 1 // Expose only leaf 0 initially.
	srv := setupShardedCachedAPI(t, activeID, inactiveID, activeShard, inactiveShard, 20*time.Millisecond)

	// Reveal leaf 1 as soon as the initial fast probe misses.
	srv.onInclusion = func(logID int64, _ int64, _ []byte) {
		if logID == activeID {
			srv.setSize(activeID, 2)
		}
	}

	recentUUID := hex.EncodeToString(activeShard.leafHashes[1])
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/log/entries/"+recentUUID, nil).WithContext(ctx)
	resp := GetLogEntryByUUIDHandler(entries.GetLogEntryByUUIDParams{HTTPRequest: req, EntryUUID: recentUUID})

	recorder := httptest.NewRecorder()
	resp.WriteResponse(recorder, runtime.JSONProducer())
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	var got models.LogEntry
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &got))
	expectedEntryID := fmt.Sprintf("%016x%s", activeID, recentUUID)
	require.Contains(t, got, expectedEntryID)
}

func TestSearchLogQueryCoalescesActiveRefresh(t *testing.T) {
	const (
		inactiveID int64 = 48005
		activeID   int64 = 48006
	)
	inactiveShard := newShardLog(t, []byte(`{"kind":"inactive-0"}`))
	activeShard := newShardLog(t,
		[]byte(`{"kind":"active-0"}`),
		[]byte(`{"kind":"active-1"}`),
		[]byte(`{"kind":"active-2"}`),
		[]byte(`{"kind":"active-3"}`),
	)
	activeShard.size = 1 // Expose only leaf 0 initially.
	// Use a 150ms poll interval: 5 sequential refreshes would take >= 750ms,
	// whereas a single coalesced refresh finishes well under 450ms.
	srv := setupShardedCachedAPI(t, activeID, inactiveID, activeShard, inactiveShard, 150*time.Millisecond)

	// After the first fast-pass probe hits active, reveal leaves 1..3 before the single refresh poll.
	var revealed atomic.Bool
	srv.onInclusion = func(logID int64, _ int64, _ []byte) {
		if logID == activeID && revealed.CompareAndSwap(false, true) {
			srv.setSize(activeID, 4)
		}
	}

	entryID1 := fmt.Sprintf("%016x%s", activeID, hex.EncodeToString(activeShard.leafHashes[1]))
	plainUUID2 := hex.EncodeToString(activeShard.leafHashes[2])
	absentEntryID := fmt.Sprintf("%016x%s", activeID, hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf([]byte("missing-a"))))
	absentPlainUUID := hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf([]byte("missing-b")))
	// Virtual index 4 = 1 (inactive) + 3 (active leaf 3).
	idx3 := int64(4)
	absentIdx := int64(99)

	pollsBefore := srv.latestCalls[activeID].Load()
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/log/entries/retrieve", nil).WithContext(ctx)
	resp := SearchLogQueryHandler(entries.SearchLogQueryParams{
		HTTPRequest: req,
		Entry: &models.SearchLogQuery{
			EntryUUIDs: []string{entryID1, plainUUID2, absentEntryID, absentPlainUUID},
			LogIndexes: []*int64{&idx3, &absentIdx},
		},
	})

	recorder := httptest.NewRecorder()
	resp.WriteResponse(recorder, runtime.JSONProducer())
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

	var payload []models.LogEntry
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
	found := make(map[string]struct{}, len(payload))
	for _, entry := range payload {
		for id := range entry {
			found[id] = struct{}{}
		}
	}
	require.Contains(t, found, entryID1)
	require.Contains(t, found, fmt.Sprintf("%016x%s", activeID, plainUUID2))
	require.Contains(t, found, fmt.Sprintf("%016x%s", activeID, hex.EncodeToString(activeShard.leafHashes[3])))
	require.Len(t, found, 3)

	// At most 2 polls can overlap (an in-flight poll plus the single nextPoll wait),
	// nowhere near 6 sequential polls for the 6 missed queries.
	pollsDelta := srv.latestCalls[activeID].Load() - pollsBefore
	require.LessOrEqual(t, pollsDelta, int32(2), "expected a single coalesced root refresh across all misses")
}
