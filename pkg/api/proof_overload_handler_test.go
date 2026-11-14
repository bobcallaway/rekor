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
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/google/trillian"
	trilliantypes "github.com/google/trillian/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/entries"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/signer"
	"github.com/sigstore/rekor/pkg/trillianclient"
	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

type blockedProofServer struct {
	trillian.UnimplementedTrillianLogServer
	root *trillian.SignedLogRoot
}

func (s *blockedProofServer) GetLatestSignedLogRoot(context.Context, *trillian.GetLatestSignedLogRootRequest) (*trillian.GetLatestSignedLogRootResponse, error) {
	return &trillian.GetLatestSignedLogRootResponse{SignedLogRoot: s.root}, nil
}

func (*blockedProofServer) GetInclusionProofByHash(ctx context.Context, _ *trillian.GetInclusionProofByHashRequest) (*trillian.GetInclusionProofByHashResponse, error) {
	<-ctx.Done()
	return nil, status.FromContextError(ctx.Err()).Err()
}

// Exercise admission through the real cached client, retrieval helpers and API
// handlers. Calling handleRekorAPIError directly misses error identity lost by
// the intermediate UUID and search paths.
func TestProofOverloadThroughReadHandlers(t *testing.T) {
	const treeID int64 = 47002
	hash := rfc6962.DefaultHasher.HashLeaf([]byte("test leaf"))
	root := trilliantypes.LogRootV1{TreeSize: 1, RootHash: hash}
	encoded, err := root.MarshalBinary()
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	trillian.RegisterTrillianLogServer(server, &blockedProofServer{root: &trillian.SignedLogRoot{LogRoot: encoded}})
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	host, portString, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.ParseUint(portString, 10, 16)
	require.NoError(t, err)
	manager := trillianclient.NewCachedClientManager(nil, trillianclient.GRPCConfig{Address: host, Port: uint16(port)}, trillianclient.CacheConfig{
		ProofConcurrency: 1, MaxProofWaiters: 1, FrozenTreeIDs: map[int64]struct{}{treeID: {}},
	})
	defer func() { require.NoError(t, manager.Close()) }()
	ranges, err := sharding.NewLogRanges(context.Background(), "", treeID, signer.SigningConfig{SigningSchemeOrKeyPath: "memory"})
	require.NoError(t, err)
	previous := api
	api = &API{logRanges: ranges, trillianClientManager: manager}
	defer func() { api = previous }()
	client, err := manager.GetClient(treeID)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	require.NoError(t, client.GetLatest(ctx).Err)
	for range 2 {
		wg.Go(func() { client.GetLeafAndProofByHash(ctx, hash) })
	}
	require.Eventually(t, func() bool {
		families, err := prometheus.DefaultGatherer.Gather()
		if err != nil {
			return false
		}
		for _, family := range families {
			if family.GetName() != "rekor_trillian_proof_waiters" {
				continue
			}
			for _, metric := range family.Metric {
				for _, label := range metric.Label {
					if label.GetName() == "tree_id" && label.GetValue() == strconv.FormatInt(treeID, 10) && metric.GetGauge().GetValue() == 1 {
						return true
					}
				}
			}
		}
		return false
	}, time.Second, time.Millisecond)
	uuid := hex.EncodeToString(hash)
	entryID := fmt.Sprintf("%016x%s", treeID, uuid)
	for _, test := range []struct {
		name, id string
		search   bool
	}{
		{"lookup-entry-id", entryID, false}, {"lookup-uuid", uuid, false},
		{"search-entry-id", entryID, true}, {"search-uuid", uuid, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/log/entries", nil).WithContext(ctx)
			var response middleware.Responder
			if test.search {
				response = SearchLogQueryHandler(entries.SearchLogQueryParams{HTTPRequest: req, Entry: &models.SearchLogQuery{EntryUUIDs: []string{test.id}}})
			} else {
				response = GetLogEntryByUUIDHandler(entries.GetLogEntryByUUIDParams{HTTPRequest: req, EntryUUID: test.id})
			}
			recorder := httptest.NewRecorder()
			response.WriteResponse(recorder, runtime.JSONProducer())
			require.Equal(t, http.StatusServiceUnavailable, recorder.Code, recorder.Body.String())
			require.Equal(t, "1", recorder.Header().Get("Retry-After"))
		})
	}
}
