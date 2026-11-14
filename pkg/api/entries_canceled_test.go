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
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/golang/mock/gomock"
	"github.com/google/trillian/testonly"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/entries"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/signer"
	"github.com/sigstore/rekor/pkg/trillianclient"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestUUIDLookupDistinguishesBackendAndCallerCancellation(t *testing.T) {
	ctl := gomock.NewController(t)
	s, closeServer, err := testonly.NewMockServer(ctl)
	require.NoError(t, err)
	defer closeServer()
	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(nil, status.Error(codes.Canceled, "backend canceled")).AnyTimes()
	_, portString, err := net.SplitHostPort(s.Addr)
	require.NoError(t, err)
	port, err := strconv.ParseUint(portString, 10, 16)
	require.NoError(t, err)
	manager := trillianclient.NewClientManager(nil, trillianclient.GRPCConfig{Address: "localhost", Port: uint16(port)})
	defer manager.Close()
	ranges, err := sharding.NewLogRanges(context.Background(), "", 1, signer.SigningConfig{SigningSchemeOrKeyPath: "memory"})
	require.NoError(t, err)
	previous := api
	t.Cleanup(func() { api = previous })
	api = &API{logRanges: ranges, trillianClientManager: manager}
	const uuid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, canceled := range []bool{false, true} {
		name := "live request"
		want := http.StatusInternalServerError
		if canceled {
			name = "caller canceled"
			want = 499
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if canceled {
				cancel()
			}
			_, err := retrieveUUIDFromTree(ctx, uuid, 1)
			require.Error(t, err)
			if canceled {
				require.ErrorIs(t, err, context.Canceled)
			} else {
				require.NotErrorIs(t, err, context.Canceled)
				require.NotErrorIs(t, err, ErrNotFound)
			}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/log/entries/"+uuid, nil).WithContext(ctx)
			recorder := httptest.NewRecorder()
			GetLogEntryByUUIDHandler(entries.GetLogEntryByUUIDParams{HTTPRequest: req, EntryUUID: uuid}).WriteResponse(recorder, runtime.JSONProducer())
			require.Equal(t, want, recorder.Code, recorder.Body.String())
		})
	}
}
