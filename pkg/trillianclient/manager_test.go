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
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/trillian"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestCleanDialHostname(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "dns:/// scheme is stripped",
			input: "dns:///trillian-logserver.ns.svc",
			want:  "trillian-logserver.ns.svc",
		},
		{
			name:  "plain hostname is unchanged",
			input: "trillian-logserver.ns.svc",
			want:  "trillian-logserver.ns.svc",
		},
		{
			name:  "localhost is unchanged",
			input: "localhost",
			want:  "localhost",
		},
		{
			name:  "dns:/// with port is stripped correctly",
			input: "dns:///trillian-logserver.ns.svc:8091",
			want:  "trillian-logserver.ns.svc:8091",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanDialHostname(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCachedClientManagerIsExplicit(t *testing.T) {
	s, _ := newMockLog(t)
	host, portString, err := net.SplitHostPort(s.Addr)
	require.NoError(t, err)
	port, err := strconv.ParseUint(portString, 10, 16)
	require.NoError(t, err)
	config := GRPCConfig{Address: host, Port: uint16(port)}

	s.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(
		&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: mkSLR(t, 1, make([]byte, 32))}, nil,
	).Times(1)

	directManager := NewClientManager(nil, config)
	direct, err := directManager.GetClient(42)
	require.NoError(t, err)
	_, ok := direct.(*directTrillianClient)
	require.True(t, ok)
	require.NoError(t, directManager.Close())

	cachedManager := NewCachedClientManager(nil, config, CacheConfig{
		PollInterval:  time.Hour,
		FrozenTreeIDs: map[int64]struct{}{42: {}},
	})
	cached, err := cachedManager.GetClient(42)
	require.NoError(t, err)
	_, ok = cached.(*cachedTrillianClient)
	require.True(t, ok)
	require.Equal(t, codes.OK, cached.GetLatest(context.Background()).Status)
	require.NoError(t, cachedManager.Close())
}
