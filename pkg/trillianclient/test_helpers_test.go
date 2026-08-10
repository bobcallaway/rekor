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
	"fmt"
	"testing"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/merkle/rfc6962"
	inmemory "github.com/transparency-dev/merkle/testonly"
	"go.uber.org/goleak"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// grpcDialIgnores tolerates the transient TCP-dial goroutines that grpc spawns
// while establishing a connection (addrConn.connect -> net dialParallel/dialSerial).
// trillian's testonly.NewMockServer opens an eager grpc.Dial connection whose
// reconnect/dial goroutines can outlive its close by a few milliseconds; they
// always terminate once the dial context is canceled, so they are benign. This
// does not mask a real client leak: a leaked grpc client keeps persistent
// transport goroutines (loopyWriter, http2 reader) alive, which goleak still flags.
var grpcDialIgnores = []goleak.Option{
	goleak.IgnoreAnyFunction("net.(*sysDialer).dialParallel"),
	goleak.IgnoreAnyFunction("net.(*sysDialer).dialSerial"),
}

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m, grpcDialIgnores...)
}

// mkSLR builds a SignedLogRoot with the given tree size and root hash.
func mkSLR(t *testing.T, size uint64, rootHash []byte) *trillian.SignedLogRoot {
	t.Helper()
	lr := &types.LogRootV1{TreeSize: size, RootHash: rootHash}
	b, err := lr.MarshalBinary()
	require.NoError(t, err)
	return &trillian.SignedLogRoot{LogRoot: b}
}

// logTree is a real Merkle tree over deterministic leaves. fetchAndVerifyRoot
// proves every advance against the root it already trusts, so a test that moves
// the tree forward has to hand back genuine root hashes and a genuine
// consistency proof. Fabricating them and stubbing out the verifier instead
// would disable, in test, the exact check the verification exists to perform.
type logTree struct {
	t    *testing.T
	tree *inmemory.Tree
}

// newLogTree builds a tree of maxSize leaves; any size up to that can then be
// addressed, since HashAt and ConsistencyProof are both retrospective.
func newLogTree(t *testing.T, maxSize uint64) *logTree {
	t.Helper()
	tr := inmemory.New(rfc6962.DefaultHasher)
	for i := range maxSize {
		tr.AppendData(fmt.Appendf(nil, "leaf-%d", i))
	}
	return &logTree{t: t, tree: tr}
}

// root returns the root hash the tree had when it held size leaves.
func (lt *logTree) root(size uint64) []byte {
	lt.t.Helper()
	return lt.tree.HashAt(size)
}

// resp is a GetLatestSignedLogRoot reply advertising size `to`, carrying the
// consistency proof from `from` that Trillian returns when FirstTreeSize is set.
func (lt *logTree) resp(from, to uint64) *trillian.GetLatestSignedLogRootResponse {
	lt.t.Helper()
	p, err := lt.tree.ConsistencyProof(from, to)
	require.NoError(lt.t, err)
	return &trillian.GetLatestSignedLogRootResponse{
		SignedLogRoot: mkSLR(lt.t, to, lt.root(to)),
		Proof:         &trillian.Proof{Hashes: p},
	}
}

// staleStartedClient returns a client that is already "started" — so
// ensureStarted short-circuits, no init RPC is issued, and no updater runs —
// holding a root at the given size whose last corroboration is an hour old.
// Every RPC such a client makes is therefore a staleness refresh, which is what
// lets these tests assert exact call counts.
func staleStartedClient(t *testing.T, addr string, treeID int64, opts Options, size uint64, rootHash []byte) *cachedTrillianClient {
	t.Helper()
	tc := newCachedTrillianClient(trillian.NewTrillianLogClient(dialMock(t, addr)), treeID, opts)
	tc.started.Store(true)
	tc.snapshot.Store(rootSnapshot{root: types.LogRootV1{TreeSize: size, RootHash: rootHash}, signed: mkSLR(t, size, rootHash)})
	tc.lastRootFetch.Store(time.Now().Add(-time.Hour).UnixNano())
	t.Cleanup(tc.Close)
	return tc
}

// dialMock dials the given address with insecure credentials and registers a
// cleanup to close the connection when the test ends.
func dialMock(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
