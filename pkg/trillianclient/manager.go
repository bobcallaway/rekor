//
// Copyright 2025 The Sigstore Authors.
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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	internalclient "github.com/sigstore/rekor/internal/trillianclient"
	"github.com/sigstore/rekor/pkg/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/durationpb"
)

// Options bundles all inputs for constructing a ClientManager.
type Options struct {
	// DefaultGRPC is the transport config used for any tree not listed in
	// PerTreeGRPC. Required.
	DefaultGRPC GRPCConfig
	// PerTreeGRPC maps specific tree IDs to their own transport config. Trees
	// absent from this map fall back to DefaultGRPC. Optional; may be nil.
	PerTreeGRPC map[int64]GRPCConfig

	// CacheSTH enables the cached STH client with a background updater
	// (experimental). When false, a stateless per-RPC client is used and the
	// remaining cache-related fields below are ignored.
	CacheSTH bool
	// RootRPCTimeout bounds each GetLatestSignedLogRoot RPC issued by a cached
	// client: initialization, every background updater poll, and every on-demand
	// refresh. Zero means DefaultRootRPCTimeout.
	RootRPCTimeout time.Duration
	// PollInterval is the steady cadence at which each cached client's
	// background updater fetches the latest root, and also the minimum spacing
	// between on-demand refreshes and between initialization attempts. Zero
	// means DefaultPollInterval; values below MinPollInterval are clamped.
	PollInterval time.Duration
	// MaxSTHStaleness is how long an active cached root may go uncorroborated
	// before reads stop serving it from cache and attempt a synchronous refresh,
	// returning Unavailable if that does not restore freshness. Zero derives
	// three poll intervals plus RootRPCTimeout, which is under four seconds at
	// the defaults — see successfulRootFetchMaxPollIntervals for why the bound
	// is deliberately tight and what raising it costs.
	//
	// The bound applies to every path that serves the cached root or signs a
	// proof against it: GetLatest, both leaf-and-proof lookups, and AddLeaf.
	MaxSTHStaleness time.Duration
	// FrozenTreeIDs is the set of tree IDs for frozen (inactive) shards. Cached
	// clients for these trees fetch the root once and never start a background
	// updater.
	FrozenTreeIDs map[int64]struct{}
}

// ClientManager creates and caches Trillian clients and their underlying gRPC connections.
type ClientManager struct {
	// Mutex for connections map
	connMu sync.RWMutex
	// connections maps a specific gRPC configuration to a shared connection pool.
	connections map[GRPCConfig]*grpc.ClientConn

	// Mutex for trillianClients map
	clientMu sync.RWMutex
	// trillianClients caches the client wrappers.
	trillianClients map[int64]internalclient.Client
	// shutdown is atomic rather than guarded by clientMu so getConn can check it
	// while holding connMu without introducing a lock-ordering dependency
	// between the two mutexes.
	shutdown atomic.Bool

	// opts holds the construction input. Its map fields are shallow-copied
	// by NewClientManager so the manager owns them independently of the caller.
	opts Options
}

// NewClientManager creates a new ClientManager from the given Options. The map
// fields on opts (PerTreeGRPC, FrozenTreeIDs) are shallow-copied because
// getConn reads PerTreeGRPC without a lock: a caller that retained and later
// mutated the map it passed in would be a data race, not merely a surprise.
func NewClientManager(opts Options) *ClientManager {
	perTree := make(map[int64]GRPCConfig, len(opts.PerTreeGRPC))
	maps.Copy(perTree, opts.PerTreeGRPC)
	opts.PerTreeGRPC = perTree

	frozen := make(map[int64]struct{}, len(opts.FrozenTreeIDs))
	maps.Copy(frozen, opts.FrozenTreeIDs)
	opts.FrozenTreeIDs = frozen

	return &ClientManager{
		connections:     make(map[GRPCConfig]*grpc.ClientConn),
		trillianClients: make(map[int64]internalclient.Client),
		opts:            opts,
	}
}

// getConn finds the correct gRPC config for a tree ID, then dials or retrieves a cached connection.
func (cm *ClientManager) getConn(treeID int64) (*grpc.ClientConn, error) {
	// Determine the correct GRPCConfig for this treeID.
	config, ok := cm.opts.PerTreeGRPC[treeID]
	if !ok {
		// If no specific config exists, fall back to the global default.
		config = cm.opts.DefaultGRPC
	}

	cm.connMu.RLock()
	conn, ok := cm.connections[config]
	cm.connMu.RUnlock()
	if ok {
		return conn, nil
	}

	if cm.shutdown.Load() {
		return nil, errors.New("client manager is shutting down")
	}

	cm.connMu.Lock()
	defer cm.connMu.Unlock()

	// Re-check shutdown after acquiring connMu. Close() may have run
	// between the early check and here, draining all connections.
	if cm.shutdown.Load() {
		return nil, errors.New("client manager is shutting down")
	}

	// Double-check after acquiring the write lock.
	conn, ok = cm.connections[config]
	if ok {
		return conn, nil
	}

	// Dial and cache the new connection.
	newConn, err := dial(config.Address, config.Port, config.TLSCACert, config.UseSystemTrustStore, config.GRPCServiceConfig)
	if err != nil {
		return nil, err
	}
	cm.connections[config] = newConn
	return newConn, nil
}

// GetClient returns the client for treeID, creating it if necessary. When
// CacheSTH is enabled it returns a cached STH client; otherwise a simple
// per-RPC client.
func (cm *ClientManager) GetClient(treeID int64) (internalclient.Client, error) {
	if cm.shutdown.Load() {
		return nil, errors.New("client manager is shutting down")
	}

	cm.clientMu.RLock()
	c, ok := cm.trillianClients[treeID]
	cm.clientMu.RUnlock()
	if ok {
		return c, nil
	}

	conn, err := cm.getConn(treeID)
	if err != nil {
		return nil, err
	}

	cm.clientMu.Lock()
	defer cm.clientMu.Unlock()
	// Double-check after acquiring the write lock.
	if cm.shutdown.Load() {
		return nil, errors.New("client manager is shutting down")
	}
	if c, ok = cm.trillianClients[treeID]; ok {
		return c, nil
	}

	var newClient internalclient.Client
	if cm.opts.CacheSTH {
		newClient = newCachedTrillianClient(trillian.NewTrillianLogClient(conn), treeID, cm.opts)
	} else {
		newClient = newDirectTrillianClient(trillian.NewTrillianLogClient(conn), treeID)
	}
	cm.trillianClients[treeID] = newClient
	return newClient, nil
}

func CreateAndInitTree(ctx context.Context, config GRPCConfig) (*trillian.Tree, error) {
	newConn, err := dial(config.Address, config.Port, config.TLSCACert, config.UseSystemTrustStore, config.GRPCServiceConfig)
	if err != nil {
		return nil, err
	}
	adminClient := trillian.NewTrillianAdminClient(newConn)

	t, err := adminClient.CreateTree(ctx, &trillian.CreateTreeRequest{
		Tree: &trillian.Tree{
			TreeType:        trillian.TreeType_LOG,
			TreeState:       trillian.TreeState_ACTIVE,
			MaxRootDuration: durationpb.New(time.Hour),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create tree: %w", err)
	}
	logClient := trillian.NewTrillianLogClient(newConn)

	if err := client.InitLog(ctx, t, logClient); err != nil {
		return nil, fmt.Errorf("init log: %w", err)
	}
	log.Logger.Infof("Created new tree with ID: %v", t.TreeId)
	return t, nil
}

// cleanDialHostname strips gRPC resolver scheme prefixes (e.g. "dns:///")
// from a hostname, returning the bare hostname suitable for TLS SNI and
// certificate verification. The original address with its scheme must be
// preserved for the grpc.NewClient target so the chosen resolver stays active.
func cleanDialHostname(hostname string) string {
	return strings.TrimPrefix(hostname, "dns:///")
}

func dial(hostname string, port uint16, tlsCACertFile string, useSystemTrustStore bool, serviceConfig string) (*grpc.ClientConn, error) {
	// Strip gRPC resolver scheme before TLS: if hostname is e.g.
	// "dns:///host.svc", passing it raw into tls.Config.ServerName causes
	// x509 verification to fail with `certificate valid for host.svc, not dns`.
	cleanHostname := cleanDialHostname(hostname)

	var creds credentials.TransportCredentials
	switch {
	case useSystemTrustStore:
		creds = credentials.NewTLS(&tls.Config{
			ServerName: cleanHostname,
			MinVersion: tls.VersionTLS12,
		})
	case tlsCACertFile != "":
		tlsCaCert, err := os.ReadFile(filepath.Clean(tlsCACertFile))
		if err != nil {
			return nil, fmt.Errorf("failed to load tls_ca_cert: %w", err)
		}
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(tlsCaCert) {
			return nil, fmt.Errorf("failed to append CA certificate to pool")
		}
		creds = credentials.NewTLS(&tls.Config{
			ServerName: cleanHostname,
			RootCAs:    certPool,
			MinVersion: tls.VersionTLS12,
		})
	default:
		creds = insecure.NewCredentials()
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithAuthority(cleanHostname),
	}

	if serviceConfig != "" {
		opts = append(opts, grpc.WithDefaultServiceConfig(serviceConfig))
	}
	// hostname (not cleanHostname) is intentional: the dns:/// scheme must
	// reach grpc.NewClient so gRPC uses the DNS resolver for client-side
	// load balancing. TLS and authority are handled separately above.
	conn, err := grpc.NewClient(fmt.Sprintf("%s:%d", hostname, port), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RPC server: %w", err)
	}

	return conn, nil
}

// Close stops clients and closes underlying gRPC connections.
func (cm *ClientManager) Close() error {
	var err error

	cm.shutdown.Store(true)

	cm.clientMu.Lock()
	oldClients := cm.trillianClients
	cm.trillianClients = make(map[int64]internalclient.Client)
	cm.clientMu.Unlock()

	// Close clients before connections so cached-client updater goroutines exit
	// cleanly via bgCancel/stopCh rather than seeing connection-closed errors
	// mid-RPC. Done outside locks since Close may block on wg.Wait().
	for _, c := range oldClients {
		c.Close()
	}

	cm.connMu.Lock()
	for cfg, conn := range cm.connections {
		if closeErr := conn.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close conn %v:%d: %w", cfg.Address, cfg.Port, closeErr))
		}
		delete(cm.connections, cfg)
	}
	cm.connMu.Unlock()
	return err
}
