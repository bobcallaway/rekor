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
	// flag to indicate whether the client manager is shutting down
	shutdown atomic.Bool

	// treeIDToConfig maps a specific tree ID to its gRPC configuration.
	treeIDToConfig map[int64]GRPCConfig
	// defaultConfig is the global fallback configuration.
	defaultConfig GRPCConfig
	cache         *CacheConfig
}

// CacheConfig controls the optional signed-root cache.
type CacheConfig struct {
	PollInterval     time.Duration
	RootTimeout      time.Duration
	MaxRootAge       time.Duration
	MaxPending       int
	ProofConcurrency int
	FrozenTreeIDs    map[int64]struct{}
}

// NewClientManager creates a new ClientManager.
func NewClientManager(treeIDToConfig map[int64]GRPCConfig, defaultConfig GRPCConfig) *ClientManager {
	return newClientManager(treeIDToConfig, defaultConfig, nil)
}

// NewCachedClientManager creates a manager whose clients share background root
// updates. Callers must opt in explicitly; NewClientManager remains direct.
func NewCachedClientManager(treeIDToConfig map[int64]GRPCConfig, defaultConfig GRPCConfig, cache CacheConfig) *ClientManager {
	return newClientManager(treeIDToConfig, defaultConfig, &cache)
}

func newClientManager(treeIDToConfig map[int64]GRPCConfig, defaultConfig GRPCConfig, cache *CacheConfig) *ClientManager {
	var cacheCopy *CacheConfig
	if cache != nil {
		copy := *cache
		copy.FrozenTreeIDs = maps.Clone(cache.FrozenTreeIDs)
		cacheCopy = &copy
	}
	return &ClientManager{
		connections:     make(map[GRPCConfig]*grpc.ClientConn),
		treeIDToConfig:  maps.Clone(treeIDToConfig),
		defaultConfig:   defaultConfig,
		trillianClients: make(map[int64]internalclient.Client),
		cache:           cacheCopy,
	}
}

// getConn finds the correct gRPC config for a tree ID, then dials or retrieves a cached connection.
func (cm *ClientManager) getConn(treeID int64) (*grpc.ClientConn, error) {
	if cm.shutdown.Load() {
		return nil, errors.New("client manager is shutting down")
	}
	// Determine the correct GRPCConfig for this treeID.
	config, ok := cm.treeIDToConfig[treeID]
	if !ok {
		// If no specific config exists, fall back to the global default.
		config = cm.defaultConfig
	}

	cm.connMu.RLock()
	conn, ok := cm.connections[config]
	cm.connMu.RUnlock()
	if ok {
		return conn, nil
	}

	cm.connMu.Lock()
	defer cm.connMu.Unlock()
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

// GetClient returns a Rekor Trillian client wrapper for the given tree ID.
func (cm *ClientManager) GetClient(treeID int64) (internalclient.Client, error) {
	if cm.shutdown.Load() {
		return nil, errors.New("client manager is shutting down")
	}
	cm.clientMu.RLock()
	c, ok := cm.trillianClients[treeID]
	cm.clientMu.RUnlock()
	if ok {
		if cm.shutdown.Load() {
			return nil, errors.New("client manager is shutting down")
		}
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

	logClient := trillian.NewTrillianLogClient(conn)
	var newClient internalclient.Client = newDirectTrillianClient(logClient, treeID)
	if cm.cache != nil {
		_, frozen := cm.cache.FrozenTreeIDs[treeID]
		newClient = newCachedTrillianClient(logClient, treeID, cacheOptions{
			pollInterval:     cm.cache.PollInterval,
			rootTimeout:      cm.cache.RootTimeout,
			maxRootAge:       cm.cache.MaxRootAge,
			maxPending:       cm.cache.MaxPending,
			proofConcurrency: cm.cache.ProofConcurrency,
			frozen:           frozen,
		})
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
	if cm.shutdown.Swap(true) {
		return nil
	}
	var err error

	// Clear and stop clients before closing their underlying connections.
	cm.clientMu.Lock()
	clients := cm.trillianClients
	cm.trillianClients = make(map[int64]internalclient.Client)
	cm.clientMu.Unlock()
	for _, client := range clients {
		client.Close()
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
