// Copyright 2023 The Sigstore Authors.
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

package mysql

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jmoiron/sqlx"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sigstore/rekor/pkg/log"
	"google.golang.org/api/support/bundler"

	// this imports the mysql driver for go
	_ "github.com/go-sql-driver/mysql"
)

const (
	ProviderType = "mysql"

	lookupStmt      = "SELECT EntryUUID FROM EntryIndex WHERE EntryKey IN (?)"
	writeStmt       = "INSERT IGNORE INTO EntryIndex (EntryKey, EntryUUID) VALUES (:key, :uuid)"
	createTableStmt = `CREATE TABLE IF NOT EXISTS EntryIndex (
		EntryKey varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
		EntryUUID char(80) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
		PRIMARY KEY(EntryKey, EntryUUID)
	)`

	// EntryKey's varchar(512) counts characters, not bytes. INSERT IGNORE downgrades a
	// too-long value to a warning and truncates it, storing a row no lookup can ever
	// match, so oversized keys are dropped before they reach the database.
	maxEntryKeyChars = 512

	// index writes are coalesced across entries so a burst of uploads costs a few wide
	// INSERTs instead of one per entry. The delay bounds how long a key stays unsearchable.
	bundleDelay = 250 * time.Millisecond
	bundleCount = 100

	// the write pool is unlimited by default, in which case the bundler would otherwise
	// fall back to its own default of 1 and serialize every index write.
	defaultHandlerLimit = 8

	// backpressure ceiling: Add fails once this many bytes of keys are buffered, so a
	// MySQL outage surfaces as an error instead of growing the heap without bound.
	bufferedByteLimit = 32 << 20

	// a bundle carries at most bundleCount rows and does not inherit the caller's deadline,
	// so this only needs to cover one wide INSERT.
	bundleWriteTimeout = 5 * time.Second

	// ceiling on the shutdown drain, chosen to leave the rest of StopAPI room inside a
	// typical 30s container termination grace period.
	shutdownDrainTimeout = 10 * time.Second
)

// IndexStorageProvider implements indexstorage.IndexStorage
//
// Reads and writes use independent connection pools against the same DSN.
// LookupIndices runs synchronously in the HTTP request path while WriteIndex only
// buffers, leaving the insert to a bundler goroutine, so a shared pool would let a
// burst of writes queue ahead of every read. database/sql wakes a uniformly random
// waiter rather than the longest-waiting one, so reads cannot be prioritized
// within a pool no matter how large it is.
type IndexStorageProvider struct {
	readDB      *sqlx.DB
	writeDB     *sqlx.DB
	collector   *dbStatsCollector
	bundler     *bundler.Bundler
	bundlerOnce sync.Once
	batchDelay  time.Duration
}

// indexEntry is one row of writeStmt; the tags name writeStmt's bind parameters.
type indexEntry struct {
	Key  string `db:"key"`
	UUID string `db:"uuid"`
}

func (e indexEntry) size() int { return len(e.Key) + len(e.UUID) }

func NewProvider(dsn string, opts ...Options) (*IndexStorageProvider, error) {
	provider := &IndexStorageProvider{}
	for _, o := range opts {
		o.applyBatchDelay(&provider.batchDelay)
	}

	readDB, err := openPool(dsn, poolRead, opts)
	if err != nil {
		return nil, err
	}
	provider.readDB = readDB

	writeDB, err := openPool(dsn, poolWrite, opts)
	if err != nil {
		return nil, errors.Join(err, readDB.Close())
	}
	provider.writeDB = writeDB

	if _, err := provider.writeDB.Exec(createTableStmt); err != nil {
		return nil, errors.Join(fmt.Errorf("create table if not exists failed: %w", err), provider.Shutdown())
	}

	collector := &dbStatsCollector{readDB: provider.readDB, writeDB: provider.writeDB}
	if err := prometheus.DefaultRegisterer.Register(collector); err != nil {
		return nil, errors.Join(fmt.Errorf("registering db stats collector: %w", err), provider.Shutdown())
	}
	provider.collector = collector

	// HandlerLimit derives from the write pool's limit, so the bundler cannot be built
	// until openPool has applied the options
	provider.initBundler()

	// a limit of 0 means unlimited, so report what each pool actually got
	log.Logger.Infof("search index connection pools: %d read, %d write",
		provider.readDB.Stats().MaxOpenConnections, provider.writeDB.Stats().MaxOpenConnections)

	return provider, nil
}

func (isp *IndexStorageProvider) initBundler() *bundler.Bundler {
	isp.bundlerOnce.Do(func() {
		b := bundler.NewBundler(indexEntry{}, isp.writeBundle)
		b.DelayThreshold = bundleDelay
		if isp.batchDelay > 0 {
			b.DelayThreshold = isp.batchDelay
		}
		b.BundleCountThreshold = bundleCount
		b.BufferedByteLimit = bufferedByteLimit
		b.HandlerLimit = defaultHandlerLimit
		// more concurrent bundles than connections would just queue inside the pool
		if isp.writeDB != nil {
			if maxConns := isp.writeDB.Stats().MaxOpenConnections; maxConns > 0 {
				b.HandlerLimit = maxConns
			}
		}
		isp.bundler = b
	})
	return isp.bundler
}

// writeBundle inserts one coalesced batch of index entries. WriteIndex has long since
// returned, so a failure here is only observable through these metrics and logs; the
// entries in a failed bundle are not retried and stay unsearchable.
func (isp *IndexStorageProvider) writeBundle(items any) {
	entries := items.([]indexEntry)

	ctx, cancel := context.WithTimeout(context.Background(), bundleWriteTimeout)
	defer cancel()

	start := time.Now()
	err := isp.execBundle(ctx, entries)
	labels := prometheus.Labels{"success": strconv.FormatBool(err == nil)}
	metricBatchWrites.With(labels).Inc()
	metricBatchWriteRows.With(labels).Add(float64(len(entries)))
	metricBatchWriteLatency.With(labels).Observe(time.Since(start).Seconds())

	if err != nil {
		log.Logger.Errorf("batched WriteIndex of %d entries failed, those keys are not indexed: %v", len(entries), err)
	}
}

func (isp *IndexStorageProvider) execBundle(ctx context.Context, entries []indexEntry) error {
	result, err := isp.writeDB.NamedExecContext(ctx, writeStmt, entries)
	if err != nil {
		return fmt.Errorf("mysql write error: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("mysql error getting rowsAffected: %w", err)
	}
	log.Logger.Debugf("WriteIndex affected %d rows", rowsAffected)
	return nil
}

// openPool opens one connection pool, applying only the options that name role.
func openPool(dsn string, role poolRole, opts []Options) (*sqlx.DB, error) {
	db, err := sqlx.Open(ProviderType, dsn)
	if err != nil {
		return nil, fmt.Errorf("opening %s pool: %w", role, err)
	}
	if err := db.Ping(); err != nil {
		return nil, errors.Join(fmt.Errorf("pinging %s pool: %w", role, err), db.Close())
	}

	for _, o := range opts {
		o.applyConnMaxIdleTime(db)
		o.applyConnMaxLifetime(db)
		o.applyMaxIdleConns(db, role)
		o.applyMaxOpenConns(db, role)
	}
	return db, nil
}

// LookupIndices looks up and returns all indices for the specified keys.
func (isp *IndexStorageProvider) LookupIndices(ctx context.Context, keys []string) ([]string, error) {
	if isp.readDB == nil {
		return []string{}, errors.New("sql client has not been initialized")
	}

	query, args, err := sqlx.In(lookupStmt, keys)
	if err != nil {
		return []string{}, fmt.Errorf("error preparing statement: %w", err)
	}
	rows, err := isp.readDB.QueryContext(ctx, isp.readDB.Rebind(query), args...)
	if err != nil {
		return []string{}, fmt.Errorf("error looking up indices from mysql: %w", err)
	}
	defer rows.Close()

	var entryUUIDs []string
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			return []string{}, fmt.Errorf("error parsing results from mysql: %w", err)
		}
		entryUUIDs = append(entryUUIDs, result)
	}

	if err := rows.Err(); err != nil {
		return []string{}, fmt.Errorf("error processing results from mysql: %w", err)
	}
	return entryUUIDs, nil
}

// WriteIndex queues the index for the specified keys. The rows are written
// asynchronously in coalesced batches, so a nil return only means the keys were
// buffered; MySQL failures are reported by writeBundle. Call Flush to wait for them.
func (isp *IndexStorageProvider) WriteIndex(ctx context.Context, keys []string, index string) error {
	if isp.writeDB == nil {
		return errors.New("sql client has not been initialized")
	}

	b := isp.initBundler()
	// an entry indexed under some of its keys but not others is worse than one indexed
	// under none, so every key is attempted even after one fails to buffer
	var errs []error
	for _, key := range keys {
		// a key of at most maxEntryKeyChars bytes cannot exceed maxEntryKeyChars characters
		if len(key) > maxEntryKeyChars {
			if n := utf8.RuneCountInString(key); n > maxEntryKeyChars {
				metricSkippedKeys.Inc()
				log.ContextLogger(ctx).Warnf("skipping %d character index key for entry %s, exceeds the %d character limit of EntryKey",
					n, index, maxEntryKeyChars)
				continue
			}
		}
		entry := indexEntry{Key: key, UUID: index}
		if err := b.Add(entry, entry.size()); err != nil {
			errs = append(errs, fmt.Errorf("buffering index key for entry %s: %w", index, err))
		}
	}
	return errors.Join(errs...)
}

// Flush waits for all buffered entries to be written to the database. It goes through
// initBundler rather than reading the field, since a detached WriteIndex goroutine may
// still be racing to create the bundler.
func (isp *IndexStorageProvider) Flush() {
	isp.initBundler().Flush()
}

// drain flushes buffered entries on shutdown, giving up after shutdownDrainTimeout.
// A full buffer needs far longer to drain than any container termination grace period
// allows, so an unbounded wait would just trade these entries for a SIGKILL that also
// stalls the rollout.
func (isp *IndexStorageProvider) drain() {
	done := make(chan struct{})
	go func() {
		defer close(done)
		isp.Flush()
	}()

	select {
	case <-done:
	case <-time.After(shutdownDrainTimeout):
		log.Logger.Errorf("search index buffer did not drain within %s, buffered keys are not indexed", shutdownDrainTimeout)
	}
}

// Shutdown cleans up any client resources that may be held by the provider
func (isp *IndexStorageProvider) Shutdown() error {
	// closing the pools out from under an in-flight bundle would fail writes that were
	// already accepted, so the buffer drains first, while the pools are still usable
	isp.drain()

	// a registered collector keeps reporting the closed pools as all-zero
	if isp.collector != nil {
		prometheus.DefaultRegisterer.Unregister(isp.collector)
		isp.collector = nil
	}

	var errs []error
	if isp.readDB != nil {
		errs = append(errs, isp.readDB.Close())
	}
	if isp.writeDB != nil {
		errs = append(errs, isp.writeDB.Close())
	}
	return errors.Join(errs...)
}
