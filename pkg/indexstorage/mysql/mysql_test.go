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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sigstore/rekor/pkg/log"

	"go.uber.org/goleak"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// newMockDB returns a sqlx handle over a sqlmock connection. Mocks that expect writeStmt
// need QueryMatcherEqual, since its positional form contains "(?" and is not a valid regexp.
func newMockDB(t *testing.T, matcher sqlmock.QueryMatcher) (*sqlx.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(matcher))
	if err != nil {
		t.Fatalf("unexpected error creating mock db: %v", err)
	}
	return sqlx.NewDb(db, "mysql"), mock
}

// positionalWriteStmt renders writeStmt's named parameters in the positional form the driver
// actually receives.
func positionalWriteStmt() string {
	return regexp.MustCompile(`:[a-z]*`).ReplaceAllString(writeStmt, "?")
}

func TestLookupIndices(t *testing.T) {
	keys := []string{"87c1b129fbadd7b6e9abc0a9ef7695436d767aece042bec198a97e949fcbe14c"}
	value := []string{"1e1f2c881ae0608ec77ebf88a75c66d3099113a7343238f2f7a0ebb91a4ed335"}
	db, mock := newMockDB(t, sqlmock.QueryMatcherRegexp)

	isp := IndexStorageProvider{readDB: db}
	defer isp.Shutdown()

	mock.ExpectQuery(lookupStmt).WithArgs(keys[0]).WillReturnRows(sqlmock.NewRows(value))

	if _, err := isp.LookupIndices(context.Background(), keys); err != nil {
		t.Error(err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	expectedErr := errors.New("badness")
	mock.ExpectQuery(lookupStmt).WillReturnError(expectedErr)
	if _, err := isp.LookupIndices(context.Background(), keys); err == nil {
		t.Error("unexpected success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestWriteIndex(t *testing.T) {
	keys := []string{"87c1b129fbadd7b6e9abc0a9ef7695436d767aece042bec198a97e949fcbe14c"}
	value := "1e1f2c881ae0608ec77ebf88a75c66d3099113a7343238f2f7a0ebb91a4ed335"
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
	expectedStmt := positionalWriteStmt()

	isp := IndexStorageProvider{writeDB: db}
	defer isp.Shutdown()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations not met: %v", err)
	}

	mock.ExpectExec(expectedStmt).WithArgs(keys[0], value).WillReturnResult(sqlmock.NewResult(1, 1))
	if err := isp.WriteIndex(context.Background(), keys, value); err != nil {
		t.Errorf("%v, %v", expectedStmt, err)
	}
	isp.Flush()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	// keys queued together coalesce into a single wide INSERT
	keysBatch := []string{"key1", "key2"}
	valueBatch := "uuid1"
	expectedBatchStmt := expectedStmt + ",(?, ?)"
	mock.ExpectExec(expectedBatchStmt).WithArgs("key1", valueBatch, "key2", valueBatch).WillReturnResult(sqlmock.NewResult(2, 2))
	if err := isp.WriteIndex(context.Background(), keysBatch, valueBatch); err != nil {
		t.Errorf("%v, %v", expectedBatchStmt, err)
	}
	isp.Flush()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

// TestWriteIndexCoalescesAcrossCalls covers the point of the bundler: keys from separate
// entries, queued in separate WriteIndex calls, collapse into one INSERT. Batching within
// a single call was already what the pre-bundler multi-row insert did.
func TestWriteIndexCoalescesAcrossCalls(t *testing.T) {
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
	// long enough that only the explicit Flush can close the bundle
	isp := IndexStorageProvider{writeDB: db, batchDelay: time.Minute}
	defer isp.Shutdown() //nolint:errcheck

	mock.ExpectExec(positionalWriteStmt()+",(?, ?)").
		WithArgs("key1", "uuid1", "key2", "uuid2").
		WillReturnResult(sqlmock.NewResult(2, 2))

	if err := isp.WriteIndex(context.Background(), []string{"key1"}, "uuid1"); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := isp.WriteIndex(context.Background(), []string{"key2"}, "uuid2"); err != nil {
		t.Fatalf("second write: %v", err)
	}
	isp.Flush()

	// a second INSERT here means the two calls did not share a bundle
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

// TestBatchDelayOption asserts the configured delay reaches the bundler, since nothing
// else observes it and an ignored value would silently keep the default.
func TestBatchDelayOption(t *testing.T) {
	for _, tc := range []struct{ delay, want time.Duration }{
		{0, bundleDelay},
		{time.Second, time.Second},
	} {
		t.Run(tc.delay.String(), func(t *testing.T) {
			db, _ := newMockDB(t, sqlmock.QueryMatcherEqual)
			isp := IndexStorageProvider{writeDB: db}
			WithBatchDelay(tc.delay).applyBatchDelay(&isp.batchDelay)
			t.Cleanup(func() { isp.Shutdown() }) //nolint:errcheck

			if got := isp.initBundler().DelayThreshold; got != tc.want {
				t.Errorf("got DelayThreshold = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestMaxEntryKeyCharsMatchesSchema keeps the guard pinned to the column it protects.
func TestMaxEntryKeyCharsMatchesSchema(t *testing.T) {
	want := fmt.Sprintf("varchar(%d)", maxEntryKeyChars)
	if !strings.Contains(createTableStmt, want) {
		t.Errorf("createTableStmt does not declare EntryKey as %s", want)
	}
}

// TestWriteIndexError covers the batch write exhausting its retries after WriteIndex has
// already returned nil, which is the only way a MySQL error can now surface.
func TestWriteIndexError(t *testing.T) {
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)

	// registered before the provider so Shutdown's drain still logs to the observer
	observed, logs := observer.New(zapcore.ErrorLevel)
	restore := log.Logger
	log.Logger = zap.New(observed).Sugar()
	defer func() { log.Logger = restore }()

	isp := IndexStorageProvider{writeDB: db}
	defer isp.Shutdown() //nolint:errcheck

	for range bundleWriteRetries + 1 {
		mock.ExpectExec(positionalWriteStmt()).WillReturnError(errors.New("badness"))
	}
	if err := isp.WriteIndex(context.Background(), []string{"key"}, "value"); err != nil {
		t.Errorf("queueing should not fail: %v", err)
	}
	isp.Flush()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
	// retries log at warn, below the observer's level, so only the final failure is seen
	if logs.FilterMessageSnippet("badness").Len() != 1 {
		t.Errorf("write failure was not logged exactly once, got entries: %v", logs.All())
	}
}

// TestWriteIndexRetry covers a transient failure: the bundle is retried and written, and
// nothing is reported as lost.
func TestWriteIndexRetry(t *testing.T) {
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)

	observed, logs := observer.New(zapcore.ErrorLevel)
	restore := log.Logger
	log.Logger = zap.New(observed).Sugar()
	defer func() { log.Logger = restore }()

	isp := IndexStorageProvider{writeDB: db}
	defer isp.Shutdown() //nolint:errcheck

	retriesBefore := testutil.ToFloat64(metricBatchWriteRetries)
	mock.ExpectExec(positionalWriteStmt()).WithArgs("key", "value").WillReturnError(errors.New("connection reset"))
	mock.ExpectExec(positionalWriteStmt()).WithArgs("key", "value").WillReturnResult(sqlmock.NewResult(1, 1))
	if err := isp.WriteIndex(context.Background(), []string{"key"}, "value"); err != nil {
		t.Errorf("queueing should not fail: %v", err)
	}
	isp.Flush()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
	if got := testutil.ToFloat64(metricBatchWriteRetries) - retriesBefore; got != 1 {
		t.Errorf("got %v retries, want 1", got)
	}
	if logs.Len() != 0 {
		t.Errorf("recovered write should not log an error, got entries: %v", logs.All())
	}
}

// TestPoolSeparation asserts reads never touch the write pool and vice versa.
// Each mock fails the test if it receives an unexpected statement.
func TestPoolSeparation(t *testing.T) {
	keys := []string{"87c1b129fbadd7b6e9abc0a9ef7695436d767aece042bec198a97e949fcbe14c"}
	value := "1e1f2c881ae0608ec77ebf88a75c66d3099113a7343238f2f7a0ebb91a4ed335"

	readDB, readMock := newMockDB(t, sqlmock.QueryMatcherRegexp)
	writeDB, writeMock := newMockDB(t, sqlmock.QueryMatcherEqual)

	isp := IndexStorageProvider{readDB: readDB, writeDB: writeDB}
	defer isp.Shutdown()

	readMock.ExpectQuery(lookupStmt).WithArgs(keys[0]).
		WillReturnRows(sqlmock.NewRows([]string{"EntryUUID"}).AddRow(value))
	got, err := isp.LookupIndices(context.Background(), keys)
	if err != nil {
		t.Errorf("lookup: %v", err)
	}
	if len(got) != 1 || got[0] != value {
		t.Errorf("lookup returned %v, want [%s]", got, value)
	}

	writeMock.ExpectExec(positionalWriteStmt()).WithArgs(keys[0], value).WillReturnResult(sqlmock.NewResult(1, 1))
	if err := isp.WriteIndex(context.Background(), keys, value); err != nil {
		t.Errorf("write: %v", err)
	}
	isp.Flush()

	// an unmet expectation on either mock means a statement went to the wrong pool
	if err := readMock.ExpectationsWereMet(); err != nil {
		t.Errorf("read pool: %v", err)
	}
	if err := writeMock.ExpectationsWereMet(); err != nil {
		t.Errorf("write pool: %v", err)
	}
}

func TestDBStatsCollector(t *testing.T) {
	readDB, _ := newMockDB(t, sqlmock.QueryMatcherRegexp)
	writeDB, _ := newMockDB(t, sqlmock.QueryMatcherRegexp)
	isp := IndexStorageProvider{readDB: readDB, writeDB: writeDB}
	defer isp.Shutdown()

	collector := &dbStatsCollector{readDB: isp.readDB, writeDB: isp.writeDB}
	for _, name := range []string{
		"rekor_index_storage_db_connections_open",
		"rekor_index_storage_db_wait_count_total",
		"rekor_index_storage_db_wait_duration_seconds_total",
	} {
		if got := testutil.CollectAndCount(collector, name); got != 2 {
			t.Errorf("%s: got %d series, want 2 (one per pool)", name, got)
		}
	}

	problems, err := testutil.CollectAndLint(collector)
	if err != nil {
		t.Fatalf("lint: %v", err)
	}
	for _, p := range problems {
		t.Errorf("lint: %s: %s", p.Metric, p.Text)
	}
}

// TestDBStatsCollectorNilPool covers a partially constructed provider, where one pool was
// never opened.
func TestDBStatsCollectorNilPool(t *testing.T) {
	collector := &dbStatsCollector{}
	if got := testutil.CollectAndCount(collector); got != 0 {
		t.Errorf("got %d series from an empty collector, want 0", got)
	}
}

// TestShutdownUnregistersCollector guards against a closed provider holding the registry
// slot, which would report all-zero pool stats forever and block any replacement provider.
func TestShutdownUnregistersCollector(t *testing.T) {
	readDB, readMock := newMockDB(t, sqlmock.QueryMatcherRegexp)
	writeDB, writeMock := newMockDB(t, sqlmock.QueryMatcherRegexp)
	isp := IndexStorageProvider{readDB: readDB, writeDB: writeDB}
	isp.collector = &dbStatsCollector{readDB: isp.readDB, writeDB: isp.writeDB}

	if err := prometheus.DefaultRegisterer.Register(isp.collector); err != nil {
		t.Fatalf("register: %v", err)
	}
	readMock.ExpectClose()
	writeMock.ExpectClose()
	if err := isp.Shutdown(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	for name, mock := range map[string]sqlmock.Sqlmock{"read": readMock, "write": writeMock} {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("%s pool not closed: %v", name, err)
		}
	}

	// the slot is free only if a replacement can claim it
	replacement := &dbStatsCollector{}
	if err := prometheus.DefaultRegisterer.Register(replacement); err != nil {
		t.Fatalf("registry slot still held after shutdown: %v", err)
	}
	prometheus.DefaultRegisterer.Unregister(replacement)
}

func TestConnOptionsAreRoleScoped(t *testing.T) {
	// each pool is opened with the full option slice, so an option meant for the other
	// pool must leave this one at its default of unlimited
	for _, tc := range []struct {
		name string
		opt  Options
		role poolRole
		want int
	}{
		{"read option on read pool", WithReadMaxOpenConns(5), poolRead, 5},
		{"read option on write pool", WithReadMaxOpenConns(5), poolWrite, 0},
		{"write option on write pool", WithWriteMaxOpenConns(7), poolWrite, 7},
		{"write option on read pool", WithWriteMaxOpenConns(7), poolRead, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := newMockDB(t, sqlmock.QueryMatcherRegexp)
			defer db.Close()
			tc.opt.applyMaxOpenConns(db, tc.role)
			if got := db.Stats().MaxOpenConnections; got != tc.want {
				t.Errorf("got %d max open connections, want %d", got, tc.want)
			}
		})
	}
}

func TestUninitializedClient(t *testing.T) {
	// this is not initialized with a real mysql client
	isp := IndexStorageProvider{}
	if _, err := isp.LookupIndices(context.Background(), []string{"key"}); err == nil {
		t.Error("unexpected success")
	}
	if err := isp.WriteIndex(context.Background(), []string{"key"}, "value"); err == nil {
		t.Error("unexpected success")
	}
}

// TestWriteIndexKeyLengthLimit pins the skip to EntryKey's character limit rather than its
// byte length: utf8mb4 permits four bytes per character, so a 512 character key of astral
// codepoints is 2048 bytes and still fits the column.
func TestWriteIndexKeyLengthLimit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		key     string
		skipped bool
	}{
		{"ascii at limit", strings.Repeat("a", maxEntryKeyChars), false},
		{"ascii over limit", strings.Repeat("a", maxEntryKeyChars+1), true},
		{"four byte runes at limit", strings.Repeat("𝔘", maxEntryKeyChars), false},
		{"four byte runes over limit", strings.Repeat("𝔘", maxEntryKeyChars+1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
			isp := IndexStorageProvider{writeDB: db}
			t.Cleanup(func() { isp.Shutdown() }) //nolint:errcheck

			// with no expectation registered, any statement reaching the mock fails the test
			if !tc.skipped {
				mock.ExpectExec(positionalWriteStmt()).WithArgs(tc.key, "uuid").
					WillReturnResult(sqlmock.NewResult(1, 1))
			}
			if err := isp.WriteIndex(context.Background(), []string{tc.key}, "uuid"); err != nil {
				t.Fatalf("write: %v", err)
			}
			isp.Flush()

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Error(err)
			}
		})
	}
}

// TestWriteIndexSkipsOnlyOversizedKey guards the per-key granularity of the skip: dropping
// one key must not cost the entry its remaining, valid index keys.
func TestWriteIndexSkipsOnlyOversizedKey(t *testing.T) {
	db, mock := newMockDB(t, sqlmock.QueryMatcherEqual)
	isp := IndexStorageProvider{writeDB: db}
	defer isp.Shutdown() //nolint:errcheck

	oversized := strings.Repeat("a", maxEntryKeyChars+1)
	mock.ExpectExec(positionalWriteStmt()+",(?, ?)").WithArgs("good1", "uuid", "good2", "uuid").
		WillReturnResult(sqlmock.NewResult(2, 2))

	if err := isp.WriteIndex(context.Background(), []string{"good1", oversized, "good2"}, "uuid"); err != nil {
		t.Fatalf("write: %v", err)
	}
	isp.Flush()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

// TestBundlerHandlerLimit pins how HandlerLimit is derived from the write pool: it tracks
// the pool's limit so batch writers cannot outnumber the connections they need, and an
// unlimited pool falls back to defaultHandlerLimit rather than the bundler's default of 1.
func TestBundlerHandlerLimit(t *testing.T) {
	for _, tc := range []struct{ writeMaxOpen, want int }{
		{1, 1},
		{5, 5},
		{20, 20},
		{0, defaultHandlerLimit},
	} {
		t.Run(fmt.Sprintf("max_open_conns_%d", tc.writeMaxOpen), func(t *testing.T) {
			writeDB, _ := newMockDB(t, sqlmock.QueryMatcherEqual)
			writeDB.SetMaxOpenConns(tc.writeMaxOpen)
			isp := IndexStorageProvider{writeDB: writeDB}
			t.Cleanup(func() { isp.Shutdown() }) //nolint:errcheck

			if got := isp.initBundler().HandlerLimit; got != tc.want {
				t.Errorf("got bundler.HandlerLimit = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
