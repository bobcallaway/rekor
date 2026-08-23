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
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	rootPolls = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rekor_trillian_root_polls_total",
		Help: "Trillian signed-root polls by tree and outcome.",
	}, []string{"tree_id", "outcome"})
	rootSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rekor_trillian_cached_root_size",
		Help: "Most recent verified Trillian tree size cached by this process.",
	}, []string{"tree_id"})
	writesPending = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rekor_trillian_writes_pending",
		Help: "Writes currently waiting for Trillian inclusion.",
	}, []string{"tree_id"})
	writesRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rekor_trillian_writes_rejected_total",
		Help: "Writes rejected because the per-process pending limit was reached.",
	}, []string{"tree_id"})
	proofsInFlight = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rekor_trillian_proofs_in_flight",
		Help: "Trillian proof operations currently in flight.",
	}, []string{"tree_id"})
	sizeWaiterCount = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rekor_trillian_size_waiters",
		Help: "Callers currently waiting for a cached tree-size advance.",
	}, []string{"tree_id"})
	sizeBucketCount = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rekor_trillian_size_waiter_buckets",
		Help: "Distinct target tree sizes represented by cached-client waiters.",
	}, []string{"tree_id"})
)

type cachedClientMetrics struct {
	pollSuccess   prometheus.Counter
	pollFailure   prometheus.Counter
	rootSize      prometheus.Gauge
	pending       prometheus.Gauge
	rejected      prometheus.Counter
	proofs        prometheus.Gauge
	waiters       prometheus.Gauge
	waiterBuckets prometheus.Gauge
}

func newCachedClientMetrics(treeID int64) cachedClientMetrics {
	label := strconv.FormatInt(treeID, 10)
	return cachedClientMetrics{
		pollSuccess:   rootPolls.WithLabelValues(label, "success"),
		pollFailure:   rootPolls.WithLabelValues(label, "failure"),
		rootSize:      rootSize.WithLabelValues(label),
		pending:       writesPending.WithLabelValues(label),
		rejected:      writesRejected.WithLabelValues(label),
		proofs:        proofsInFlight.WithLabelValues(label),
		waiters:       sizeWaiterCount.WithLabelValues(label),
		waiterBuckets: sizeBucketCount.WithLabelValues(label),
	}
}
