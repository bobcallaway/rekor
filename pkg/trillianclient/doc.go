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

// Package trillianclient provides Rekor wrappers around Trillian's gRPC API.
//
// Two client modes are supported:
//
//   - cachedTrillianClient (default; --trillian_log_server.cache_sth): cached
//     Signed Tree Head (STH) behavior with a background updater.
//
//   - directTrillianClient (--trillian_log_server.cache_sth=false): stateless,
//     per-RPC behavior with no background goroutines and no cached root state.
//
// In cached mode, the client keeps an atomic snapshot of the latest verified
// root and uses waiter channels to wake only callers whose requested tree size
// has been reached. Each fetched root is proven to be an append-only extension
// of the one already cached, using the consistency proof Trillian returns
// alongside it, so a forked or corrupted log cannot be cached and then signed
// into a checkpoint.
//
// Because a cached root proves nothing about Trillian's current liveness, one
// left uncorroborated for longer than MaxSTHStaleness is not served: the client
// refetches on demand and reports Unavailable if that does not restore
// freshness. This bound is enforced on every path that serves the root or signs
// a proof against it — log-info, both leaf-and-proof lookups, and entry upload
// — and it is deliberately tight. Operators should expect a Trillian brownout
// lasting more than a few seconds to surface as 503s rather than as entries
// vouched for by a root nobody could corroborate.
//
// Frozen trees (inactive shards) are identified through configuration and are
// treated specially: the client initializes once, does not start an updater,
// is exempt from the staleness bound, and fails fast when callers request sizes
// that cannot be reached.
//
// The package exposes metrics for updater health, root advancement, and waiting
// behavior to support operational monitoring.
package trillianclient
