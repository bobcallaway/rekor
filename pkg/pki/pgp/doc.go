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

// Package pgp implements legacy OpenPGP signature and public-key handling.
//
// Deprecated: OpenPGP support is retained for compatibility with existing
// Rekor clients and log entries. New integrations should use another supported
// signature format. OpenPGP support will be removed in the next major release.
package pgp
