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

package pgp_test

import (
	"github.com/sigstore/rekor/pkg/pki/pgp"
	"golang.org/x/crypto/openpgp" //nolint:staticcheck
)

// Preserve the pre-v1.5.4 return type for callers that consume the underlying
// key ring. The external test package ensures this checks the public API rather
// than relying on package-private implementation details.
func legacyKeyRing(publicKey *pgp.PublicKey) (openpgp.KeyRing, error) {
	return publicKey.KeyRing()
}
