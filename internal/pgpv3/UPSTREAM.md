<!--
 Copyright 2026 The Sigstore Authors.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

# Vendored OpenPGP V3 support

The following BSD-licensed code is copied from
`github.com/pgpkeys-eu/go-crypto` commit
`d2a8cc303a65a5643c299cb0ffde2ced6f1e14ee`:

- `algorithm/hash.go`: `openpgp/internal/algorithm/hash.go`
- `encoding/encoding.go`: `openpgp/internal/encoding/encoding.go`
- `encoding/mpi.go`: `openpgp/internal/encoding/mpi.go`
- `packet/signature_v3.go`: `openpgp/packet/signature_v3.go`
- `packet/public_key_v3_verify.go`: `PublicKey.VerifySignatureV3` from
  `openpgp/packet/public_key_v3.go`
- `packet/helpers.go`: `readFull` and `padToKeySize` from
  `openpgp/packet/packet.go`

The copied declarations are unchanged. The only changes to a complete copied
file are the two import paths in `packet/signature_v3.go`, which point to the
copies inside Rekor's `internal` tree. The `adapter.go` files contain all
Rekor-specific code needed for packet framing and conversion to ProtonMail's
public types.

The upstream `LICENSE` and `PATENTS` files are included in this directory.
