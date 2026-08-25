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

// Package pgpv3 provides the narrow OpenPGP V3 detached-signature support
// needed to read and verify historical Rekor entries and RPMs.
package pgpv3

import (
	_ "crypto/md5"  //nolint:gosec // Required to verify historical OpenPGP signatures.
	_ "crypto/sha1" //nolint:gosec // Required to verify historical OpenPGP signatures.
	_ "crypto/sha256"
	_ "crypto/sha3"
	_ "crypto/sha512"
	"io"
	"strconv"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	protonpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	pgpv3packet "github.com/sigstore/rekor/internal/pgpv3/packet"
)

// ErrNotV3 is returned when an OpenPGP packet is not a V2 or V3 signature.
var ErrNotV3 = pgpv3packet.ErrNotV3

// Signature is an OpenPGP V2 or V3 signature packet.
type Signature = pgpv3packet.SignatureV3

// Parse reads a single binary OpenPGP V2 or V3 signature packet.
func Parse(encoded []byte) (*Signature, error) {
	return pgpv3packet.Parse(encoded)
}

// ParseStrict reads exactly one binary OpenPGP V2 or V3 signature packet.
func ParseStrict(encoded []byte) (*Signature, error) {
	return pgpv3packet.ParseStrict(encoded)
}

// Verify checks a detached V3 signature against data and a ProtonMail keyring.
func Verify(sig *Signature, data io.Reader, keyring openpgp.KeyRing) error {
	h, err := sig.PrepareVerify()
	if err != nil {
		return err
	}
	if sig.SigType == protonpacket.SigTypeText {
		h = openpgp.NewCanonicalTextHash(h)
	} else if sig.SigType != protonpacket.SigTypeBinary {
		return pgperrors.UnsupportedError("unsupported signature type: " + strconv.Itoa(int(sig.SigType)))
	}
	if _, err := io.Copy(h, data); err != nil && err != io.EOF {
		return err
	}

	keys := keyring.KeysByIdUsage(sig.IssuerKeyId, protonpacket.KeyFlagSign)
	if len(keys) == 0 {
		return pgperrors.ErrUnknownIssuer
	}
	var lastErr error
	for _, key := range keys {
		publicKey := pgpv3packet.NewPublicKey(key.PublicKey)
		lastErr = publicKey.VerifySignatureV3(h, sig)
		if lastErr == nil {
			return nil
		}
	}
	return lastErr
}
