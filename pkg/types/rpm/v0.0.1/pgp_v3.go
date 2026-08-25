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

package rpm

import (
	"bytes"
	"crypto"
	_ "crypto/md5"  //nolint:gosec // Required to validate payloads of legacy RPMs.
	_ "crypto/sha1" //nolint:gosec // Required to validate payloads of legacy RPMs.
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/sassoftware/go-rpmutils"

	"github.com/sigstore/rekor/internal/pgpv3"
	"github.com/sigstore/rekor/pkg/pki/pgp"
)

type rpmSignatureRegion struct {
	tag        int
	headerOnly bool
}

var rpmSignatureRegions = []rpmSignatureRegion{
	{tag: rpmutils.SIG_RSA, headerOnly: true},
	{tag: rpmutils.SIG_DSA, headerOnly: true},
	{tag: rpmutils.SIG_PGP, headerOnly: false},
	{tag: rpmutils.SIG_GPG, headerOnly: false},
}

func verifyRPM(packageBytes []byte, key *pgp.PublicKey, keyring openpgp.EntityList) (*rpmutils.RpmHeader, int, error) {
	v3Header, err := rpmHeaderWithV3Signature(packageBytes)
	if err != nil {
		return nil, 0, err
	}
	if v3Header == nil {
		header, signatures, err := rpmutils.Verify(bytes.NewReader(packageBytes), keyring)
		return header, len(signatures), err
	}
	signatureCount, v3Err := verifyRPMWithV3(packageBytes, v3Header, key, keyring)
	if v3Err != nil {
		return nil, 0, v3Err
	}
	return v3Header, signatureCount, nil
}

func rpmHeaderWithV3Signature(packageBytes []byte) (*rpmutils.RpmHeader, error) {
	header, err := rpmutils.ReadHeader(bytes.NewReader(packageBytes))
	if err != nil {
		return nil, err
	}
	for _, region := range rpmSignatureRegions {
		encoded, err := header.GetBytes(region.tag)
		if isMissingRPMTag(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if _, err := pgpv3.ParseStrict(encoded); err == nil {
			return header, nil
		} else if !errors.Is(err, pgpv3.ErrNotV3) {
			return nil, err
		}
	}
	return nil, nil
}

func verifyRPMWithV3(packageBytes []byte, header *rpmutils.RpmHeader, key *pgp.PublicKey, keyring openpgp.EntityList) (int, error) {
	headerRange := header.GetRange()
	if headerRange.Start < 0 || headerRange.Start > headerRange.End || headerRange.End > len(packageBytes) {
		return 0, errors.New("invalid RPM header range")
	}
	if err := verifyRPMPayloadDigest(header, packageBytes[headerRange.Start:headerRange.End], packageBytes[headerRange.End:]); err != nil {
		return 0, err
	}

	signatureCount := 0
	for _, region := range rpmSignatureRegions {
		encoded, err := header.GetBytes(region.tag)
		if isMissingRPMTag(err) {
			continue
		}
		if err != nil {
			return 0, err
		}

		signedBytes := packageBytes[headerRange.Start:]
		if region.headerOnly {
			signedBytes = packageBytes[headerRange.Start:headerRange.End]
		}
		v3Signature, err := pgpv3.ParseStrict(encoded)
		switch {
		case err == nil:
			if err := pgpv3.Verify(v3Signature, bytes.NewReader(signedBytes), keyring); err != nil {
				return 0, err
			}
		case errors.Is(err, pgpv3.ErrNotV3):
			signature, parseErr := pgp.NewSignature(bytes.NewReader(encoded))
			if parseErr != nil {
				return 0, parseErr
			}
			if verifyErr := signature.Verify(bytes.NewReader(signedBytes), key); verifyErr != nil {
				return 0, verifyErr
			}
		default:
			return 0, err
		}
		signatureCount++
	}

	return signatureCount, nil
}

func verifyRPMPayloadDigest(header *rpmutils.RpmHeader, generalHeader, payload []byte) error {
	digests, digestErr := header.GetStrings(rpmutils.PAYLOADDIGEST)
	algorithms, algorithmErr := header.GetUint32s(rpmutils.PAYLOADDIGESTALGO)
	if digestErr == nil && algorithmErr == nil && len(digests) > 0 && len(algorithms) > 0 {
		hashAlgorithm, ok := rpmHash(algorithms[0])
		if !ok || !hashAlgorithm.Available() {
			return fmt.Errorf("unknown RPM payload digest algorithm %d", algorithms[0])
		}
		h := hashAlgorithm.New()
		if _, err := h.Write(payload); err != nil {
			return err
		}
		if calculated := hex.EncodeToString(h.Sum(nil)); calculated != digests[0] {
			return fmt.Errorf("payload %s digest mismatch", hashAlgorithm)
		}
		return nil
	}

	expectedMD5, err := header.GetBytes(rpmutils.SIG_MD5)
	if err != nil {
		return errors.New("no usable payload digest found")
	}
	h := crypto.MD5.New() //nolint:gosec // Compatibility check for legacy RPM metadata.
	if _, err := h.Write(generalHeader); err != nil {
		return err
	}
	if _, err := h.Write(payload); err != nil {
		return err
	}
	if !bytes.Equal(h.Sum(nil), expectedMD5) {
		return errors.New("md5 digest mismatch")
	}
	return nil
}

func rpmHash(id uint32) (crypto.Hash, bool) {
	switch id {
	case rpmutils.HASH_MD5:
		return crypto.MD5, true
	case rpmutils.HASH_SHA1:
		return crypto.SHA1, true
	case rpmutils.HASH_SHA224:
		return crypto.SHA224, true
	case rpmutils.HASH_SHA256:
		return crypto.SHA256, true
	case rpmutils.HASH_SHA384:
		return crypto.SHA384, true
	case rpmutils.HASH_SHA512:
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

func isMissingRPMTag(err error) bool {
	var missing rpmutils.NoSuchTagError
	return errors.As(err, &missing)
}
