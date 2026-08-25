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

package pgp

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/sigstore/rekor/internal/pgpv3"
)

func (s *Signature) detectV3Signature(encoded []byte) error {
	_, err := pgpv3.Parse(encoded)
	if errors.Is(err, pgpv3.ErrNotV3) {
		return nil
	}
	if err != nil {
		return err
	}
	s.isV3 = true
	return nil
}

func (s Signature) verifyV3(data io.Reader, key *PublicKey) error {
	encoded := s.signature
	if s.isArmored {
		block, err := armor.Decode(bytes.NewReader(encoded))
		if err != nil {
			return fmt.Errorf("error decoding armored PGP signature: %w", err)
		}
		encoded, err = io.ReadAll(block.Body)
		if err != nil {
			return fmt.Errorf("error reading armored PGP signature: %w", err)
		}
	}

	sig, err := pgpv3.Parse(encoded)
	if err != nil {
		return fmt.Errorf("error reading PGP V3 signature: %w", err)
	}
	return pgpv3.Verify(sig, data, key.key)
}
