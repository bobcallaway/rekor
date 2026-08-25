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

package packet

import (
	"bytes"
	"errors"

	protonpacket "github.com/ProtonMail/go-crypto/openpgp/packet"
)

// ErrNotV3 is returned when an OpenPGP packet is not a V2 or V3 signature.
var ErrNotV3 = errors.New("not an OpenPGP V3 signature")

type SignatureType = protonpacket.SignatureType
type PublicKeyAlgorithm = protonpacket.PublicKeyAlgorithm

const (
	PubKeyAlgoRSA         = protonpacket.PubKeyAlgoRSA
	PubKeyAlgoRSASignOnly = protonpacket.PubKeyAlgoRSASignOnly
	PubKeyAlgoDSA         = protonpacket.PubKeyAlgoDSA
)

// PublicKey adapts the exported portion of a ProtonMail public key for the
// copied V3 verification method.
type PublicKey struct {
	PubKeyAlgo PublicKeyAlgorithm
	PublicKey  interface{}
}

// NewPublicKey creates a V3 verifier view of a ProtonMail public key.
func NewPublicKey(publicKey *protonpacket.PublicKey) *PublicKey {
	return &PublicKey{
		PubKeyAlgo: publicKey.PubKeyAlgo,
		PublicKey:  publicKey.PublicKey,
	}
}

func (pk *PublicKey) CanSign() bool {
	return pk.PubKeyAlgo.CanSign()
}

// Parse reads a single binary OpenPGP V2 or V3 signature packet.
func Parse(encoded []byte) (*SignatureV3, error) {
	return parse(encoded, false)
}

// ParseStrict reads exactly one binary OpenPGP V2 or V3 signature packet.
func ParseStrict(encoded []byte) (*SignatureV3, error) {
	return parse(encoded, true)
}

func parse(encoded []byte, strict bool) (*SignatureV3, error) {
	reader := bytes.NewReader(encoded)
	opaque, err := protonpacket.NewOpaqueReader(reader).Next()
	if err != nil {
		return nil, err
	}
	if opaque.Tag != 2 || len(opaque.Contents) == 0 || opaque.Contents[0] >= 4 {
		return nil, ErrNotV3
	}
	if strict && reader.Len() != 0 {
		return nil, errors.New("trailing data after OpenPGP signature packet")
	}

	sig := new(SignatureV3)
	if err := sig.parse(bytes.NewReader(opaque.Contents)); err != nil {
		return nil, err
	}
	return sig, nil
}
