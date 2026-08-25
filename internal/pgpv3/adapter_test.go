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

package pgpv3

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
)

func TestParseAndVerify(t *testing.T) {
	data := readTestFile(t, "../../pkg/pki/pgp/testdata/repomd.xml")
	encoded := readTestFile(t, "../../pkg/pki/pgp/testdata/repomd.xml.sig")
	keyBytes := readTestFile(t, "../../pkg/pki/pgp/testdata/repomd_armored_public.pgp")
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(keyBytes))
	if err != nil {
		t.Fatal(err)
	}

	sig, err := Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(sig, bytes.NewReader(data), keyring); err != nil {
		t.Fatalf("verifying V3 signature: %v", err)
	}
	if err := Verify(sig, bytes.NewReader(append(data, 0)), keyring); err == nil {
		t.Fatal("V3 signature unexpectedly verified modified data")
	}
}

func TestParsePacketFraming(t *testing.T) {
	v3 := readTestFile(t, "../../pkg/pki/pgp/testdata/repomd.xml.sig")
	withTrailingData := append(append([]byte(nil), v3...), 0)
	if _, err := Parse(withTrailingData); err != nil {
		t.Fatalf("non-strict parsing changed historical detached-signature behavior: %v", err)
	}
	if _, err := ParseStrict(withTrailingData); err == nil {
		t.Fatal("strict parsing accepted trailing data")
	}

	v4 := readTestFile(t, "../../pkg/pki/pgp/testdata/hello_world.txt.v4.sig")
	if _, err := Parse(v4); !errors.Is(err, ErrNotV3) {
		t.Fatalf("parsing V4 signature: got %v, want ErrNotV3", err)
	}
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}
