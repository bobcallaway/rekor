//
// Copyright 2021 The Sigstore Authors.
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

package alpine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/sigstore/rekor/pkg/pki/x509"
)

func TestAlpinePackage(t *testing.T) {
	inputArchive, err := os.Open("../../../tests/test_alpine.apk")
	if err != nil {
		t.Fatalf("could not open archive %v", err)
	}

	p := Package{}
	err = p.Unmarshal(inputArchive)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	pubKey, err := os.Open("../../../tests/test_alpine.pub")
	if err != nil {
		t.Fatalf("could not open archive %v", err)
	}

	pub, err := x509.NewPublicKey(pubKey)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}

	if err = p.VerifySignature(pub.CryptoPubKey()); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func FuzzPackageUnmarshal(f *testing.F) {
	// 3 gzips
	// first valid TAR, one file named .SIGN, with a valid signature
	// second valid TAR, one file named .PKGINFO, with fuzz total input
	// valid TAR, valid name, with fuzz map, manually written K=V\n with datahash=SHA256(rand), with 3rd gzip = rand
	// IGNORE FOR NOW valid TAR, valid name, with fuzz map, manually written K=V\n, junk for 3rd
	f.Fuzz(func(t *testing.T, pkginfoFile []byte, validDataHash bool) {
		dataFile := bytes.NewBuffer([]byte("something"))
		dataSum := sha256.Sum256(dataFile.Bytes())
		dataTarBuf := &bytes.Buffer{}
		dataTar := tar.NewWriter(dataTarBuf)
		dataTar.WriteHeader(&tar.Header{Name: "somefile"})
		dataTar.Write(dataFile.Bytes())
		dataTar.Close()
		dataTarGZBuf := &bytes.Buffer{}
		dataTarGZWriter := gzip.NewWriter(dataTarGZBuf)
		/*fuzz1 := fuzz.NewConsumer(dataFile.Bytes())
		dataTar, err := fuzz1.TarBytes()
		if err != nil {
			t.Logf("invalid tar generated")
			t.Skip("invalid tar generated")
		}*/
		if _, err := io.Copy(dataTarGZWriter, dataTarBuf); err != nil {
			t.Error("unable to copy tar")
		}
		var m map[string]string
		fuzz2 := fuzz.NewConsumer(pkginfoFile[:])
		if err := fuzz2.FuzzMap(&m); err != nil {
			t.Logf("unable to populate .PKGINFO map: %v", err)
			t.Skip("unable to populate .PKGINFO map")
		}
		if validDataHash {
			m["datahash"] = hex.EncodeToString(dataSum[:])
		}
		controlFile := &bytes.Buffer{}
		controlTar := tar.NewWriter(controlFile)
		controlTar.WriteHeader(&tar.Header{Name: ".PKGINFO"})
		pkginfoBuf := &bytes.Buffer{}
		for k, v := range m {
			pkginfoBuf.WriteString(fmt.Sprintf("%v=%v\n", k, v))
		}
		controlTar.Close()
		controlTarGZFile := &bytes.Buffer{}
		controlTarGZ := gzip.NewWriter(controlTarGZFile)
		if _, err := io.CopyN(controlTarGZ, controlFile, int64(controlFile.Len()-1024)); err != nil {
			t.Error("failed to copy pkgInfo")
		}
		signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		controlSHA1 := sha1.Sum(pkginfoBuf.Bytes())
		controlSig, _ := ecdsa.SignASN1(rand.Reader, signingKey, controlSHA1[:])

		sigFile := &bytes.Buffer{}
		sigTar := tar.NewWriter(sigFile)
		sigTarGZFile := &bytes.Buffer{}
		sigTarGZ := gzip.NewWriter(sigTarGZFile)
		sigTar.WriteHeader(&tar.Header{Name: ".SIGN"})
		sigTar.Write(controlSig)
		sigTar.Close()
		if _, err := io.CopyN(sigTarGZ, sigFile, int64(sigFile.Len()-1024)); err != nil {
			t.Errorf("failed to copy signature")
		}

		pkg := Package{}
		err := pkg.Unmarshal(io.MultiReader(sigTarGZFile, controlTarGZFile, dataTarGZBuf))
		if err == nil && validDataHash {
			t.Error("unexpected success with validDataHash = true")
		}
		if err != nil {
			t.Logf("err != nil: %v", err)
		}
	})
}
