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

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

func main() {
	count := flag.Int("count", 50000, "number of distinct signed entries")
	output := flag.String("output", "fixtures.json", "fixture output path")
	flag.Parse()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	publicKey := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	rows := make([]any, *count)
	for i := range rows {
		hash := sha256.Sum256(fmt.Appendf(nil, "rekor-perf-artifact-%d", i))
		sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
		if err != nil {
			panic(err)
		}
		rows[i] = map[string]any{
			"kind": "hashedrekord", "apiVersion": "0.0.1",
			"spec": map[string]any{
				"data":      map[string]any{"hash": map[string]string{"algorithm": "sha256", "value": hex.EncodeToString(hash[:])}},
				"signature": map[string]any{"content": base64.StdEncoding.EncodeToString(sig), "publicKey": map[string]string{"content": publicKey}},
			},
		}
	}
	f, err := os.Create(*output)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(rows); err != nil {
		panic(err)
	}
}
