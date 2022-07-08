//
// Copyright 2022 The Sigstore Authors.
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

package intoto

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/in-toto/in-toto-golang/in_toto"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
	dsse_signer "github.com/sigstore/sigstore/pkg/signature/dsse"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestNewEntryReturnType(t *testing.T) {
	entry := NewEntry()
	if reflect.TypeOf(entry) != reflect.ValueOf(&V002Entry{}).Type() {
		t.Errorf("invalid type returned from NewEntry: %T", entry)
	}
}

func envelope(t *testing.T, k *ecdsa.PrivateKey, payload []byte, payloadType string) string {
	s, err := signature.LoadECDSASigner(k, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	wrappedSigner := dsse_signer.WrapSigner(s, string(payloadType))
	dsseEnv, err := wrappedSigner.SignMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}

	return string(dsseEnv)
}

func multiSignedEnvelope(t *testing.T, k1, k2 *ecdsa.PrivateKey, payload []byte, payloadType string) string {
	s1, err := signature.LoadECDSASigner(k1, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := signature.LoadECDSASigner(k2, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	wrappedSigner := dsse_signer.WrapMultiSigner(payloadType, s1, s2)
	dsseEnv, err := wrappedSigner.SignMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}

	return string(dsseEnv)
}

func TestV002Entry_Unmarshal(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := pem.EncodeToMemory(&pem.Block{
		Bytes: der,
		Type:  "PUBLIC KEY",
	})

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ca := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		EmailAddresses: []string{"joe@schmoe.com"},
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	invalid, err := json.Marshal(dsse.Envelope{
		Payload: "hello",
		Signatures: []dsse.Signature{
			{
				Sig: string(strfmt.Base64("foobar")),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	validStatement := in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          "something",
			PredicateType: "some/predicate",
			Subject: []in_toto.Subject{
				{
					Name: "name",
					Digest: slsa.DigestSet{
						"sha256": "1baf8b9b2448656795641f356eb2bc69171633a4b2cd71015554ddf675e778e8",
					},
				},
			},
		},
	}
	validPayload, _ := json.Marshal(&validStatement)

	tests := []struct {
		name                string
		want                models.IntotoV002Schema
		it                  *models.IntotoV002Schema
		wantErr             bool
		additionalIndexKeys []string
	}{
		{
			name:    "empty",
			it:      &models.IntotoV002Schema{},
			wantErr: true,
		},
		{
			name: "missing envelope",
			it: &models.IntotoV002Schema{
				Signature: &models.IntotoV002SchemaSignature{
					PublicKey: &models.IntotoV002SchemaSignaturePublicKey{
						Content: strfmt.Base64(pub),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid envelope",
			it: &models.IntotoV002Schema{
				Signature: &models.IntotoV002SchemaSignature{
					PublicKey: &models.IntotoV002SchemaSignaturePublicKey{
						Content: strfmt.Base64(pub),
					},
				},
				Content: &models.IntotoV002SchemaContent{
					Envelope: string(invalid),
				},
			},
			wantErr: true,
		},
		{
			name: "invalid public key with valid envelope",
			it: &models.IntotoV002Schema{
				Signature: &models.IntotoV002SchemaSignature{
					PublicKey: &models.IntotoV002SchemaSignaturePublicKey{
						Content: strfmt.Base64([]byte("hello")),
					},
				},
				Content: &models.IntotoV002SchemaContent{
					Envelope: envelope(t, key, validPayload, in_toto.PayloadType),
				},
			},
			wantErr: true,
		},
		{
			name: "valid payload but not intoto payload type",
			it: &models.IntotoV002Schema{
				Signature: &models.IntotoV002SchemaSignature{
					PublicKey: &models.IntotoV002SchemaSignaturePublicKey{
						Content: strfmt.Base64(pub),
					},
				},
				Content: &models.IntotoV002SchemaContent{
					Envelope: envelope(t, key, validPayload, "text"),
					EnvelopeHash: &models.IntotoV002SchemaContentEnvelopeHash{
						Algorithm: swag.String(models.IntotoV002SchemaContentEnvelopeHashAlgorithmSha256),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid intoto with signed twice",
			it: &models.IntotoV002Schema{
				Signature: &models.IntotoV002SchemaSignature{
					PublicKey: &models.IntotoV002SchemaSignaturePublicKey{
						Content: strfmt.Base64(pub),
					},
				},
				Content: &models.IntotoV002SchemaContent{
					Envelope: multiSignedEnvelope(t, key, priv, validPayload, in_toto.PayloadType),
					EnvelopeHash: &models.IntotoV002SchemaContentEnvelopeHash{
						Algorithm: swag.String(models.IntotoV002SchemaContentEnvelopeHashAlgorithmSha256),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid intoto with raw key",
			it: &models.IntotoV002Schema{
				Signature: &models.IntotoV002SchemaSignature{
					PublicKey: &models.IntotoV002SchemaSignaturePublicKey{
						Content: strfmt.Base64(pub),
					},
				},
				Content: &models.IntotoV002SchemaContent{
					Envelope: envelope(t, key, validPayload, in_toto.PayloadType),
					EnvelopeHash: &models.IntotoV002SchemaContentEnvelopeHash{
						Algorithm: swag.String(models.IntotoV002SchemaContentEnvelopeHashAlgorithmSha256),
					},
				},
			},
			additionalIndexKeys: []string{"sha256:1baf8b9b2448656795641f356eb2bc69171633a4b2cd71015554ddf675e778e8"},
			wantErr:             false,
		},
		{
			name: "valid intoto with cert",
			it: &models.IntotoV002Schema{
				Signature: &models.IntotoV002SchemaSignature{
					PublicKey: &models.IntotoV002SchemaSignaturePublicKey{
						Content: strfmt.Base64([]byte(pemBytes)),
					},
				},
				Content: &models.IntotoV002SchemaContent{
					Envelope: envelope(t, priv, validPayload, in_toto.PayloadType),
					EnvelopeHash: &models.IntotoV002SchemaContentEnvelopeHash{
						Algorithm: swag.String(models.IntotoV002SchemaContentEnvelopeHashAlgorithmSha256),
					},
				},
			},
			additionalIndexKeys: []string{"joe@schmoe.com", "sha256:1baf8b9b2448656795641f356eb2bc69171633a4b2cd71015554ddf675e778e8"},
			wantErr:             false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &V002Entry{}
			if tt.it.Content != nil {
				h := sha256.Sum256([]byte(tt.it.Content.Envelope))
				tt.it.Content.EnvelopeHash = &models.IntotoV002SchemaContentEnvelopeHash{
					Algorithm: swag.String(models.IntotoV002SchemaContentEnvelopeHashAlgorithmSha256),
					Value:     swag.String(hex.EncodeToString(h[:])),
				}
			}

			apiVersion := APIVERSION
			it := &models.Intoto{
				APIVersion: &apiVersion,
				Spec:       tt.it,
			}

			var uv = func() error {
				if err := v.Unmarshal(it); err != nil {
					return err
				}
				if err := v.validate(); err != nil {
					return err
				}
				keysWanted := tt.additionalIndexKeys
				if tt.it.Signature != nil && tt.it.Signature.PublicKey != nil {
					h := sha256.Sum256(tt.it.Signature.PublicKey.Content)
					keysWanted = append(keysWanted, fmt.Sprintf("sha256:%s", hex.EncodeToString(h[:])))
				}
				payloadBytes, _ := v.env.DecodeB64Payload()
				payloadSha := sha256.Sum256(payloadBytes)
				payloadHash := hex.EncodeToString(payloadSha[:])
				// Always start with the hash
				keysWanted = append(keysWanted, "sha256:"+payloadHash)
				hashkey := strings.ToLower(fmt.Sprintf("%s:%s", *tt.it.Content.EnvelopeHash.Algorithm, *tt.it.Content.EnvelopeHash.Value))
				keysWanted = append(keysWanted, hashkey)
				if got, _ := v.IndexKeys(); !cmp.Equal(got, keysWanted, cmpopts.SortSlices(func(x, y string) bool { return x < y })) {
					t.Errorf("V002Entry.IndexKeys() = %v, want %v", got, keysWanted)
				}
				canonicalBytes, err := v.Canonicalize(context.Background())
				if err != nil {
					t.Errorf("error canonicalizing entry: %v", err)
				}

				pe, err := models.UnmarshalProposedEntry(bytes.NewReader(canonicalBytes), runtime.JSONConsumer())
				if err != nil {
					t.Errorf("unexpected err from Unmarshalling canonicalized entry for '%v': %v", tt.name, err)
				}
				canonicalEntry, err := types.NewEntry(pe)
				if err != nil {
					t.Errorf("unexpected err from type-specific unmarshalling for '%v': %v", tt.name, err)
				}
				canonicalV002 := canonicalEntry.(*V002Entry)
				fmt.Printf("%v", canonicalV002.IntotoObj.Content)
				if *canonicalV002.IntotoObj.Content.EnvelopeHash.Value != *tt.it.Content.EnvelopeHash.Value {
					t.Errorf("envelope hashes do not match post canonicalization: %v %v", *canonicalV002.IntotoObj.Content.EnvelopeHash.Value, *tt.it.Content.EnvelopeHash.Value)
				}
				if canonicalV002.AttestationKey() != "" && *canonicalV002.IntotoObj.Content.PayloadHash.Value != payloadHash {
					t.Errorf("payload hashes do not match post canonicalization: %v %v", canonicalV002.IntotoObj.Content.PayloadHash.Value, payloadHash)
				}

				return nil
			}
			if err := uv(); (err != nil) != tt.wantErr {
				t.Errorf("V002Entry.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestV002Entry_IndexKeys(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := pem.EncodeToMemory(&pem.Block{
		Bytes: der,
		Type:  "PUBLIC KEY",
	})

	h := sha256.Sum256([]byte("foo"))
	dataSHA := hex.EncodeToString(h[:])
	hashkey := strings.ToLower(fmt.Sprintf("%s:%s", "sha256", dataSHA))
	fmt.Printf("hashkey = %v\n", hashkey)

	tests := []struct {
		name      string
		statement in_toto.Statement
		want      []string
	}{
		{
			name: "standard",
			want: []string{},
			statement: in_toto.Statement{
				Predicate: "hello",
			},
		},
		{
			name: "subject",
			want: []string{"sha256:foo"},
			statement: in_toto.Statement{
				StatementHeader: in_toto.StatementHeader{
					Subject: []in_toto.Subject{
						{
							Name: "foo",
							Digest: map[string]string{
								"sha256": "foo",
							},
						},
					},
				},
				Predicate: "hello",
			},
		},
		{
			name: "slsa",
			want: []string{"sha256:bar"},
			statement: in_toto.Statement{
				Predicate: slsa.ProvenancePredicate{
					Materials: []slsa.ProvenanceMaterial{
						{
							URI: "foo",
							Digest: map[string]string{
								"sha256": "bar",
							}},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.statement)
			if err != nil {
				t.Fatal(err)
			}
			v := &models.IntotoV002Schema{
				Content: &models.IntotoV002SchemaContent{
					Envelope: envelope(t, key, b, in_toto.PayloadType),
					EnvelopeHash: &models.IntotoV002SchemaContentEnvelopeHash{
						Algorithm: swag.String(models.IntotoV002SchemaContentPayloadHashAlgorithmSha256),
					},
				},
				Signature: &models.IntotoV002SchemaSignature{
					PublicKey: &models.IntotoV002SchemaSignaturePublicKey{
						Content: strfmt.Base64(pub),
					},
				},
			}

			envelopeHash := sha256.Sum256([]byte(v.Content.Envelope))
			v.Content.EnvelopeHash.Value = swag.String(fmt.Sprintf("%v", hex.EncodeToString(envelopeHash[:])))

			apiVersion := APIVERSION
			it := &models.Intoto{
				APIVersion: &apiVersion,
				Spec:       v,
			}

			entry, err := types.NewEntry(it)
			if err != nil {
				t.Errorf("unexpected err from type-specific unmarshalling for '%v': %v", tt.name, err)
			}
			sha := sha256.Sum256(b)
			// start with the payload hash
			want := []string{"sha256:" + hex.EncodeToString(sha[:])}
			want = append(want, tt.want...)
			// add the envelope digest
			want = append(want, "sha256:"+*v.Content.EnvelopeHash.Value)
			// add the public key digest
			keySha := sha256.Sum256(pub)
			want = append(want, "sha256:"+hex.EncodeToString(keySha[:]))
			got, err := entry.IndexKeys()
			if err != nil {
				t.Error(err)
			}
			if !cmp.Equal(got, want, cmpopts.SortSlices(func(x, y string) bool { return x < y })) {
				sort.Strings(got)
				sort.Strings(want)
				t.Errorf("V002Entry.IndexKeys() =\n%v, want\n%v", got, want)
			}
		})
	}
}
