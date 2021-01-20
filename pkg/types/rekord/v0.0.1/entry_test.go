/*
Copyright © 2020 Bob Callaway <bcallawa@redhat.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package rekord

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/go-openapi/swag"
	"github.com/projectrekor/rekor/pkg/generated/models"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestNewEntryReturnType(t *testing.T) {
	entry := NewEntry()
	if reflect.TypeOf(entry) != reflect.ValueOf(&V001Entry{}).Type() {
		t.Errorf("invalid type returned from NewEntry: %T", entry)
	}
}

func TestCrossFieldValidation(t *testing.T) {
	type TestCase struct {
		caseDesc                  string
		entry                     V001Entry
		hasExtEntities            bool
		expectUnmarshalSuccess    bool
		expectCanonicalizeSuccess bool
	}

	sigBytes, _ := ioutil.ReadFile("../../../../tests/test_file.sig")
	keyBytes, _ := ioutil.ReadFile("../../../../tests/test_public_key.key")
	dataBytes, _ := ioutil.ReadFile("../../../../tests/test_file.txt")

	h := sha256.New()
	_, _ = h.Write(dataBytes)
	dataSHA := hex.EncodeToString(h.Sum(nil))

	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			file := &sigBytes
			var err error

			switch r.URL.Path {
			case "/signature":
				file = &sigBytes
			case "/key":
				file = &keyBytes
			case "/data":
				file = &dataBytes
			default:
				err = errors.New("unknown URL")
			}
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(*file)
		}))
	defer testServer.Close()

	testCases := []TestCase{
		{
			caseDesc:               "empty obj",
			entry:                  V001Entry{},
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature without url or content",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
					},
				},
			},
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature without public key",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    models.RekordURL(testServer.URL + "/signature"),
					},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature with empty public key",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:    "pgp",
						URL:       models.RekordURL(testServer.URL + "/signature"),
						PublicKey: &models.RekordPublicKey{},
					},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature without data",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    models.RekordURL(testServer.URL + "/signature"),
						PublicKey: &models.RekordPublicKey{
							URL: models.RekordURL(testServer.URL + "/key"),
						},
					},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature with empty data",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    models.RekordURL(testServer.URL + "/signature"),
						PublicKey: &models.RekordPublicKey{
							URL: models.RekordURL(testServer.URL + "/key"),
						},
					},
					Data: &models.RekordData{},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature with data & url but no hash",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    models.RekordURL(testServer.URL + "/signature"),
						PublicKey: &models.RekordPublicKey{
							URL: models.RekordURL(testServer.URL + "/key"),
						},
					},
					Data: &models.RekordData{
						URL: models.RekordURL(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature with data & url and empty hash",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    models.RekordURL(testServer.URL + "/signature"),
						PublicKey: &models.RekordPublicKey{
							URL: models.RekordURL(testServer.URL + "/key"),
						},
					},
					Data: &models.RekordData{
						Hash: &models.RekordHash{},
						URL:  models.RekordURL(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature with data & url and hash missing value",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    models.RekordURL(testServer.URL + "/signature"),
						PublicKey: &models.RekordPublicKey{
							URL: models.RekordURL(testServer.URL + "/key"),
						},
					},
					Data: &models.RekordData{
						Hash: &models.RekordHash{
							Algorithm: swag.String(models.RekordHashAlgorithmSha256),
						},
						URL: models.RekordURL(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:         true,
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature with data & url with 404 error on signature",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    models.RekordURL(testServer.URL + "/404"),
						PublicKey: &models.RekordPublicKey{
							URL: models.RekordURL(testServer.URL + "/key"),
						},
					},
					Data: &models.RekordData{
						Hash: &models.RekordHash{
							Algorithm: swag.String(models.RekordHashAlgorithmSha256),
							Value:     swag.String(dataSHA),
						},
						URL: models.RekordURL(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "signature with data & url with 404 error on key",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    models.RekordURL(testServer.URL + "/signature"),
						PublicKey: &models.RekordPublicKey{
							URL: models.RekordURL(testServer.URL + "/404"),
						},
					},
					Data: &models.RekordData{
						Hash: &models.RekordHash{
							Algorithm: swag.String(models.RekordHashAlgorithmSha256),
							Value:     swag.String(dataSHA),
						},
						URL: models.RekordURL(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "signature with data & url with 404 error on data",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    models.RekordURL(testServer.URL + "/signature"),
						PublicKey: &models.RekordPublicKey{
							URL: models.RekordURL(testServer.URL + "/key"),
						},
					},
					Data: &models.RekordData{
						Hash: &models.RekordHash{
							Algorithm: swag.String(models.RekordHashAlgorithmSha256),
							Value:     swag.String(dataSHA),
						},
						URL: models.RekordURL(testServer.URL + "/404"),
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "signature with invalid sig content, key content & with data with content",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  "pgp",
						Content: models.RekordContent(dataBytes),
						PublicKey: &models.RekordPublicKey{
							Content: models.RekordContent(keyBytes),
						},
					},
					Data: &models.RekordData{
						Content: models.RekordContent(dataBytes),
					},
				},
			},
			hasExtEntities:            false,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "signature with sig content, invalid key content & with data with content",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  "pgp",
						Content: models.RekordContent(sigBytes),
						PublicKey: &models.RekordPublicKey{
							Content: models.RekordContent(dataBytes),
						},
					},
					Data: &models.RekordData{
						Content: models.RekordContent(dataBytes),
					},
				},
			},
			hasExtEntities:            false,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "signature with sig content, key content & with data with content",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  "pgp",
						Content: models.RekordContent(sigBytes),
						PublicKey: &models.RekordPublicKey{
							Content: models.RekordContent(dataBytes),
						},
					},
					Data: &models.RekordData{
						Content: models.RekordContent(dataBytes),
					},
				},
			},
			hasExtEntities:            false,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "signature with data & url and incorrect hash value",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    models.RekordURL(testServer.URL + "/signature"),
						PublicKey: &models.RekordPublicKey{
							URL: models.RekordURL(testServer.URL + "/key"),
						},
					},
					Data: &models.RekordData{
						Hash: &models.RekordHash{
							Algorithm: swag.String(models.RekordHashAlgorithmSha256),
							Value:     swag.String("3030303030303030303030303030303030303030303030303030303030303030"),
						},
						URL: models.RekordURL(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "signature with data & url and complete hash value",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    models.RekordURL(testServer.URL + "/signature"),
						PublicKey: &models.RekordPublicKey{
							URL: models.RekordURL(testServer.URL + "/key"),
						},
					},
					Data: &models.RekordData{
						Hash: &models.RekordHash{
							Algorithm: swag.String(models.RekordHashAlgorithmSha256),
							Value:     swag.String(dataSHA),
						},
						URL: models.RekordURL(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
		{
			caseDesc: "signature with sig content, url key & with data with url and complete hash value",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  "pgp",
						Content: models.RekordContent(sigBytes),
						PublicKey: &models.RekordPublicKey{
							URL: models.RekordURL(testServer.URL + "/key"),
						},
					},
					Data: &models.RekordData{
						Hash: &models.RekordHash{
							Algorithm: swag.String(models.RekordHashAlgorithmSha256),
							Value:     swag.String(dataSHA),
						},
						URL: models.RekordURL(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
		{
			caseDesc: "signature with sig url, key content & with data with url and complete hash value",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format: "pgp",
						URL:    models.RekordURL(testServer.URL + "/signature"),
						PublicKey: &models.RekordPublicKey{
							Content: models.RekordContent(keyBytes),
						},
					},
					Data: &models.RekordData{
						Hash: &models.RekordHash{
							Algorithm: swag.String(models.RekordHashAlgorithmSha256),
							Value:     swag.String(dataSHA),
						},
						URL: models.RekordURL(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
		{
			caseDesc: "signature with sig content, key content & with data with url and complete hash value",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  "pgp",
						Content: models.RekordContent(sigBytes),
						PublicKey: &models.RekordPublicKey{
							Content: models.RekordContent(keyBytes),
						},
					},
					Data: &models.RekordData{
						Hash: &models.RekordHash{
							Algorithm: swag.String(models.RekordHashAlgorithmSha256),
							Value:     swag.String(dataSHA),
						},
						URL: models.RekordURL(testServer.URL + "/data"),
					},
				},
			},
			hasExtEntities:            true,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
		{
			caseDesc: "signature with sig content, key content & with data with content",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  "pgp",
						Content: models.RekordContent(sigBytes),
						PublicKey: &models.RekordPublicKey{
							Content: models.RekordContent(keyBytes),
						},
					},
					Data: &models.RekordData{
						Content: models.RekordContent(dataBytes),
					},
				},
			},
			hasExtEntities:            false,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
		{
			caseDesc: "valid obj with extradata",
			entry: V001Entry{
				RekordObj: models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Format:  "pgp",
						Content: models.RekordContent(sigBytes),
						PublicKey: &models.RekordPublicKey{
							Content: models.RekordContent(keyBytes),
						},
					},
					Data: &models.RekordData{
						Content: models.RekordContent(dataBytes),
					},
					ExtraData: []byte("{\"something\": \"here\""),
				},
			},
			hasExtEntities:            false,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
	}

	for _, tc := range testCases {
		if err := tc.entry.Validate(); (err == nil) != tc.expectUnmarshalSuccess {
			t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
		}

		v := &V001Entry{}
		r := models.Rekord{
			APIVersion: swag.String(tc.entry.APIVersion()),
			Spec:       tc.entry.RekordObj,
		}
		if err := v.Unmarshal(&r); (err == nil) != tc.expectUnmarshalSuccess {
			t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
		}

		if tc.entry.HasExternalEntities() != tc.hasExtEntities {
			t.Errorf("unexpected result from HasExternalEntities for '%v'", tc.caseDesc)
		}

		if _, err := tc.entry.Canonicalize(context.TODO()); (err == nil) != tc.expectCanonicalizeSuccess {
			t.Errorf("unexpected result from Canonicalize for '%v': %v", tc.caseDesc, err)
		}
	}
}
