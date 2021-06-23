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

package intoto

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/in-toto/in-toto-golang/pkg/ssl"
	"github.com/spf13/viper"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pki"
	pkifactory "github.com/sigstore/rekor/pkg/pki/factory"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/intoto"
)

const (
	APIVERSION = "0.0.1"
)

func init() {
	if err := intoto.VersionMap.SetEntryFactory(APIVERSION, NewEntry); err != nil {
		log.Logger.Panic(err)
	}
}

type V001Entry struct {
	IntotoObj models.IntotoV001Schema
	keyObj    pki.PublicKey
	env       ssl.Envelope
}

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V001Entry{}
}

func (v V001Entry) IndexKeys() []string {
	var result []string

	h := sha256.Sum256([]byte(v.env.Payload))
	payloadKey := "sha256:" + string(h[:])
	result = append(result, payloadKey)
	return result
}

func (v *V001Entry) Unmarshal(pe models.ProposedEntry) error {
	it, ok := pe.(*models.Intoto)
	if !ok {
		return errors.New("cannot unmarshal non Intoto v0.0.1 type")
	}

	var err error
	if err := types.DecodeEntry(it.Spec, &v.IntotoObj); err != nil {
		return err
	}

	// field validation
	if err := v.IntotoObj.Validate(strfmt.Default); err != nil {
		return err
	}

	// Only support x509 signatures for intoto attestations
	af, err := pkifactory.NewArtifactFactory("x509")
	if err != nil {
		return err
	}

	v.keyObj, err = af.NewPublicKey(bytes.NewReader(*v.IntotoObj.PublicKey))
	if err != nil {
		return err
	}

	return v.Validate()
}

func (v V001Entry) HasExternalEntities() bool {
	return false
}

func (v *V001Entry) FetchExternalEntities(ctx context.Context) error {
	return nil
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	if v.keyObj == nil {
		return nil, errors.New("cannot canonicalze empty key")
	}
	pk, err := v.keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}
	pkb := strfmt.Base64(pk)

	h := sha256.Sum256([]byte(v.IntotoObj.Content.Envelope))

	canonicalEntry := models.IntotoV001Schema{
		PublicKey: &pkb,
		Content: &models.IntotoV001SchemaContent{
			Hash: &models.IntotoV001SchemaContentHash{
				Algorithm: swag.String(models.IntotoV001SchemaContentHashAlgorithmSha256),
				Value:     swag.String(hex.EncodeToString(h[:])),
			},
		},
	}

	itObj := models.Intoto{}
	itObj.APIVersion = swag.String(APIVERSION)
	itObj.Spec = &canonicalEntry

	bytes, err := json.Marshal(&itObj)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

// Validate performs cross-field validation for fields in object
func (v *V001Entry) Validate() error {
	// TODO handle multiple
	sslVerifier, err := ssl.NewEnvelopeSigner(&verifier{pub: v.keyObj})
	if err != nil {
		return err
	}

	if err := json.Unmarshal([]byte(v.IntotoObj.Content.Envelope), &v.env); err != nil {
		return err
	}

	ok, err := sslVerifier.Verify(&v.env)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("invalid signature")
	}

	return nil
}

func (v *V001Entry) Attestation() (string, []byte) {
	if len(v.env.Payload) > viper.GetInt("max_attestation_size") {
		log.Logger.Infof("Skipping attestation storage, size %d is greater than max %d", len(v.env.Payload), viper.GetInt("max_attestation_size"))
		return "", nil
	}
	return v.env.PayloadType, []byte(v.env.Payload)
}

type verifier struct {
	pub    pki.PublicKey
	signer crypto.Signer
}

func (v *verifier) Sign(d []byte) ([]byte, string, error) {
	if v.signer == nil {
		return nil, "", errors.New("nil signer")
	}
	h := sha256.Sum256(d)
	sig, err := v.signer.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, "", err
	}
	return sig, "", nil
}

func (v *verifier) Verify(keyID string, data, sig []byte) (bool, error) {
	af, err := pkifactory.NewArtifactFactory("x509")
	if err != nil {
		return false, err
	}

	s, err := af.NewSignature(bytes.NewReader(sig))
	if err != nil {
		return false, err
	}
	if err := s.Verify(bytes.NewReader(data), v.pub); err != nil {
		return false, err
	}
	return true, nil
}

func (v V001Entry) CreateFromPFlags(_ context.Context, props types.ArtifactProperties) (models.ProposedEntry, error) {
	returnVal := models.Intoto{}

	var err error
	artifactBytes := props.ArtifactBytes
	if artifactBytes == nil {
		if props.ArtifactPath == nil {
			return nil, errors.New("invalid path to artifact specified")
		}
		artifactBytes, err = ioutil.ReadFile(filepath.Clean(props.ArtifactPath.Path))
		if err != nil {
			return nil, err
		}
	}
	publicKeyBytes := props.PublicKeyBytes
	if publicKeyBytes == nil {
		if props.PublicKeyPath == nil {
			return nil, errors.New("invalid path to public key specified")
		}
		publicKeyBytes, err = ioutil.ReadFile(filepath.Clean(props.PublicKeyPath.Path))
		if err != nil {
			return nil, fmt.Errorf("error reading public key file: %w", err)
		}
	}
	kb := strfmt.Base64(publicKeyBytes)

	re := V001Entry{
		IntotoObj: models.IntotoV001Schema{
			Content: &models.IntotoV001SchemaContent{
				Envelope: string(artifactBytes),
			},
			PublicKey: &kb,
		},
	}

	returnVal.Spec = re.IntotoObj
	returnVal.APIVersion = swag.String(re.APIVersion())

	return &returnVal, nil
}
