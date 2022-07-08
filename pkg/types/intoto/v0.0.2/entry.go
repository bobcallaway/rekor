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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/spf13/viper"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/intoto"
	"github.com/sigstore/sigstore/pkg/signature"
	dsse_verifier "github.com/sigstore/sigstore/pkg/signature/dsse"
)

const (
	APIVERSION = "0.0.2"
)

func init() {
	if err := intoto.VersionMap.SetEntryFactory(APIVERSION, NewEntry); err != nil {
		log.Logger.Panic(err)
	}
}

type V002Entry struct {
	IntotoObj models.IntotoV002Schema
	keyObj    pki.PublicKey
	sigObj    pki.Signature
	statement *in_toto.Statement
	env       *dsse.Envelope
}

func (v V002Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V002Entry{}
}

func (v V002Entry) IndexKeys() ([]string, error) {
	var result []string

	// add digest over entire DSSE envelope
	if v.IntotoObj.Content != nil && v.IntotoObj.Content.EnvelopeHash != nil {
		hashkey := strings.ToLower(fmt.Sprintf("%s:%s", swag.StringValue(v.IntotoObj.Content.EnvelopeHash.Algorithm), swag.StringValue(v.IntotoObj.Content.EnvelopeHash.Value)))
		result = append(result, hashkey)
	} else {
		log.Logger.Error("could not find content digest to include in index keys")
	}

	// add digest over public key
	if v.keyObj != nil {
		key, err := v.keyObj.CanonicalValue()
		if err == nil {
			keyHash := sha256.Sum256(key)
			result = append(result, fmt.Sprintf("sha256:%s", strings.ToLower(hex.EncodeToString(keyHash[:]))))

			// add digest over any subjects within signing certificate
			result = append(result, v.keyObj.Subjects()...)
		} else {
			log.Logger.Errorf("could not canonicalize public key to include in index keys: %v", err)
		}
	} else {
		log.Logger.Error("could not find public key to include in index keys")
	}

	// add digest base64-decoded payload inside of DSSE envelope
	payloadBytes, err := base64.StdEncoding.DecodeString(v.env.Payload)
	if err == nil {
		payloadHash := sha256.Sum256(payloadBytes)
		result = append(result, fmt.Sprintf("sha256:%s", strings.ToLower(hex.EncodeToString(payloadHash[:]))))
	} else {
		log.Logger.Errorf("error decoding intoto payload to compute digest: %v", err)
	}

	switch v.env.PayloadType {
	case in_toto.PayloadType:
		if v.statement != nil {
			for _, s := range v.statement.Subject {
				for alg, ds := range s.Digest {
					result = append(result, alg+":"+ds)
				}
			}
		}
		// Not all in-toto statements will contain a SLSA provenance predicate.
		// See https://github.com/in-toto/attestation/blob/main/spec/README.md#predicate
		// for other predicates.
		if predicate, err := parseSlsaPredicate(v.env.Payload); err == nil {
			if predicate.Predicate.Materials != nil {
				for _, s := range predicate.Predicate.Materials {
					for alg, ds := range s.Digest {
						result = append(result, alg+":"+ds)
					}
				}
			}
		}
	default:
		log.Logger.Infof("unknown in_toto statement type (%s), cannot extract additional index keys", v.env.PayloadType)
	}
	return result, nil
}

func parseStatement(p string) (*in_toto.Statement, error) {
	ps := &in_toto.Statement{}
	payload, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(payload, ps); err != nil {
		return nil, err
	}
	return ps, nil
}

func parseSlsaPredicate(p string) (*in_toto.ProvenanceStatement, error) {
	predicate := &in_toto.ProvenanceStatement{}
	payload, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(payload, predicate); err != nil {
		return nil, err
	}
	return predicate, nil
}

func (v *V002Entry) Unmarshal(pe models.ProposedEntry) error {
	it, ok := pe.(*models.Intoto)
	if !ok {
		return errors.New("cannot unmarshal non Intoto v0.0.2 type")
	}

	var err error
	if err := types.DecodeEntry(it.Spec, &v.IntotoObj); err != nil {
		return err
	}

	// field validation
	if err := v.IntotoObj.Validate(strfmt.Default); err != nil {
		return err
	}

	v.keyObj, err = x509.NewPublicKey(bytes.NewReader(v.IntotoObj.Signature.PublicKey.Content))
	if err != nil {
		return err
	}

	return v.validate()
}

func (v *V002Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	if v.keyObj == nil {
		return nil, errors.New("cannot canonicalze empty key")
	}
	pk, err := v.keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}
	pkb := strfmt.Base64(pk)

	sig, err := v.sigObj.CanonicalValue()
	if err != nil {
		return nil, err
	}
	skb := strfmt.Base64(sig)

	h := sha256.Sum256([]byte(v.IntotoObj.Content.Envelope))

	canonicalEntry := models.IntotoV002Schema{
		Content: &models.IntotoV002SchemaContent{
			EnvelopeHash: &models.IntotoV002SchemaContentEnvelopeHash{
				Algorithm: swag.String(models.IntotoV002SchemaContentEnvelopeHashAlgorithmSha256),
				Value:     swag.String(hex.EncodeToString(h[:])),
			},
		},
		Signature: &models.IntotoV002SchemaSignature{
			PublicKey: &models.IntotoV002SchemaSignaturePublicKey{
				Content: pkb,
			},
			Content: skb,
		},
	}
	if attKey, attValue := v.AttestationKeyValue(); attValue != nil {
		canonicalEntry.Content.PayloadHash = &models.IntotoV002SchemaContentPayloadHash{
			Algorithm: swag.String(models.IntotoV002SchemaContentPayloadHashAlgorithmSha256),
			Value:     swag.String(strings.Replace(attKey, fmt.Sprintf("%s:", models.IntotoV002SchemaContentPayloadHashAlgorithmSha256), "", 1)),
		}
	}

	itObj := models.Intoto{}
	itObj.APIVersion = swag.String(APIVERSION)
	itObj.Spec = &canonicalEntry

	return json.Marshal(&itObj)
}

// validate performs cross-field validation for fields in object
func (v *V002Entry) validate() error {
	// TODO handle multiple
	pk := v.keyObj.(*x509.PublicKey)

	// This also gets called in the CLI, where we won't have this data
	if v.IntotoObj.Content.Envelope == "" {
		return nil
	}
	vfr, err := signature.LoadVerifier(pk.CryptoPubKey(), crypto.SHA256)
	if err != nil {
		return err
	}
	dsseVerifier := dsse_verifier.WrapVerifier(vfr)

	if err := dsseVerifier.VerifySignature(strings.NewReader(v.IntotoObj.Content.Envelope), nil); err != nil {
		return err
	}

	env := dsse.Envelope{}
	if err := json.Unmarshal([]byte(v.IntotoObj.Content.Envelope), &env); err != nil {
		return err
	}

	if env.PayloadType != in_toto.PayloadType {
		return fmt.Errorf("envelope payload type must be %v", in_toto.PayloadType)
	}
	statement, err := parseStatement(env.Payload)
	if err != nil {
		return err
	}

	if len(env.Signatures) != 1 {
		return errors.New("multiple signatures are not supported in the intoto v0.0.2 type")
	}
	sigObj, err := x509.NewSignature(base64.NewDecoder(base64.StdEncoding, strings.NewReader(env.Signatures[0].Sig)))
	if err != nil {
		return err
	}

	v.env = &env
	v.statement = statement
	v.sigObj = sigObj
	return nil
}

// AttestationKey returns the digest of the attestation that was uploaded, to be used to lookup the attestation from storage
func (v *V002Entry) AttestationKey() string {
	if v.IntotoObj.Content != nil && v.IntotoObj.Content.PayloadHash != nil {
		return fmt.Sprintf("%s:%s", *v.IntotoObj.Content.PayloadHash.Algorithm, *v.IntotoObj.Content.PayloadHash.Value)
	}
	return ""
}

// AttestationKeyValue returns both the key and value to be persisted into attestation storage
func (v *V002Entry) AttestationKeyValue() (string, []byte) {
	storageSize := base64.StdEncoding.DecodedLen(len(v.env.Payload))
	if storageSize > viper.GetInt("max_attestation_size") {
		log.Logger.Infof("Skipping attestation storage, size %d is greater than max %d", storageSize, viper.GetInt("max_attestation_size"))
		return "", nil
	}
	attBytes, _ := base64.StdEncoding.DecodeString(v.env.Payload)
	attHash := sha256.Sum256(attBytes)
	attKey := fmt.Sprintf("%s:%s", models.IntotoV002SchemaContentPayloadHashAlgorithmSha256, hex.EncodeToString(attHash[:]))
	return attKey, attBytes
}

func (v V002Entry) CreateFromArtifactProperties(_ context.Context, props types.ArtifactProperties) (models.ProposedEntry, error) {
	returnVal := models.Intoto{}

	var err error
	artifactBytes := props.ArtifactBytes
	if artifactBytes == nil {
		if props.ArtifactPath == nil {
			return nil, errors.New("path to artifact file must be specified")
		}
		if props.ArtifactPath.IsAbs() {
			return nil, errors.New("intoto envelopes cannot be fetched over HTTP(S)")
		}
		artifactBytes, err = ioutil.ReadFile(filepath.Clean(props.ArtifactPath.Path))
		if err != nil {
			return nil, err
		}
	}
	publicKeyBytes := props.PublicKeyBytes
	if publicKeyBytes == nil {
		if props.PublicKeyPath == nil {
			return nil, errors.New("public key must be provided to verify signature")
		}
		publicKeyBytes, err = ioutil.ReadFile(filepath.Clean(props.PublicKeyPath.Path))
		if err != nil {
			return nil, fmt.Errorf("error reading public key file: %w", err)
		}
	}
	kb := strfmt.Base64(publicKeyBytes)

	re := V002Entry{
		IntotoObj: models.IntotoV002Schema{
			Content: &models.IntotoV002SchemaContent{
				Envelope: string(artifactBytes),
			},
			Signature: &models.IntotoV002SchemaSignature{
				PublicKey: &models.IntotoV002SchemaSignaturePublicKey{
					Content: kb,
				},
			},
		},
	}
	h := sha256.Sum256([]byte(re.IntotoObj.Content.Envelope))
	re.IntotoObj.Content.EnvelopeHash = &models.IntotoV002SchemaContentEnvelopeHash{
		Algorithm: swag.String(models.IntotoV002SchemaContentEnvelopeHashAlgorithmSha256),
		Value:     swag.String(hex.EncodeToString(h[:])),
	}

	returnVal.Spec = re.IntotoObj
	returnVal.APIVersion = swag.String(re.APIVersion())

	return &returnVal, nil
}
