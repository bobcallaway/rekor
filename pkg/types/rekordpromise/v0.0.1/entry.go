/*
Copyright © 2021 Bob Callaway <bcallawa@redhat.com>

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
package rekordpromise

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/projectrekor/rekor/pkg/log"
	"github.com/projectrekor/rekor/pkg/types"
	"github.com/projectrekor/rekor/pkg/util"

	"github.com/asaskevich/govalidator"

	"github.com/go-openapi/strfmt"

	"github.com/projectrekor/rekor/pkg/pki"
	"github.com/projectrekor/rekor/pkg/types/rekordpromise"

	"github.com/go-openapi/swag"
	"github.com/mitchellh/mapstructure"
	"github.com/projectrekor/rekor/pkg/generated/models"
	"golang.org/x/sync/errgroup"
)

const (
	APIVERSION = "0.0.1"
)

func init() {
	rekordpromise.SemVerToFacFnMap.Set(APIVERSION, NewEntry)
}

type V001PromiseEntry struct {
	RekordPromiseObj        models.RekordPromiseV001Schema
	fetchedExternalEntities bool
	keyObj                  pki.PublicKey
}

func (v V001PromiseEntry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V001PromiseEntry{}
}

func Base64StringtoByteArray() mapstructure.DecodeHookFunc {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String || t.Kind() != reflect.Slice {
			return data, nil
		}

		bytes, err := base64.StdEncoding.DecodeString(data.(string))
		if err != nil {
			return []byte{}, fmt.Errorf("failed parsing base64 data: %v", err)
		}
		return bytes, nil
	}
}

func (v V001PromiseEntry) IndexKeys() []string {
	var result []string

	if v.HasExternalEntities() {
		if err := v.FetchExternalEntities(context.Background()); err != nil {
			log.Logger.Error(err)
			return result
		}
	}

	key, err := v.keyObj.CanonicalValue()
	if err != nil {
		log.Logger.Error(err)
	} else {
		hasher := sha256.New()
		if _, err := hasher.Write(key); err != nil {
			log.Logger.Error(err)
		} else {
			result = append(result, strings.ToLower(hex.EncodeToString(hasher.Sum(nil))))
		}
	}

	if v.RekordPromiseObj.Data.Hash != nil {
		result = append(result, strings.ToLower(swag.StringValue(v.RekordPromiseObj.Data.Hash.Value)))
	}

	return result
}

func (v *V001PromiseEntry) Unmarshal(pe models.ProposedEntry) error {
	rekordPromise, ok := pe.(*models.RekordPromise)
	if !ok {
		return errors.New("cannot unmarshal non Rekord v0.0.1 type")
	}

	cfg := mapstructure.DecoderConfig{
		DecodeHook: Base64StringtoByteArray(),
		Result:     &v.RekordPromiseObj,
	}

	dec, err := mapstructure.NewDecoder(&cfg)
	if err != nil {
		return fmt.Errorf("error initializing decoder: %w", err)
	}

	if err := dec.Decode(rekordPromise.Spec); err != nil {
		return err
	}
	// field validation
	if err := v.RekordPromiseObj.Validate(strfmt.Default); err != nil {
		return err
	}
	// cross field validation
	return v.Validate()

}

func (v V001PromiseEntry) HasExternalEntities() bool {
	if v.fetchedExternalEntities {
		return false
	}

	if v.RekordPromiseObj.Data != nil && v.RekordPromiseObj.Data.URL != "" {
		return true
	}
	if v.RekordPromiseObj.Signature != nil && v.RekordPromiseObj.Signature.PublicKey != nil && v.RekordPromiseObj.Signature.PublicKey.URL != "" {
		return true
	}
	return false
}

func (v *V001PromiseEntry) FetchExternalEntities(ctx context.Context) error {
	if v.fetchedExternalEntities {
		return nil
	}

	if err := v.Validate(); err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)

	hashR, hashW := io.Pipe()
	defer hashR.Close()

	closePipesOnError := func(err error) error {
		if e := hashR.CloseWithError(err); e != nil {
			log.Logger.Error(fmt.Errorf("error closing pipe: %w", e))
		}
		if e := hashW.CloseWithError(err); e != nil {
			log.Logger.Error(fmt.Errorf("error closing pipe: %w", e))
		}
		return err
	}

	oldSHA := ""
	if v.RekordPromiseObj.Data.Hash != nil && v.RekordPromiseObj.Data.Hash.Value != nil {
		oldSHA = swag.StringValue(v.RekordPromiseObj.Data.Hash.Value)
	}
	artifactFactory := pki.NewArtifactFactory(string(v.RekordPromiseObj.Signature.Format))

	g.Go(func() error {
		defer hashW.Close()

		dataReadCloser, err := util.FileOrURLReadCloser(ctx, string(v.RekordPromiseObj.Data.URL), v.RekordPromiseObj.Data.Content, true)
		if err != nil {
			return closePipesOnError(err)
		}
		defer dataReadCloser.Close()

		/* #nosec G110 */
		if _, err := io.Copy(hashW, dataReadCloser); err != nil {
			return closePipesOnError(err)
		}
		return nil
	})

	hashResult := make(chan string)

	g.Go(func() error {
		defer close(hashResult)
		hasher := sha256.New()

		if _, err := io.Copy(hasher, hashR); err != nil {
			return closePipesOnError(err)
		}

		computedSHA := hex.EncodeToString(hasher.Sum(nil))
		if oldSHA != "" && computedSHA != oldSHA {
			return closePipesOnError(fmt.Errorf("SHA mismatch: %s != %s", computedSHA, oldSHA))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case hashResult <- computedSHA:
			return nil
		}
	})

	g.Go(func() error {
		keyReadCloser, err := util.FileOrURLReadCloser(ctx, string(v.RekordPromiseObj.Signature.PublicKey.URL),
			v.RekordPromiseObj.Signature.PublicKey.Content, false)
		if err != nil {
			return closePipesOnError(err)
		}
		defer keyReadCloser.Close()

		key, err := artifactFactory.NewPublicKey(keyReadCloser)
		if err != nil {
			return closePipesOnError(err)
		}
		v.keyObj = key

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	})

	computedSHA := <-hashResult

	if err := g.Wait(); err != nil {
		return err
	}

	// if we get here, all goroutines succeeded without error
	if oldSHA == "" {
		v.RekordPromiseObj.Data.Hash = &models.RekordHash{}
		v.RekordPromiseObj.Data.Hash.Algorithm = swag.String(models.RekordHashAlgorithmSha256)
		v.RekordPromiseObj.Data.Hash.Value = swag.String(computedSHA)
	}

	v.fetchedExternalEntities = true
	return nil
}

func (v *V001PromiseEntry) Canonicalize(ctx context.Context) ([]byte, error) {
	if err := v.FetchExternalEntities(ctx); err != nil {
		return nil, err
	}
	if v.keyObj == nil {
		return nil, errors.New("key object not initialized before canonicalization")
	}

	canonicalEntry := models.RekordPromiseV001Schema{}
	canonicalEntry.ExtraData = v.RekordPromiseObj.ExtraData

	// need to canonicalize key content
	canonicalEntry.Signature = &models.RekordPromiseV001SchemaSignature{}

	// key URL (if known) is not set deliberately
	var err error
	canonicalEntry.Signature.Format = v.RekordPromiseObj.Signature.Format
	canonicalEntry.Signature.PublicKey = &models.RekordPublicKey{}
	canonicalEntry.Signature.PublicKey.Content, err = v.keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}

	canonicalEntry.Data = &models.RekordData{}
	canonicalEntry.Data.Hash = v.RekordPromiseObj.Data.Hash
	// data content is not set deliberately

	// ExtraData is copied through unfiltered
	canonicalEntry.ExtraData = v.RekordPromiseObj.ExtraData

	// wrap in valid object with kind and apiVersion set
	rekordPromiseObj := models.RekordPromise{}
	rekordPromiseObj.APIVersion = swag.String(APIVERSION)
	rekordPromiseObj.Spec = &canonicalEntry

	bytes, err := json.Marshal(&rekordPromiseObj)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

//Validate performs cross-field validation for fields in object
func (v V001PromiseEntry) Validate() error {

	sig := v.RekordPromiseObj.Signature
	if sig == nil {
		return errors.New("missing signature")
	}

	key := sig.PublicKey
	if key == nil {
		return errors.New("missing public key")
	}
	if len(key.Content) == 0 && key.URL == "" {
		return errors.New("one of 'content' or 'url' must be specified for publicKey")
	}

	data := v.RekordPromiseObj.Data
	if data == nil {
		return errors.New("missing data")
	}

	if len(data.Content) == 0 && data.URL == "" {
		return errors.New("one of 'content' or 'url' must be specified for data")
	}

	hash := data.Hash
	if data.URL != "" && hash == nil {
		return errors.New("hash must be specified if 'url' is present for data")
	}

	if hash != nil {
		if !govalidator.IsHash(swag.StringValue(hash.Value), swag.StringValue(hash.Algorithm)) {
			return errors.New("invalid value for hash")
		}
	}

	return nil
}
