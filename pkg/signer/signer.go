/*
Copyright 2021 The Sigstore Authors.

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

package signer

import (
	"context"
	"crypto"
	"strings"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"golang.org/x/exp/slices"

	// these are imported to load the providers via init() calls
	_ "github.com/sigstore/sigstore/pkg/signature/kms/aws"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/azure"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/gcp"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/hashivault"
)

// SigningConfig initializes the signer for a specific shard
type SigningConfig struct {
	SigningSchemeOrKeyPath string `json:"signingSchemeOrKeyPath" yaml:"signingSchemeOrKeyPath"`
	FileSignerPassword     string `json:"fileSignerPassword" yaml:"fileSignerPassword"`
	TinkKEKURI             string `json:"tinkKEKURI" yaml:"tinkKEKURI"`
	TinkKeysetPath         string `json:"tinkKeysetPath" yaml:"tinkKeysetPath"`
}

func (sc SigningConfig) IsUnset() bool {
	return sc.SigningSchemeOrKeyPath == "" && sc.FileSignerPassword == "" &&
		sc.TinkKEKURI == "" && sc.TinkKeysetPath == ""
}

func New(ctx context.Context, signer, pass, tinkKEKURI, tinkKeysetPath string) (signature.Signer, error) {
	switch {
	case slices.ContainsFunc(kms.SupportedProviders(),
		func(s string) bool {
			return strings.HasPrefix(signer, s)
		}):
		return kms.Get(ctx, signer, crypto.SHA256)
	case signer == MemoryScheme:
		return NewMemory()
	case signer == TinkScheme:
		return NewTinkSigner(ctx, tinkKEKURI, tinkKeysetPath)
	default:
		return NewFile(signer, pass)
	}
}
