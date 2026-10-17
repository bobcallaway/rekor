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

package client

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"time"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/hashicorp/go-cleanhttp"
	retryablehttp "github.com/hashicorp/go-retryablehttp"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/util"
)

// maxErrorBodyBytes caps how much of the final response body we embed in
// the error message to avoid flooding terminals with large payloads.
const maxErrorBodyBytes = 512

// retryErrorHandler makes the final error surfaced after retries include the
// underlying cause (transport error or final response status + body snippet).
// Without a custom handler retryablehttp's default message is just
// "<METHOD> <URL> giving up after N attempt(s)", which hides the actual
// reason the retries failed — especially when the server returned an error
// response (5xx) rather than a transport error. See
// https://github.com/sigstore/rekor/issues/2640.
func retryErrorHandler(resp *http.Response, err error, numTries int) (*http.Response, error) {
	if err != nil {
		return nil, fmt.Errorf("giving up after %d attempt(s): %w", numTries, err)
	}
	if resp != nil {
		defer resp.Body.Close()
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		snippet := string(bytes.TrimSpace(body))
		if readErr == nil && snippet != "" {
			return nil, fmt.Errorf("giving up after %d attempt(s): status %d: %s",
				numTries, resp.StatusCode, snippet)
		}
		return nil, fmt.Errorf("giving up after %d attempt(s): status %d",
			numTries, resp.StatusCode)
	}

	return nil, fmt.Errorf("giving up after %d attempt(s)", numTries)
}

func GetRekorClient(rekorServerURL string, opts ...Option) (*client.Rekor, error) {
	url, err := url.Parse(rekorServerURL)
	if err != nil {
		return nil, err
	}
	o := makeOptions(opts...)

	retryableClient := retryablehttp.NewClient()
	defaultTransport := cleanhttp.DefaultTransport()
	if o.NoDisableKeepalives {
		defaultTransport.DisableKeepAlives = false
	}
	if o.InsecureTLS {
		/* #nosec G402 */
		defaultTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	} else if o.TLSConfig != nil {
		defaultTransport.TLSClientConfig = o.TLSConfig
	}
	retryableClient.HTTPClient = &http.Client{
		Transport: defaultTransport,
	}
	retryableClient.Backoff = retryBackoff
	retryableClient.RetryMax = int(o.RetryCount)
	retryableClient.RetryWaitMin = o.RetryWaitMin
	retryableClient.RetryWaitMax = o.RetryWaitMax
	retryableClient.Logger = o.Logger
	retryableClient.ErrorHandler = retryErrorHandler

	httpClient := retryableClient.StandardClient()
	httpClient.Transport = createRoundTripper(httpClient.Transport, o)

	// sanitize path
	if url.Path == "" {
		url.Path = client.DefaultBasePath
	}

	rt := httptransport.NewWithClient(url.Host, url.Path, []string{url.Scheme}, httpClient)
	rt.Consumers["application/json"] = runtime.JSONConsumer()
	rt.Consumers["application/x-pem-file"] = runtime.TextConsumer()
	rt.Producers["application/json"] = runtime.JSONProducer()

	registry := strfmt.Default
	registry.Add("signedCheckpoint", &util.SignedNote{}, util.SignedCheckpointValidator)
	return client.New(rt, registry), nil
}

// retryBackoff honors Retry-After on 429/503 and adds up to 25% jitter (at
// most one second). Other responses use bounded exponential backoff with
// up to 25% jitter, retaining explicit zero-delay options.
func retryBackoff(min, max time.Duration, attempt int, resp *http.Response) time.Duration {
	// Zero fallback bounds distinguish a positive Retry-After from the
	// library's exponential fallback without duplicating its header parser.
	if delay := retryablehttp.DefaultBackoff(0, 0, attempt, resp); delay > 0 {
		window := delay / 4
		if window > time.Second {
			window = time.Second
		}
		// Avoid overflowing when an unusually large Retry-After is received.
		if delay > time.Duration(1<<63-1)-window {
			return delay
		}
		return delay + time.Duration(rand.Int64N(int64(window)+1))
	}
	delay := retryablehttp.DefaultBackoff(min, max, attempt, nil)
	if delay <= 0 {
		return delay
	}
	window := delay / 4
	if remaining := max - delay; window > remaining {
		window = remaining
	}
	if window <= 0 {
		return delay
	}
	return delay + time.Duration(rand.Int64N(int64(window)+1))
}
