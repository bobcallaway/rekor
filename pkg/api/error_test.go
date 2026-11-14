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

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-openapi/runtime"
	internalclient "github.com/sigstore/rekor/internal/trillianclient"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/entries"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestMapGRPCToHTTP(t *testing.T) {
	tests := []struct {
		code int
		err  error
		want int
	}{
		{http.StatusOK, status.Error(codes.Canceled, "context canceled"), http.StatusOK},
		{http.StatusInternalServerError, status.Error(codes.Canceled, "context canceled"), 499},
		{http.StatusInternalServerError, status.Error(codes.DeadlineExceeded, "deadline exceeded"), http.StatusGatewayTimeout},
		{http.StatusInternalServerError, status.Error(codes.DataLoss, "dataloss"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		if got := mapGRPCToHTTP(tt.code, tt.err); got != tt.want {
			t.Errorf("mapGRPCToHTTP(%v, %v) = %v, want %v", tt.code, tt.err, got, tt.want)
		}
	}
}

func TestHandleRekorAPIError_ClientCanceled(t *testing.T) {
	// Case 1: When client context is NOT canceled, we expect a standard HTTP 500 response.
	t.Run("Context not canceled returns 500", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/log/entries?logIndex=1", nil)
		params := entries.GetLogEntryByIndexParams{
			HTTPRequest: req,
			LogIndex:    1,
		}

		responder := handleRekorAPIError(params, http.StatusInternalServerError, errors.New("underlying error"), "some server error message")

		recorder := httptest.NewRecorder()
		responder.WriteResponse(recorder, runtime.JSONProducer())

		if recorder.Code != http.StatusInternalServerError {
			t.Errorf("Expected status code %d, got %d", http.StatusInternalServerError, recorder.Code)
		}
	})

	// Case 2: When client context IS canceled (simulating a disconnect), we expect HTTP 499.
	t.Run("Context canceled returns 499", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel the context to simulate client disconnect mid-flight

		req := httptest.NewRequest("GET", "/api/v1/log/entries?logIndex=1", nil).WithContext(ctx)
		params := entries.GetLogEntryByIndexParams{
			HTTPRequest: req,
			LogIndex:    1,
		}

		responder := handleRekorAPIError(params, http.StatusInternalServerError, errors.New("underlying error"), "some server error message")

		recorder := httptest.NewRecorder()
		responder.WriteResponse(recorder, runtime.JSONProducer())

		if recorder.Code != 499 {
			t.Errorf("Expected status code 499, got %d", recorder.Code)
		}
	})

	// Case 3: a wrapped gRPC Canceled error downgrades to 499 even though the
	// request context is still live, so the empty message must not fall through
	// to http.StatusText(499), which is "".
	t.Run("Canceled gRPC error populates default message", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/log/entries?logIndex=1", nil)
		params := entries.GetLogEntryByIndexParams{
			HTTPRequest: req,
			LogIndex:    1,
		}

		err := fmt.Errorf("wrapped: %w", status.Error(codes.Canceled, "context canceled"))
		responder := handleRekorAPIError(params, http.StatusInternalServerError, err, "")

		recorder := httptest.NewRecorder()
		responder.WriteResponse(recorder, runtime.JSONProducer())

		if recorder.Code != 499 {
			t.Errorf("Expected status code 499, got %d", recorder.Code)
		}

		var payload models.Error
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatalf("could not decode response body: %v", err)
		}
		if payload.Message != clientDisconnected {
			t.Errorf("Expected message %q, got %q", clientDisconnected, payload.Message)
		}
	})
}

func TestCreateLogEntryLocalOverload(t *testing.T) {
	for _, tt := range []struct {
		name       string
		err        error
		code       int
		retryAfter string
	}{
		{"local admission", internalclient.ErrPendingWritesFull, http.StatusServiceUnavailable, "1"},
		{"wrapped admission", fmt.Errorf("add leaf: %w", internalclient.ErrPendingWritesFull), http.StatusServiceUnavailable, "1"},
		{"identical backend status", status.Error(codes.ResourceExhausted, internalclient.ErrPendingWritesFull.Error()), http.StatusInternalServerError, ""},
		{"backend exhaustion", status.Error(codes.ResourceExhausted, "backend limit"), http.StatusInternalServerError, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			params := entries.CreateLogEntryParams{HTTPRequest: httptest.NewRequest(http.MethodPost, "/api/v1/log/entries", nil)}
			response := handleRekorAPIError(params, http.StatusInternalServerError, tt.err, trillianUnexpectedResult)
			recorder := httptest.NewRecorder()
			response.WriteResponse(recorder, runtime.JSONProducer())
			if recorder.Code != tt.code {
				t.Fatalf("status: got %d, want %d", recorder.Code, tt.code)
			}
			if got := recorder.Header().Get("Retry-After"); got != tt.retryAfter {
				t.Fatalf("Retry-After: got %q, want %q", got, tt.retryAfter)
			}
			var payload models.Error
			if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Code != int64(tt.code) {
				t.Fatalf("body code: %d", payload.Code)
			}
			if tt.retryAfter != "" && payload.Message != "too many writes are pending; retry later" {
				t.Fatalf("unexpected message: %q", payload.Message)
			}
		})
	}
}

func TestCheckpointSigningOverloadResponse(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/log/entries?logIndex=0", nil)
	params := entries.GetLogEntryByIndexParams{HTTPRequest: req}
	response := handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("checkpoint: %w", errCheckpointSigningFull), sthGenerateError)
	recorder := httptest.NewRecorder()
	response.WriteResponse(recorder, runtime.JSONProducer())
	if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") != "1" {
		t.Fatalf("unexpected overload response: %d %v", recorder.Code, recorder.Header())
	}
}

func TestProofQueueOverloadResponse(t *testing.T) {
	for _, endpoint := range []string{"index", "uuid", "create", "search"} {
		for _, kind := range []string{"local", "wrapped", "backend", "canceled"} {
			t.Run(endpoint+"/"+kind, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/api/v1/log/entries", nil)
				err := error(internalclient.ErrProofQueueFull)
				wantCode, wantRetry := http.StatusServiceUnavailable, "1"
				switch kind {
				case "wrapped":
					err = fmt.Errorf("proof: %w", err)
				case "backend":
					err = status.Error(codes.ResourceExhausted, err.Error())
					wantCode, wantRetry = http.StatusInternalServerError, ""
				case "canceled":
					ctx, cancel := context.WithCancel(req.Context())
					cancel()
					req = req.WithContext(ctx)
					wantCode, wantRetry = statusClientClosedRequest, ""
				}
				var params any
				switch endpoint {
				case "index":
					params = entries.GetLogEntryByIndexParams{HTTPRequest: req}
				case "uuid":
					params = entries.GetLogEntryByUUIDParams{HTTPRequest: req}
				case "create":
					params = entries.CreateLogEntryParams{HTTPRequest: req}
				case "search":
					params = entries.SearchLogQueryParams{HTTPRequest: req}
				}
				response := handleRekorAPIError(params, http.StatusInternalServerError, err, trillianUnexpectedResult)
				recorder := httptest.NewRecorder()
				response.WriteResponse(recorder, runtime.JSONProducer())
				if recorder.Code != wantCode || recorder.Header().Get("Retry-After") != wantRetry {
					t.Fatalf("unexpected response: %d %v", recorder.Code, recorder.Header())
				}
				var payload models.Error
				if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
					t.Fatal(err)
				}
				if payload.Code != int64(wantCode) {
					t.Fatalf("body code: got %d, want %d", payload.Code, wantCode)
				}
				if wantRetry != "" && payload.Message != "too many requests are waiting for proofs; retry later" {
					t.Fatalf("unexpected message: %q", payload.Message)
				}
			})
		}
	}
}
