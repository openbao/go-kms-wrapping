// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openbao/go-kms-wrapping/kms/securosyshsm/v2/internal/client"
	"github.com/openbao/go-kms-wrapping/kms/securosyshsm/v2/internal/helpers"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

func TestWaitForRequestReturnsCompletedRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/request/request-1" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(&helpers.RequestResponse{
			Id:     "request-1",
			Status: "EXECUTED",
			Result: "result",
		})
	}))
	defer server.Close()

	key := testSecurosysKey(t, server.URL)

	request, err := key.waitForRequest(t.Context(), "request-1")
	if err != nil {
		t.Fatalf("waitForRequest returned error: %v", err)
	}
	if request.Status != "EXECUTED" {
		t.Fatalf("expected EXECUTED status, got %q", request.Status)
	}
}

func TestWaitForRequestStopsWhenContextCancelledDuringPoll(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		select {
		case <-r.Context().Done():
		case <-releaseRequest:
			_ = json.NewEncoder(w).Encode(&helpers.RequestResponse{
				Id:     "request-1",
				Status: "PENDING",
			})
		}
	}))
	defer server.Close()
	defer close(releaseRequest)

	key := testSecurosysKey(t, server.URL)
	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)

	go func() {
		_, err := key.waitForRequest(ctx, "request-1")
		errCh <- err
	}()

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for request poll to start")
	}

	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
		if errors.Is(err, ErrApprovalTimeout) {
			t.Fatalf("expected cancellation not to be reported as approval timeout: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for waitForRequest to stop")
	}
}

func TestWaitForRequestStopsWhenKMSClosedDuringPoll(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		select {
		case <-r.Context().Done():
		case <-releaseRequest:
			_ = json.NewEncoder(w).Encode(&helpers.RequestResponse{
				Id:     "request-1",
				Status: "PENDING",
			})
		}
	}))
	defer server.Close()
	defer close(releaseRequest)

	key := testSecurosysKey(t, server.URL)
	closeCtx, closeKMS := context.WithCancel(context.Background())
	key.closeCtx = closeCtx
	ctx := t.Context()
	errCh := make(chan error, 1)

	go func() {
		_, err := key.waitForRequest(ctx, "request-1")
		errCh <- err
	}()

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for request poll to start")
	}

	closeKMS()

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrKMSClosed) {
			t.Fatalf("expected ErrKMSClosed, got %v", err)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
		if errors.Is(err, ErrApprovalTimeout) {
			t.Fatalf("expected KMS close not to be reported as approval timeout: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for waitForRequest to stop")
	}
}

func TestEncryptStopsWhenContextTimesOut(t *testing.T) {
	releaseRequest := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/encrypt" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		select {
		case <-r.Context().Done():
		case <-releaseRequest:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()
	defer close(releaseRequest)

	key := testSecurosysKey(t, server.URL)
	key.keyAttrs = helpers.KeyAttributes{
		Label:     "key-1",
		Algorithm: "AES",
	}

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()

	_, err := key.Encrypt(ctx, &kms.CipherOptions{Data: []byte("plaintext")})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}

func testSecurosysKey(t *testing.T, hostURL string) *securosysKey {
	t.Helper()

	tsbClient, err := client.NewTSBClient(hostURL, client.AuthStruct{})
	if err != nil {
		t.Fatalf("failed to create test client: %v", err)
	}

	return &securosysKey{
		client: &client.SecurosysClient{TSBClient: tsbClient},
	}
}
