// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package incertkms

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	kmssdk "github.com/incert-kms/kms-sdk-go"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

const (
	incertkmsTestUsername = "test-user"
	incertkmsTestPassword = "test-pass"
	incertkmsTestKeyName  = "openbao-seal-key"
)

// fakeKMS is an in-process httptest.Server that fakes the KMS API. The crypto
// endpoints echo the submitted bytes back so encrypt/decrypt round-trips
// preserve the plaintext.
type fakeKMS struct {
	srv     *httptest.Server
	vslotID uuid.UUID
	keyID   uuid.UUID

	// searchResults is what the key search endpoint (FindKeys) returns. Tests
	// that exercise lookup by name set it before calling SetConfig. The
	// server-side name filter is not emulated.
	searchResults []kmssdk.KeySearchResult
}

// newFakeKMS starts a fake KMS exposing a single vslot and a single AES key.
// The server is closed when the test finishes.
func newFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()

	f := &fakeKMS{
		vslotID: uuid.New(),
		keyID:   uuid.New(),
	}

	mux := http.NewServeMux()

	// Auth configuration endpoint (unauthenticated). Tells the SDK to use a
	// Keycloak provider hosted on the same test server under /auth.
	mux.HandleFunc("/api/configs/auth", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(kmssdk.Config{
			Type: kmssdk.AuthenticationTypeOAuth2,
			OAuth2: &kmssdk.OAuth2Config{
				Provider: kmssdk.OAuth2ProviderKeycloak,
				Keycloak: &kmssdk.OAuth2KeycloakConfig{URL: "/auth"},
			},
		})
	})

	// Fake Keycloak token endpoint.
	mux.HandleFunc("/auth/realms/kms/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":       "test-access-token",
			"expires_in":         3600,
			"refresh_token":      "test-refresh-token",
			"refresh_expires_in": 7200,
		})
	})

	// List vslots. Returns a single vslot with the pre-allocated ID so that
	// vslotInit matches the configured vslot.
	mux.HandleFunc("/api/vslots", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"content": []kmssdk.Vslot{
				{ID: f.vslotID, Provider: uuid.New(), ProviderName: "test"},
			},
		})
	})

	// Key search endpoint (FindKeys). Returns whatever the test configured.
	mux.HandleFunc("/api/keys", func(w http.ResponseWriter, r *http.Request) {
		results := f.searchResults
		if results == nil {
			results = []kmssdk.KeySearchResult{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"content": results})
	})

	// Key detail / encrypt / decrypt endpoints. Encrypt and decrypt echo the
	// submitted bytes back, which is enough to validate the wrapper plumbing.
	mux.HandleFunc("/api/keys/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/p/encrypt"),
			strings.HasSuffix(r.URL.Path, "/p/decrypt"):
			var req kmssdk.CryptoRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(map[string][]byte{"data": req.Data})
		default:
			_ = json.NewEncoder(w).Encode(kmssdk.KeyDetail{
				ID:   f.keyID,
				Name: incertkmsTestKeyName,
				Alg:  "AES256",
			})
		}
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)

	return f
}

// config returns a seal configuration pointing at the fake, without any key
// selector, with extra merged on top.
func (f *fakeKMS) config(extra map[string]string) map[string]string {
	cfg := map[string]string{
		"url":      f.srv.URL,
		"username": incertkmsTestUsername,
		"password": incertkmsTestPassword,
		"vslot":    f.vslotID.String(),
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

// newIncertKmsTestWrapper returns a Wrapper configured against a fake KMS by
// key id. The server is closed when the test finishes, and the test fails
// immediately if the wrapper cannot be configured against the fake.
func newIncertKmsTestWrapper(t *testing.T) *Wrapper {
	t.Helper()

	f := newFakeKMS(t)

	wrapper := NewWrapper()
	_, err := wrapper.SetConfig(t.Context(), wrapping.WithConfigMap(f.config(map[string]string{
		"key": f.keyID.String(),
	})))
	require.NoError(t, err, "configuring wrapper against the fake KMS")

	return wrapper
}
