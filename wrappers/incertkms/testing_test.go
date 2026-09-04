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

// newIncertKmsTestWrapper returns a Wrapper configured against an in-process
// httptest.Server that fakes the KMS API. The crypto endpoints echo the
// submitted bytes back so encrypt/decrypt round-trips preserve the plaintext.
// The fake KMS server is shut down automatically when the calling test
// ends. If SetConfig fails against it, the calling test is aborted.
func newIncertKmsTestWrapper(t *testing.T) *Wrapper {
	t.Helper()

	vslotID := uuid.New()
	keyID := uuid.New()

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
				{ID: vslotID, Provider: uuid.New(), ProviderName: "test"},
			},
		})
	})

	// Key search endpoint (FindKeys). The configured key path uses the
	// trailing-slash handler below, so this stays empty.
	mux.HandleFunc("/api/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"content": []kmssdk.KeySearchResult{},
		})
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
				ID:   keyID,
				Name: incertkmsTestKeyName,
				Alg:  "AES256",
			})
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	wrapper := NewWrapper()
	_, err := wrapper.SetConfig(t.Context(), wrapping.WithConfigMap(map[string]string{
		"url":      srv.URL,
		"username": incertkmsTestUsername,
		"password": incertkmsTestPassword,
		"vslot":    vslotID.String(),
		"key":      keyID.String(),
	}))
	require.NoError(t, err, "configuring wrapper against the fake KMS")

	return wrapper
}
