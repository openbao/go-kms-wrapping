// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package incertkms

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/google/uuid"
	kmssdk "github.com/incert-kms/kms-sdk-go"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

const (
	incertkmsTestUsername = "test-user"
	incertkmsTestPassword = "test-pass"
	incertkmsTestKeyName  = "openbao-seal-key"
)

// newIncertKmsTestWrapper returns a Wrapper configured against an in-process
// httptest.Server that fakes the KMS API. The crypto endpoints echo the
// submitted bytes back so encrypt/decrypt round-trips preserve the plaintext.
// The caller is responsible for closing the returned server, typically via
// defer srv.Close() at the call site.
func newIncertKmsTestWrapper() (*Wrapper, *httptest.Server) {
	vslotID := uuid.New()
	keyID := uuid.New()

	mux := http.NewServeMux()

	// Auth configuration endpoint (unauthenticated). Tells the SDK to use a
	// Keycloak provider hosted on the same test server under /auth.
	mux.HandleFunc("/api/configs/auth", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(kmssdk.Config{
			Type: kmssdk.AuthenticationTypeOAuth2,
			Oauth2: &kmssdk.Oauth2Config{
				Provider: kmssdk.Oauth2ProviderKeycloak,
				Keycloak: &kmssdk.Oauth2KeycloakConfig{URL: "/auth"},
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
	// vslotInit matches the configured kms_vslot.
	mux.HandleFunc("/api/vslots", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"content": []kmssdk.Vslot{
				{ID: vslotID, Provider: uuid.New(), ProviderName: "test"},
			},
		})
	})

	// Create-key endpoint, used when no kms_key is configured.
	mux.HandleFunc("/api/vslots/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/p/kg") {
			_ = json.NewEncoder(w).Encode(map[string]uuid.UUID{"id": keyID})
		}
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

	wrapper := NewWrapper()
	_, _ = wrapper.SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		"kms_url":      srv.URL,
		"kms_username": incertkmsTestUsername,
		"kms_password": incertkmsTestPassword,
		"kms_vslot":    vslotID.String(),
		"kms_key":      keyID.String(),
	}))

	return wrapper, srv
}
