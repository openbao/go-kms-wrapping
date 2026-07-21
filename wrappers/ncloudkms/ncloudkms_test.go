// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package ncloudkms

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

// TestCreateNaverSignature pins the ncp-apigw-signature-v2 message format and
// verifies the signing is deterministic and sensitive to the secret key. It
// needs no network access.
func TestCreateNaverSignature(t *testing.T) {
	method := "POST"
	uri := "/keys/v2/my-key/encrypt"
	ts := time.UnixMilli(1_700_000_000_000)
	accessKey := "access-key"
	secretKey := "secret-key"

	got := createNaverSignature(method, uri, ts, accessKey, secretKey)

	// Independently recompute the expected signature to lock the exact message
	// layout: "{method} {uri}\n{timestampMillis}\n{accessKey}".
	message := fmt.Sprintf("%s %s\n%d\n%s", method, uri, ts.UnixMilli(), accessKey)
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(message))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	require.Equal(t, want, got, "signature mismatch")

	// Deterministic for identical inputs.
	again := createNaverSignature(method, uri, ts, accessKey, secretKey)
	require.Equal(t, got, again, "signature not deterministic")

	// A different secret must produce a different signature.
	other := createNaverSignature(method, uri, ts, accessKey, "different-secret")
	require.NotEqual(t, got, other, "signature did not change with a different secret key")
}

// TestSetConfig exercises the credential/key-tag resolution and metadata output
// without touching the network. Env vars are disallowed so the host
// environment cannot influence the result.
func TestSetConfig(t *testing.T) {
	t.Run("missing key tag", func(t *testing.T) {
		w := NewWrapper()
		_, err := w.SetConfig(
			t.Context(),
			wrapping.WithDisallowEnvVars(true),
			wrapping.WithConfigMap(map[string]string{
				"access_key": "ak",
				"secret_key": "sk",
			}),
		)
		require.Error(t, err, "expected error when key tag is missing")
	})

	t.Run("missing credentials", func(t *testing.T) {
		w := NewWrapper()
		_, err := w.SetConfig(
			t.Context(),
			wrapping.WithDisallowEnvVars(true),
			wrapping.WithConfigMap(map[string]string{
				"key_tag": "my-key",
			}),
		)
		require.Error(t, err, "expected error when credentials are missing")
	})

	t.Run("valid config", func(t *testing.T) {
		w := NewWrapper()
		cfg, err := w.SetConfig(
			t.Context(),
			wrapping.WithDisallowEnvVars(true),
			wrapping.WithConfigMap(map[string]string{
				"key_tag":    "my-key",
				"access_key": "ak",
				"secret_key": "sk",
			}),
		)
		require.NoError(t, err)
		require.Equal(t, "my-key", cfg.Metadata["key_tag"])
		require.Equal(t, defaultDomain, cfg.Metadata["domain"])
		require.NotNil(t, w.client, "client was not initialized")

		id, err := w.KeyId(t.Context())
		require.NoError(t, err)
		require.Equal(t, "my-key", id)
	})

	t.Run("custom domain via config map", func(t *testing.T) {
		w := NewWrapper()
		cfg, err := w.SetConfig(
			t.Context(),
			wrapping.WithDisallowEnvVars(true),
			wrapping.WithConfigMap(map[string]string{
				"key_tag":    "my-key",
				"domain":     "kms.example.com",
				"access_key": "ak",
				"secret_key": "sk",
			}),
		)
		require.NoError(t, err)
		require.Equal(t, "kms.example.com", cfg.Metadata["domain"])
	})
}

// TestDecryptInvalidInput covers the missing-key-info guard, which needs no
// network.
func TestDecryptInvalidInput(t *testing.T) {
	w := NewWrapper()

	_, err := w.Decrypt(t.Context(), &wrapping.BlobInfo{})
	require.Error(t, err, "expected error for missing key info")
}

func TestType(t *testing.T) {
	w := NewWrapper()
	typ, err := w.Type(t.Context())
	require.NoError(t, err)
	require.Equal(t, Type, typ)
	require.Equal(t, "ncloudkms", string(Type))
}
