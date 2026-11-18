// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package exoscalekms

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	v3 "github.com/exoscale/egoscale/v3"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

const (
	testKeyA = "6f1f7b1e-0000-4000-8000-00000000000a"
	testKeyB = "6f1f7b1e-0000-4000-8000-00000000000b"
)

// mockKMS fakes the Exoscale KMS API. Like the real one, it rejects a ciphertext made under another key.
type mockKMS struct{}

func (mockKMS) Encrypt(_ context.Context, id v3.UUID, req v3.EncryptRequest) (*v3.EncryptResponse, error) {
	return &v3.EncryptResponse{Ciphertext: append([]byte(id+":"), req.Plaintext...)}, nil
}

func (mockKMS) Decrypt(_ context.Context, id v3.UUID, req v3.DecryptRequest) (*v3.DecryptResponse, error) {
	plaintext, ok := bytes.CutPrefix(req.Ciphertext, []byte(id+":"))
	if !ok {
		return nil, fmt.Errorf("ciphertext was not made under key %s", id)
	}
	return &v3.DecryptResponse{Plaintext: plaintext}, nil
}

// testConfig returns a complete seal config for keyId.
func testConfig(keyId string) map[string]string {
	return map[string]string{
		"key_id":     keyId,
		"zone":       "ch-gva-2",
		"api_key":    "EXOtest",
		"api_secret": "secret",
	}
}

// newTestWrapper returns a wrapper for keyId that talks to the mock and ignores env vars.
func newTestWrapper(t *testing.T, keyId string) *Wrapper {
	t.Helper()
	w := NewWrapper()
	w.client = mockKMS{}
	_, err := w.SetConfig(t.Context(), wrapping.WithConfigMap(testConfig(keyId)), wrapping.WithDisallowEnvVars(true))
	require.NoError(t, err)
	return w
}

// setTestEnv sets every env var the wrapper reads to a value that differs from testConfig.
func setTestEnv(t *testing.T) {
	t.Setenv(EnvExoscaleKmsKeyId, testKeyB)
	t.Setenv(EnvExoscaleKmsZone, "de-fra-1")
	t.Setenv(EnvExoscaleApiKey, "EXOenv")
	t.Setenv(EnvExoscaleApiSecret, "env-secret")
}

func TestExoscaleKmsWrapper_Lifecycle(t *testing.T) {
	w := newTestWrapper(t, testKeyA)

	plaintext := []byte("foo")
	blob, err := w.Encrypt(t.Context(), plaintext)
	require.NoError(t, err)
	require.Equal(t, testKeyA, blob.KeyInfo.KeyId)
	require.NotEqual(t, plaintext, blob.Ciphertext)

	got, err := w.Decrypt(t.Context(), blob)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)

	keyId, err := w.KeyId(t.Context())
	require.NoError(t, err)
	require.Equal(t, testKeyA, keyId)
}

func TestExoscaleKmsWrapper_KeySwitch(t *testing.T) {
	wA := newTestWrapper(t, testKeyA)
	blob, err := wA.Encrypt(t.Context(), []byte("foo"))
	require.NoError(t, err)

	wB := newTestWrapper(t, testKeyB)
	got, err := wB.Decrypt(t.Context(), blob)
	require.NoError(t, err)

	require.Equal(t, []byte("foo"), got)
}

func TestExoscaleKmsWrapper_DecryptWithoutKeyId(t *testing.T) {
	w := newTestWrapper(t, testKeyA)
	blob, err := w.Encrypt(t.Context(), []byte("foo"))
	require.NoError(t, err)

	blob.KeyInfo.KeyId = ""
	got, err := w.Decrypt(t.Context(), blob)
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), got)
}

func TestExoscaleKmsWrapper_SetConfigErrors(t *testing.T) {
	for _, missing := range []string{"key_id", "zone", "api_key", "api_secret"} {
		t.Run(missing, func(t *testing.T) {
			config := testConfig(testKeyA)
			delete(config, missing)

			w := NewWrapper()
			w.client = mockKMS{}
			_, err := w.SetConfig(t.Context(), wrapping.WithConfigMap(config), wrapping.WithDisallowEnvVars(true))
			require.Error(t, err)
		})
	}
}

func TestExoscaleKmsWrapper_EndpointWithoutZone(t *testing.T) {
	config := testConfig(testKeyA)
	delete(config, "zone")
	config["endpoint"] = "https://api.example.invalid/v2"

	w := NewWrapper()
	w.client = mockKMS{}
	wrapConfig, err := w.SetConfig(t.Context(), wrapping.WithConfigMap(config), wrapping.WithDisallowEnvVars(true))
	require.NoError(t, err)

	want := map[string]string{
		"key_id":   testKeyA,
		"endpoint": config["endpoint"],
	}
	require.Equal(t, want, wrapConfig.Metadata)
}

func TestExoscaleKmsWrapper_EnvOverridesConfig(t *testing.T) {
	setTestEnv(t)

	w := NewWrapper()
	w.client = mockKMS{}
	_, err := w.SetConfig(t.Context(), wrapping.WithConfigMap(testConfig(testKeyA)))
	require.NoError(t, err)

	require.Equal(t, testKeyB, w.keyId)
	require.Equal(t, "de-fra-1", w.zone)
	require.Equal(t, "EXOenv", w.apiKey)
	require.Equal(t, "env-secret", w.apiSecret)
}

func TestExoscaleKmsWrapper_IgnoreEnv(t *testing.T) {
	setTestEnv(t)

	w := newTestWrapper(t, testKeyA)

	require.Equal(t, testKeyA, w.keyId)
	require.Equal(t, "ch-gva-2", w.zone)
	require.Equal(t, "EXOtest", w.apiKey)
	require.Equal(t, "secret", w.apiSecret)
}

func TestExoscaleKmsWrapper_NilInputs(t *testing.T) {
	w := newTestWrapper(t, testKeyA)

	_, err := w.Encrypt(t.Context(), nil)
	require.Error(t, err)
	_, err = w.Decrypt(t.Context(), nil)
	require.Error(t, err)
	_, err = w.Decrypt(t.Context(), &wrapping.BlobInfo{})
	require.Error(t, err)

	unconfigured := NewWrapper()
	_, err = unconfigured.Encrypt(t.Context(), []byte("foo"))
	require.Error(t, err)
	_, err = unconfigured.Decrypt(t.Context(), &wrapping.BlobInfo{KeyInfo: &wrapping.KeyInfo{}})
	require.Error(t, err)
}
