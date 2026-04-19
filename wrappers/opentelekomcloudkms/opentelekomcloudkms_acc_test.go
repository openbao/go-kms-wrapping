// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package opentelekomcloudkms

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenTelekomCloudKMS_Lifecycle(t *testing.T) {
	mustHaveOTCEnv(t)

	ctx := t.Context()
	w := NewWrapper()

	// Setting configuration from environment variables.
	_, err := w.SetConfig(ctx)
	require.NoError(t, err, "SetConfig")

	plaintext := []byte("foo")
	blob, err := w.Encrypt(ctx, plaintext)
	require.NoError(t, err, "Encrypt")
	require.NotNil(t, blob)
	require.NotNil(t, blob.KeyInfo)
	require.NotEmpty(t, blob.KeyInfo.WrappedKey)
	require.NotEmpty(t, blob.Ciphertext)

	pt, err := w.Decrypt(ctx, blob)
	require.NoError(t, err, "Decrypt")
	require.Equal(t, plaintext, pt, "roundtrip mismatch")

	// Verify KeyId is available after successful operations.
	keyID, err := w.KeyId(ctx)
	require.NoError(t, err, "KeyId")
	require.NotEmpty(t, keyID)
}

func TestOpenTelekomCloudKMS_Encrypt_NilPlaintext(t *testing.T) {
	w := NewWrapper()
	_, err := w.Encrypt(t.Context(), nil)
	require.Error(t, err)
}

func mustHaveOTCEnv(t *testing.T) {
	t.Helper()

	// Skip tests if we are not running acceptance tests
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	requireEnv(t, EnvOpenTelekomCloudKmsKeyId)
	requireEnv(t, EnvOpenTelekomCloudAccessKey)
	requireEnv(t, EnvOpenTelekomCloudSecretKey)
}

func requireEnv(t *testing.T, key string) {
	t.Helper()
	if os.Getenv(key) == "" {
		t.Skipf("missing required env var %s (skipping integration test)", key)
	}
}
