// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package stackitkms

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAccWrapperRoundtrip exercises the wrapper against the real STACKIT KMS
// API. It only runs when VAULT_ACC or KMS_ACC_TESTS is set and expects the
// wrapper configuration in STACKITKMS_* environment variables plus STACKIT
// SDK credentials (e.g. STACKIT_SERVICE_ACCOUNT_KEY_PATH).
func TestAccWrapperRoundtrip(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.Skip("set VAULT_ACC or KMS_ACC_TESTS (plus STACKITKMS_*/STACKIT_* env vars) to run acceptance tests")
	}

	ctx := context.Background()
	w := NewWrapper()
	_, err := w.SetConfig(ctx)
	require.NoError(t, err)

	plaintext := []byte("stackitkms acceptance test")
	blob, err := w.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	require.False(t, bytes.Contains(blob.Ciphertext, plaintext), "ciphertext contains plaintext")

	decrypted, err := w.Decrypt(ctx, blob)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}
