// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package exoscalekms

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// This test calls the real Exoscale KMS API.
//
// To run it, set:
//   - KMS_ACC_TESTS
//   - EXOSCALEKMS_KEY_ID
//   - EXOSCALEKMS_ZONE or EXOSCALEKMS_ENDPOINT
//   - EXOSCALE_API_KEY
//   - EXOSCALE_API_SECRET
//
// The API key needs the get-kms-key, encrypt and decrypt operations on the key.
func TestAccExoscaleKmsWrapper_Lifecycle(t *testing.T) {
	if os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	w := NewWrapper()
	_, err := w.SetConfig(t.Context())
	require.NoError(t, err)

	input := []byte("foo")
	blob, err := w.Encrypt(t.Context(), input)
	require.NoError(t, err)

	plaintext, err := w.Decrypt(t.Context(), blob)
	require.NoError(t, err)
	require.Equal(t, input, plaintext)
}
