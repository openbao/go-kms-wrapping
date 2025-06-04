// Copyright The OpenBao Contributors
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// Tests in this file execute real calls. The calls themselves should be free,
// but the KMS key used is generally not free.
//
// To run these tests, the following env variables need to be set:
//   - BAO_HSM_LIB
//   - BAO_HSM_TOKEN_LABEL or BAO_HSM_SLOT
//   - BAO_HSM_PIN
//   - BAO_HSM_KEY_LABEL or BAO_HSM_KEY_ID

func TestWrapper(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	ctx := context.Background()
	k := NewWrapper()

	err := k.Init(ctx)
	require.NoError(t, err)

	_, err = k.SetConfig(ctx)
	require.NoError(t, err)

	plaintext := []byte("foo")
	ciphertext, err := k.Encrypt(ctx, plaintext)
	require.NoError(t, err)

	decrypted, err := k.Decrypt(ctx, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)

	err = k.Finalize(ctx)
	require.NoError(t, err)
}

func TestExternalKey(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}
}
