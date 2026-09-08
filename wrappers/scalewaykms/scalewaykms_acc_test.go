// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package scalewaykms

import (
	"bytes"
	"context"
	"os"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

// This test executes real calls against the Scaleway Key Manager API. The API
// calls themselves are billed, and the key used is generally not free.
//
// To run this test, the following env variables need to be set:
//   - SCALEWAYKMS_WRAPPER_KEY_ID (the Key Manager key id, usage symmetric_encryption)
//   - SCW_ACCESS_KEY
//   - SCW_SECRET_KEY
//   - SCW_DEFAULT_REGION (the region the key lives in, e.g. fr-par)
//
// SCW_DEFAULT_PROJECT_ID may also be set. Credentials and region may
// alternatively be provided through the standard Scaleway configuration file.
func TestAccScalewayKmsWrapper_Lifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	k := NewWrapper()
	_, err := k.SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		"key_id": os.Getenv("SCW_KMS_KEY_ID"),
	}))
	require.NoError(t, err)

	input := []byte("foo")
	swi, err := k.Encrypt(context.Background(), input)
	require.NoError(t, err)
	require.NotEqual(t, input, swi.Ciphertext)

	pt, err := k.Decrypt(context.Background(), swi)
	require.NoError(t, err)
	require.Equal(t, input, pt)

	swi2, err := k.Encrypt(context.Background(), input)
	require.NoError(t, err)
	require.NotEqual(t, swi.Ciphertext, swi2.Ciphertext)

	corruptedSwi := &wrapping.BlobInfo{
		Ciphertext: bytes.Clone(swi.Ciphertext),
		Iv:         swi.Iv,
		KeyInfo:    swi.KeyInfo,
	}
	corruptedSwi.Ciphertext[0] ^= 0xff
	_, err = k.Decrypt(context.Background(), corruptedSwi)
	require.Error(t, err)
}
