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

// This test executes real calls. The calls themselves should be free,
// but the KMS key used is generally not free.
//
// To run this test, the following env variables need to be set:
//   - BAO_HSM_SLOT
//   - BAO_HSM_PIN
//   - BAO_HSM_LIB
//   - BAO_HSM_KEY_LABEL
//   - BAO_HSM_KEY_ID
//   - BAO_HSM_MECHANISM
func TestAccPkcs11Wrapper_Lifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	s := NewWrapper()
	_, err := s.SetConfig(context.Background())
	require.NoError(t, err)

	input := []byte("foo")
	swi, err := s.Encrypt(context.Background(), input)
	require.NoError(t, err)

	pt, err := s.Decrypt(context.Background(), swi)
	require.NoError(t, err)

	require.Equal(t, input, pt)
}
