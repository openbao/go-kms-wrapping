// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package ncloudkms

import (
	"os"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

// This test executes real calls against Naver Cloud KMS. The calls themselves
// should be inexpensive, but the KMS key used is generally not free. Please see
// the Ncloud documentation for KMS pricing.
//
// To run this test, the following env variables need to be set:
//   - NCLOUDKMS_WRAPPER_KEY_TAG
//   - NCLOUDKMS_WRAPPER_ACCESS_KEY
//   - NCLOUDKMS_WRAPPER_SECRET_KEY
//
// Optionally set NCLOUDKMS_DOMAIN (e.g. kms.apigw.gov-ntruss.com) to target the
// public-sector cloud; it defaults to the civilian cloud.
func TestAccNcloudKmsWrapper_Lifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	ctx := t.Context()
	s := NewWrapper()

	var opts []wrapping.Option
	if d := os.Getenv("NCLOUDKMS_DOMAIN"); d != "" {
		opts = append(opts, wrapping.WithConfigMap(map[string]string{"domain": d}))
	}
	_, err := s.SetConfig(ctx, opts...)
	require.NoError(t, err, "SetConfig")

	input := []byte("foo")
	swi, err := s.Encrypt(ctx, input)
	require.NoError(t, err, "Encrypt")

	pt, err := s.Decrypt(ctx, swi)
	require.NoError(t, err, "Decrypt")
	require.Equal(t, input, pt, "roundtrip mismatch")
}
