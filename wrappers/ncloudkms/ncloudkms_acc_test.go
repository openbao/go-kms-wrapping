// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package ncloudkms

import (
	"context"
	"os"
	"reflect"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// This test executes real calls against Naver Cloud KMS. The calls themselves
// should be inexpensive, but the KMS key used is generally not free. Please see
// the Ncloud documentation for KMS pricing.
//
// To run this test, the following env variables need to be set:
//   - NCLOUDKMS_WRAPPER_KEY_TAG
//   - NCP_ACCESS_KEY
//   - NCP_SECRET_KEY
//
// Optionally set NCLOUDKMS_DOMAIN (e.g. kms.apigw.gov-ntruss.com) to target the
// public-sector cloud; it defaults to the civilian cloud.
func TestAccNcloudKmsWrapper_Lifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	s := NewWrapper()

	var opts []wrapping.Option
	if d := os.Getenv("NCLOUDKMS_DOMAIN"); d != "" {
		opts = append(opts, WithDomain(d))
	}
	if _, err := s.SetConfig(context.Background(), opts...); err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	input := []byte("foo")
	swi, err := s.Encrypt(context.Background(), input, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	pt, err := s.Decrypt(context.Background(), swi, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}
}
