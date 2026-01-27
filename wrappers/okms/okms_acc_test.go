// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package okms

import (
	"context"
	"os"
	"reflect"
	"testing"
)

// This test executes real calls. The calls themselves should be free,
// but the OKMS key used is generally not free.
//
// To run this test, the following env variables need to be set:
//   - OKMS_ACC_TESTS_KEY_ID
//   - BAO_OKMS_ENDPOINT
//   - BAO_OKMS_ID
//   - BAO_OKMS_CLIENT_CERT
//   - BAO_OKMS_CLIENT_KEY
func TestAcckmipWrapper_Lifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	keyId := os.Getenv("OKMS_ACC_TESTS_KEY_ID")
	if keyId == "" {
		t.SkipNow()
	}
	if os.Setenv(EnvOkmsWrapperKeyId, keyId) != nil {
		t.SkipNow()
	}

	ow := NewWrapper()
	_, err := ow.SetConfig(context.Background())
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	input := []byte("foo")
	swi, err := ow.Encrypt(context.Background(), input)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	pt, err := ow.Decrypt(context.Background(), swi)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}
}
