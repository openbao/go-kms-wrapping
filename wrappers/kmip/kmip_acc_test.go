// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"os"
	"reflect"
	"testing"
)

// This test executes real calls. The calls themselves should be free,
// but the KMS key used is generally not free.
//
// To run this test, the following env variables need to be set:
//   - VAULT_KMIP_SEAL_KEY_ID or KMIP_WRAPPING_KEY_ID
//   - KMIP_CA_CERT
//   - KMIP_CLIENT_CERT
//   - KMIP_CLIENT_KEY
//   - KMIP_ENDPOINT
//   - KMIP_SERVER_NAME
func TestAcckmipWrapper_Lifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	s := NewWrapper()
	_, err := s.SetConfig(context.Background())
	if err != nil {
		t.Fatalf("err : %s", err)
	}

	input := []byte("foo")
	swi, err := s.Encrypt(context.Background(), input)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	pt, err := s.Decrypt(context.Background(), swi)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}
}
