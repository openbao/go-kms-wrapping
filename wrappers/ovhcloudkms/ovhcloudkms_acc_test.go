// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package ovhcloudkms

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// This test executes real calls. The calls themselves should be free,
// but the OKMS key used is generally not free.
//
// To run this test, the following env variables need to be set:
//   - OVHCLOUDKMS_KEY_ID
//   - OVHCLOUDKMS_ENDPOINT
//   - OVHCLOUDKMS_ID
//
// You can choose the auth type by setting corresponding env variables:
// token:
//   - OVHCLOUDKMS_TOKEN
//
// mTLS:
//   - OVHCLOUDKMS_CLIENT_CERT
//   - OVHCLOUDKMS_CLIENT_KEY
func TestAccOvhcloudKmsWrapper_Lifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	keyId := os.Getenv("OVHCLOUDKMS_KEY_ID")
	if keyId == "" {
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
	if bytes.Equal(input, swi.Ciphertext) {
		t.Fatalf("ciphertext should differ from input")
	}

	pt, err := ow.Decrypt(context.Background(), swi)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}

	swi2, err := ow.Encrypt(context.Background(), input)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	if bytes.Equal(swi.Ciphertext, swi2.Ciphertext) {
		t.Fatalf("re-encrypting the same input should produce a different ciphertext")
	}

	corruptedSwi := &wrapping.BlobInfo{
		Ciphertext: bytes.Clone(swi.Ciphertext),
		Iv:         swi.Iv,
		KeyInfo:    swi.KeyInfo,
	}
	corruptedSwi.Ciphertext[0] ^= 0xff
	if _, err := ow.Decrypt(context.Background(), corruptedSwi); err == nil {
		t.Fatalf("decrypt corrupted ciphertext should return an error")
	}
}
