// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package scalewaykms

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
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

	if os.Getenv("SCALEWAYKMS_WRAPPER_KEY_ID") == "" {
		t.SkipNow()
	}

	k := NewWrapper()
	_, err := k.SetConfig(context.Background())
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	input := []byte("foo")
	swi, err := k.Encrypt(context.Background(), input)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	if bytes.Equal(input, swi.Ciphertext) {
		t.Fatalf("ciphertext should differ from input")
	}

	pt, err := k.Decrypt(context.Background(), swi)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}

	swi2, err := k.Encrypt(context.Background(), input)
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
	if _, err := k.Decrypt(context.Background(), corruptedSwi); err == nil {
		t.Fatalf("decrypt corrupted ciphertext should return an error")
	}
}
