// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package opentelekomcloudkms

import (
	"bytes"
	"context"
	"os"
	"testing"
)

func TestOpenTelekomCloudKMS_Lifecycle(t *testing.T) {
	mustHaveOTCEnv(t)

	ctx := context.Background()
	w := NewWrapper()

	// Setting configuration from environment variables.
	if _, err := w.SetConfig(ctx); err != nil {
		t.Fatalf("SetConfig failed: %v", err)
	}

	plaintext := []byte("foo")
	blob, err := w.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if blob == nil || blob.KeyInfo == nil {
		t.Fatalf("Encrypt returned nil blob and/or nil KeyInfo")
	}
	if len(blob.KeyInfo.WrappedKey) == 0 {
		t.Fatalf("Encrypt returned empty wrapped key")
	}
	if len(blob.Ciphertext) == 0 {
		t.Fatalf("Encrypt returned empty ciphertext")
	}

	pt, err := w.Decrypt(ctx, blob)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("roundtrip mismatch:\n  got:  %q\n  want: %q", string(pt), string(plaintext))
	}

	// Verify KeyId is available after successful operations.
	keyID, err := w.KeyId(ctx)
	if err != nil {
		t.Fatalf("KeyId failed: %v", err)
	}
	if keyID == "" {
		t.Fatalf("KeyId returned empty string")
	}
}

func TestOpenTelekomCloudKMS_SetConfig_ResolvesKeyId(t *testing.T) {
	mustHaveOTCEnv(t)

	ctx := context.Background()
	w := NewWrapper()

	if _, err := w.SetConfig(ctx); err != nil {
		t.Fatalf("SetConfig failed: %v", err)
	}

	// After SetConfig, wrapper tries kms.Get() and stores the resolved key ID.
	keyID, err := w.KeyId(ctx)
	if err != nil {
		t.Fatalf("KeyId failed: %v", err)
	}
	if keyID == "" {
		t.Fatalf("expected resolved key ID after SetConfig, got empty")
	}
}

func TestOpenTelekomCloudKMS_Encrypt_NilPlaintext(t *testing.T) {
	w := NewWrapper()
	if _, err := w.Encrypt(context.Background(), nil); err == nil {
		t.Fatalf("expected error for nil plaintext")
	}
}

func TestOpenTelekomCloudKMS_Decrypt_NilInput(t *testing.T) {
	w := NewWrapper()
	if _, err := w.Decrypt(context.Background(), nil); err == nil {
		t.Fatalf("expected error for nil input")
	}
}

func mustHaveOTCEnv(t *testing.T) {
	t.Helper()

	// Skip tests if we are not running acceptance tests
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	requireEnv(t, EnvOpenTelekomCloudKmsWrapperKeyId)
	requireEnv(t, "OPENTELEKOMCLOUD_REGION")
	requireEnv(t, "OPENTELEKOMCLOUD_PROJECT")
	requireEnv(t, "OPENTELEKOMCLOUD_ACCESS_KEY")
	requireEnv(t, "OPENTELEKOMCLOUD_SECRET_KEY")
}

func requireEnv(t *testing.T, key string) {
	t.Helper()
	if os.Getenv(key) == "" {
		t.Skipf("missing required env var %s (skipping integration test)", key)
	}
}
