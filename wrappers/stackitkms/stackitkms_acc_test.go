// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package stackitkms

import (
	"bytes"
	"context"
	"os"
	"testing"
)

// TestAccWrapperRoundtrip exercises the wrapper against the real STACKIT KMS
// API. It only runs when STACKITKMS_ACC_TEST is set and expects the wrapper
// configuration in STACKITKMS_* environment variables plus STACKIT SDK
// credentials (e.g. STACKIT_SERVICE_ACCOUNT_KEY_PATH).
func TestAccWrapperRoundtrip(t *testing.T) {
	if os.Getenv("STACKITKMS_ACC_TEST") == "" {
		t.Skip("set STACKITKMS_ACC_TEST=1 (plus STACKITKMS_*/STACKIT_* env vars) to run acceptance tests")
	}

	ctx := context.Background()
	w := NewWrapper()
	if _, err := w.SetConfig(ctx); err != nil {
		t.Fatalf("SetConfig failed: %v", err)
	}

	plaintext := []byte("stackitkms acceptance test")
	blob, err := w.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if bytes.Contains(blob.Ciphertext, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}

	decrypted, err := w.Decrypt(ctx, blob)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypt = %q, want %q", decrypted, plaintext)
	}
}
