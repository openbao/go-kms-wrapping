// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package nhncloudskm

import (
	"context"
	"os"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// TestWrapper is a utility function for creating a test wrapper
func TestWrapper(tb testing.TB) *Wrapper {
	tb.Helper()

	wrapper := NewWrapper()
	_, err := wrapper.SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		"endpoint":               "https://api-keymanager.nhncloudservice.com",
		"app_key":                "test-app-key",
		"key_id":                 "test-key-id",
		"user_access_key_id":     "test-access-key-id",
		"user_secret_access_key": "test-secret-key",
		"mac_address":            "test-mac-address",
	}))
	if err != nil {
		tb.Fatalf("failed to configure test wrapper: %v", err)
	}

	return wrapper
}

// TestWrapper_WithEnv creates a wrapper configured from environment variables
// This is useful for acceptance tests that need real credentials
func TestWrapper_WithEnv(tb testing.TB) *Wrapper {
	tb.Helper()

	// Check if all required environment variables are set
	requiredEnvs := []string{
		EnvNHNCloudSKMEndpoint,
		EnvNHNCloudSKMAppKey,
		EnvNHNCloudSKMKeyID,
		EnvNHNCloudSKMUserAccessKeyID,
		EnvNHNCloudSKMUserSecretAccessKey,
	}

	for _, env := range requiredEnvs {
		if os.Getenv(env) == "" {
			tb.Skipf("skipping test: %s environment variable not set", env)
		}
	}

	wrapper := NewWrapper()
	_, err := wrapper.SetConfig(context.Background())
	if err != nil {
		tb.Fatalf("failed to configure wrapper from environment: %v", err)
	}

	return wrapper
}

// TestWrapper_Basic performs basic wrapper functionality tests
func TestWrapper_Basic(tb testing.TB, wrapper *Wrapper) {
	tb.Helper()

	ctx := context.Background()

	// Test Type
	wrapperType, err := wrapper.Type(ctx)
	if err != nil {
		tb.Fatalf("failed to get wrapper type: %v", err)
	}
	if wrapperType != wrapping.WrapperTypeNHNCloudSkm {
		tb.Fatalf("expected wrapper type %s, got %s", wrapping.WrapperTypeNHNCloudSkm, wrapperType)
	}

	// Test KeyId
	keyID, err := wrapper.KeyId(ctx)
	if err != nil {
		tb.Fatalf("failed to get key ID: %v", err)
	}
	if keyID == "" {
		tb.Fatal("key ID is empty")
	}
}

// TestWrapper_EncryptDecrypt performs basic encrypt/decrypt tests
func TestWrapper_EncryptDecrypt(tb testing.TB, wrapper *Wrapper) {
	tb.Helper()

	ctx := context.Background()
	plaintext := []byte("hello world")

	// Test encryption
	blobInfo, err := wrapper.Encrypt(ctx, plaintext)
	if err != nil {
		tb.Fatalf("failed to encrypt: %v", err)
	}

	if len(blobInfo.Ciphertext) == 0 {
		tb.Fatal("ciphertext is empty")
	}

	if blobInfo.KeyInfo == nil || blobInfo.KeyInfo.KeyId == "" {
		tb.Fatal("key info is missing")
	}

	// Test decryption
	decrypted, err := wrapper.Decrypt(ctx, blobInfo)
	if err != nil {
		tb.Fatalf("failed to decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		tb.Fatalf("decrypted text %q does not match original %q", decrypted, plaintext)
	}
}

// TestWrapper_EmptyPlaintext tests handling of empty plaintext
func TestWrapper_EmptyPlaintext(tb testing.TB, wrapper *Wrapper) {
	tb.Helper()

	ctx := context.Background()

	// Test encryption with empty plaintext should fail
	_, err := wrapper.Encrypt(ctx, []byte{})
	if err == nil {
		tb.Fatal("expected error when encrypting empty plaintext")
	}
}

// TestWrapper_LargePlaintext tests handling of large plaintext
func TestWrapper_LargePlaintext(tb testing.TB, wrapper *Wrapper) {
	tb.Helper()

	ctx := context.Background()

	// Create plaintext larger than 32KB limit
	largePlaintext := make([]byte, 33*1024)
	for i := range largePlaintext {
		largePlaintext[i] = byte(i % 256)
	}

	// Test encryption with large plaintext should fail
	_, err := wrapper.Encrypt(ctx, largePlaintext)
	if err == nil {
		tb.Fatal("expected error when encrypting plaintext larger than 32KB")
	}
}

// TestWrapper_KeyRotation tests decryption with different key IDs
func TestWrapper_KeyRotation(tb testing.TB, wrapper *Wrapper) {
	tb.Helper()

	ctx := context.Background()
	plaintext := []byte("test key rotation")

	// Encrypt with current key
	blobInfo, err := wrapper.Encrypt(ctx, plaintext)
	if err != nil {
		tb.Fatalf("failed to encrypt: %v", err)
	}

	// Change the key ID in blob info to simulate key rotation
	originalKeyID := blobInfo.KeyInfo.KeyId
	blobInfo.KeyInfo.KeyId = "different-key-id"

	// Decrypt should use the key ID from blob info
	// Note: This will likely fail in real scenarios unless both keys exist
	// but tests the code path where key ID is taken from blob info
	_, err = wrapper.Decrypt(ctx, blobInfo)
	// We expect this to fail with authentication/key not found error
	// but not with a nil pointer or parsing error
	if err == nil {
		tb.Log("Unexpectedly succeeded decryption with different key ID")
	}

	// Restore original key ID
	blobInfo.KeyInfo.KeyId = originalKeyID

	// Should work with original key ID
	decrypted, err := wrapper.Decrypt(ctx, blobInfo)
	if err != nil {
		tb.Fatalf("failed to decrypt with original key ID: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		tb.Fatalf("decrypted text %q does not match original %q", decrypted, plaintext)
	}
}
