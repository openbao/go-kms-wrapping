// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package securosyshsm

import (
	"os"
	"strings"
	"testing"

	"github.com/openbao/go-kms-wrapping/v2/kms"
	client "github.com/securosys-com/tsb-client-go"
)

// KMS configuration environment variables
var (
	SECUROSYS_HSM_RESTAPI_ENV_VAR  = "SECUROSYS_HSM_RESTAPI"
	SECUROSYS_BEARER_TOKEN_ENV_VAR = "SECUROSYS_BEARER_TOKEN"
)

// Test keys names
var (
	AES_KEY_NAME = "openbao_test_aes_key"
	RSA_KEY_NAME = "openbao_test_rsa_key"
	EC_KEY_NAME  = "openbao_test_ec_key"
	ED_KEY_NAME  = "openbao_test_ed_key"
)

func getTestClient(t *testing.T) *client.TSBClient {
	restAPI := testEnv(SECUROSYS_HSM_RESTAPI_ENV_VAR)
	bearerToken := testEnv(SECUROSYS_BEARER_TOKEN_ENV_VAR)

	if restAPI == "" || bearerToken == "" {
		t.Skip("SECUROSYS_HSM_RESTAPI or SECUROSYS_BEARER_TOKEN not set, skipping test")
		return nil
	}

	tsbClient, err := client.NewTSBClient(restAPI, client.AuthStruct{
		AuthType:    "TOKEN",
		BearerToken: bearerToken,
		AppName:     "OpenBao - Securosys HSM KMS Test",
	})
	if err != nil {
		t.Fatalf("Failed to create TSB client: %v", err)
	}

	return tsbClient
}

func openTestKMS(t *testing.T) kms.KMS {
	t.Helper()

	restAPI := testEnv(SECUROSYS_HSM_RESTAPI_ENV_VAR)
	bearerToken := testEnv(SECUROSYS_BEARER_TOKEN_ENV_VAR)
	if restAPI == "" || bearerToken == "" {
		t.Skip("SECUROSYS_HSM_RESTAPI or SECUROSYS_BEARER_TOKEN not set, skipping test")
	}

	kmsInstance := New()
	err := kmsInstance.Open(t.Context(), &kms.OpenOptions{
		ConfigMap: kms.ConfigMap{
			"rest_api":     restAPI,
			"auth":         "TOKEN",
			"bearer_token": bearerToken,
		},
	})
	if err != nil {
		t.Fatalf("Failed to open KMS: %v", err)
	}

	return kmsInstance
}

func getTestKMSKey(t *testing.T, kmsInstance kms.KMS, keyName, cipherAlgorithm string) kms.Key {
	t.Helper()

	key, err := kmsInstance.GetKey(t.Context(), &kms.KeyOptions{
		ConfigMap: kms.ConfigMap{
			"name":             keyName,
			"cipher_algorithm": cipherAlgorithm,
		},
	})
	if err != nil {
		t.Fatalf("Failed to get key %q for %s: %v", keyName, cipherAlgorithm, err)
	}

	return key
}

func createTestKey(t *testing.T, keyName, keyType string, keySize int) func() {
	tsbClient := getTestClient(t)
	if tsbClient == nil {
		return func() {}
	}

	// Create key attributes
	attrs := map[string]bool{
		"extractable": false,
		"token":       true,
		"sign":        true,
		"verify":      true,
		"encrypt":     true,
		"decrypt":     true,
		"wrap":        true,
		"unwrap":      true,
		"derive":      false,
	}

	var size float64
	if keySize > 0 {
		size = float64(keySize)
	}

	// Create the key
	_, err := tsbClient.CreateOrUpdateKey(t.Context(), keyName, "", attrs, keyType, size, nil, "", false)
	if err != nil {
		t.Logf("Key creation warning (may already exist): %v", err)
	}

	// Return cleanup function
	return func() {
		err := tsbClient.RemoveKey(t.Context(), keyName)
		if err != nil {
			t.Logf("Key cleanup warning: %v", err)
		}
	}
}

// setupTestKeys creates the AES, RSA, EC, and ED keys used by acceptance tests.
func setupTestKeys(t *testing.T) {
	tsbClient := getTestClient(t)
	if tsbClient == nil {
		return
	}

	keyConfigs := []struct {
		name     string
		keyType  string
		size     int
		curveOid string
	}{
		{AES_KEY_NAME, "AES", 256, ""},
		{RSA_KEY_NAME, "RSA", 2048, ""},
		{EC_KEY_NAME, "EC", 0, "1.2.840.10045.3.1.7"}, // P-256 curve OID
		{ED_KEY_NAME, "ED", 0, "1.3.101.112"},         // EdDSA algorithm
	}

	for _, cfg := range keyConfigs {
		attrs := map[string]bool{
			"extractable": false,
			"token":       true,
			"sign":        true,
			"verify":      true,
			"encrypt":     true,
			"decrypt":     true,
			"wrap":        true,
			"unwrap":      true,
			"derive":      false,
			"destroyable": true,
		}

		var size float64
		if cfg.size > 0 {
			size = float64(cfg.size)
		}

		_, err := tsbClient.CreateOrUpdateKey(t.Context(), cfg.name, "", attrs, cfg.keyType, size, nil, cfg.curveOid, false)
		if err != nil {
			t.Logf("Key creation warning for %s: %v", cfg.name, err)
		}
	}
}

func cleanupTestKeys(t *testing.T) {
	tsbClient := getTestClient(t)
	if tsbClient == nil {
		return
	}

	keyNames := []string{AES_KEY_NAME, RSA_KEY_NAME, EC_KEY_NAME, ED_KEY_NAME}

	for _, keyName := range keyNames {
		err := tsbClient.RemoveKey(t.Context(), keyName)
		if err != nil {
			t.Logf("Key cleanup warning for %s: %v", keyName, err)
		}
	}
}

// TestKMS covers the minimum KMS contract: Open, GetKey, Encrypt and Decrypt for AES Key
func TestKMS(t *testing.T) {
	ctx := t.Context()

	setupTestKeys(t)
	defer cleanupTestKeys(t)

	// Get configuration from environment variables
	restAPI := testEnv(SECUROSYS_HSM_RESTAPI_ENV_VAR)
	bearerToken := testEnv(SECUROSYS_BEARER_TOKEN_ENV_VAR)

	if restAPI == "" || bearerToken == "" {
		t.Skip("SECUROSYS_HSM_RESTAPI or SECUROSYS_BEARER_TOKEN not set, skipping test")
	}

	kmsInstance := New()

	err := kmsInstance.Open(ctx, &kms.OpenOptions{
		ConfigMap: kms.ConfigMap{
			"rest_api":     restAPI,
			"auth":         "TOKEN",
			"bearer_token": bearerToken,
		},
	})
	if err != nil {
		t.Fatalf("Failed to open KMS: %v", err)
	}
	defer kmsInstance.Close(ctx)

	key, err := kmsInstance.GetKey(ctx, &kms.KeyOptions{
		ConfigMap: kms.ConfigMap{
			"name": AES_KEY_NAME,
		},
	})
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}

	// Test Encrypt
	plaintext := []byte("Hello, Securosys HSM!")
	encryptOpts := &kms.CipherOptions{
		Data: plaintext,
	}
	ciphertext, err := key.Encrypt(ctx, encryptOpts)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Test Decrypt
	decrypted, err := key.Decrypt(ctx, &kms.CipherOptions{
		Data:  ciphertext,
		Nonce: encryptOpts.Nonce,
	})
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify decryption
	if string(decrypted) != string(plaintext) {
		t.Fatalf("Decrypted data does not match original. Got %s, want %s", string(decrypted), string(plaintext))
	}

	t.Log("Encrypt/Decrypt test passed")
}

func testEnv(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}
