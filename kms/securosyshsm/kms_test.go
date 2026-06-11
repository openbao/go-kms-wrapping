// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package securosyshsm

import (
	"crypto"
	"crypto/rsa"
	"os"
	"testing"

	client "github.com/openbao/go-kms-wrapping/kms/securosyshsm/v2/internal/client"
	"github.com/openbao/go-kms-wrapping/kms/securosyshsm/v2/internal/helpers"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

// KMS configuration environment variables
var SECUROSYS_HSM_RESTAPI_ENV_VAR = "SECUROSYS_HSM_RESTAPI"
var SECUROSYS_BEARER_TOKEN_ENV_VAR = "SECUROSYS_BEARER_TOKEN"

// Test keys names
var AES_KEY_NAME = "openbao_test_aes_key"
var RSA_KEY_NAME = "openbao_test_rsa_key"
var EC_KEY_NAME = "openbao_test_ec_key"
var ED_KEY_NAME = "openbao_test_ed_key"

// getTestClient returns a low-level TSB client used only by acceptance tests to
// create and clean up keys. Tests are skipped unless HSM endpoint credentials
// are provided through environment variables.
func getTestClient(t *testing.T) *client.TSBClient {
	restAPI := os.Getenv(SECUROSYS_HSM_RESTAPI_ENV_VAR)
	bearerToken := os.Getenv(SECUROSYS_BEARER_TOKEN_ENV_VAR)

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

// openTestKMS opens the Securosys implementation through the public kms.KMS
// interface. Acceptance tests use this helper so they exercise the same path
// plugin clients and wrappers use.
func openTestKMS(t *testing.T) kms.KMS {
	t.Helper()

	restAPI := os.Getenv(SECUROSYS_HSM_RESTAPI_ENV_VAR)
	bearerToken := os.Getenv(SECUROSYS_BEARER_TOKEN_ENV_VAR)
	if restAPI == "" || bearerToken == "" {
		t.Skip("SECUROSYS_HSM_RESTAPI or SECUROSYS_BEARER_TOKEN not set, skipping test")
	}

	kmsInstance := New()
	err := kmsInstance.Open(t.Context(), &kms.OpenOptions{
		ConfigMap: kms.ConfigMap{
			"restapi":     restAPI,
			"auth":        "TOKEN",
			"bearertoken": bearerToken,
		},
	})
	if err != nil {
		t.Fatalf("Failed to open KMS: %v", err)
	}

	return kmsInstance
}

// getTestKMSKey resolves a key through kms.KMS.GetKey. cipherAlgorithm is
// optional and drives the provider-specific cipher override used by the cipher
// matrix tests.
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

// assertCipherRoundTrip verifies that a key can encrypt and decrypt the same
// plaintext, carrying the nonce returned by Encrypt into Decrypt.
func assertCipherRoundTrip(t *testing.T, key kms.Key, plaintext, aad []byte) {
	t.Helper()

	encryptOpts := &kms.CipherOptions{
		Data: plaintext,
		AAD:  aad,
	}
	ciphertext, err := key.Encrypt(t.Context(), encryptOpts)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	decrypted, err := key.Decrypt(t.Context(), &kms.CipherOptions{
		Data:  ciphertext,
		AAD:   aad,
		Nonce: encryptOpts.Nonce,
	})
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("Decrypted data does not match original. Got %x, want %x", decrypted, plaintext)
	}
}

// assertSignVerify verifies that Sign and Verify agree for the same algorithm
// mapping. signerOpts is the public kms interface input; algorithm is included
// only to make subtest failures readable.
func assertSignVerify(t *testing.T, key kms.Key, algorithm string, signerOpts crypto.SignerOpts, prehashed bool) {
	t.Helper()

	data := []byte("OpenBao Securosys signature test")
	signature, err := key.Sign(t.Context(), &kms.SignOptions{
		Data:       data,
		Prehashed:  prehashed,
		SignerOpts: signerOpts,
	})
	if err != nil {
		t.Fatalf("Failed to sign with %s: %v", algorithm, err)
	}

	err = key.Verify(t.Context(), &kms.VerifyOptions{
		Signature:  signature,
		Data:       data,
		Prehashed:  prehashed,
		SignerOpts: signerOpts,
	})
	if err != nil {
		t.Fatalf("Failed to verify with %s: %v", algorithm, err)
	}
}

// cipherPlaintext returns payloads that satisfy algorithm-specific constraints.
// RSA_NO_PADDING requires a full RSA block, while AES no-padding modes require
// block-aligned plaintext.
func cipherPlaintext(algorithm string) []byte {
	if algorithm == "RSA_NO_PADDING" {
		plaintext := make([]byte, 256)
		copy(plaintext[len(plaintext)-32:], []byte("openbao securosys rsa no padding"))
		return plaintext
	}
	return []byte("OpenBao Securosys cipher test!!!")
}

// createTestKey creates a key for testing and returns cleanup function.
// It is kept for focused tests that need a single temporary key.
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
	_, err := tsbClient.CreateOrUpdateKey(keyName, "", attrs, keyType, size, nil, "", false)
	if err != nil {
		t.Logf("Key creation warning (may already exist): %v", err)
	}

	// Return cleanup function
	return func() {
		err := tsbClient.RemoveKey(keyName)
		if err != nil {
			t.Logf("Key cleanup warning: %v", err)
		}
	}
}

// setupTestKeys creates the AES, RSA, EC, and ED keys used by acceptance tests.
// Creation warnings are logged because keys may already exist from a previous
// run or from manual setup.
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

		_, err := tsbClient.CreateOrUpdateKey(cfg.name, "", attrs, cfg.keyType, size, nil, cfg.curveOid, false)
		if err != nil {
			t.Logf("Key creation warning for %s: %v", cfg.name, err)
		}
	}
}

// cleanupTestKeys removes the acceptance-test keys after a run. Cleanup errors
// are logged instead of failing the test so the primary operation failure is not
// hidden.
func cleanupTestKeys(t *testing.T) {
	tsbClient := getTestClient(t)
	if tsbClient == nil {
		return
	}

	keyNames := []string{AES_KEY_NAME, RSA_KEY_NAME, EC_KEY_NAME, ED_KEY_NAME}

	for _, keyName := range keyNames {
		err := tsbClient.RemoveKey(keyName)
		if err != nil {
			t.Logf("Key cleanup warning for %s: %v", keyName, err)
		}
	}
}

// TestKMS covers the minimum KMS contract: Open, GetKey, Encrypt, Decrypt, and
// Close using the default AES-GCM behavior.
func TestKMS(t *testing.T) {
	ctx := t.Context()

	// Setup: Create test keys
	setupTestKeys(t)
	defer cleanupTestKeys(t)

	// Get configuration from environment variables
	restAPI := os.Getenv(SECUROSYS_HSM_RESTAPI_ENV_VAR)
	bearerToken := os.Getenv(SECUROSYS_BEARER_TOKEN_ENV_VAR)

	if restAPI == "" || bearerToken == "" {
		t.Skip("SECUROSYS_HSM_RESTAPI or SECUROSYS_BEARER_TOKEN not set, skipping test")
	}

	// Create new KMS instance
	kmsInstance := New()

	// Open KMS with configuration
	err := kmsInstance.Open(ctx, &kms.OpenOptions{
		ConfigMap: kms.ConfigMap{
			"restapi":     restAPI,
			"auth":        "TOKEN",
			"bearertoken": bearerToken,
		},
	})
	if err != nil {
		t.Fatalf("Failed to open KMS: %v", err)
	}
	defer kmsInstance.Close(ctx)

	// Test GetKey with AES key
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

// TestKMSCipherAlgorithms verifies every AES and RSA cipher advertised by the
// Securosys helper constants can round-trip through kms.Key Encrypt/Decrypt.
func TestKMSCipherAlgorithms(t *testing.T) {
	ctx := t.Context()

	setupTestKeys(t)
	defer cleanupTestKeys(t)

	kmsInstance := openTestKMS(t)
	defer kmsInstance.Close(ctx)

	for _, algorithm := range helpers.AES_CIPHER_LIST {
		t.Run("AES/"+algorithm, func(t *testing.T) {
			key := getTestKMSKey(t, kmsInstance, AES_KEY_NAME, algorithm)
			assertCipherRoundTrip(t, key, cipherPlaintext(algorithm), nil)
		})
	}

	for _, algorithm := range helpers.RSA_CIPHER_LIST {
		t.Run("RSA/"+algorithm, func(t *testing.T) {
			key := getTestKMSKey(t, kmsInstance, RSA_KEY_NAME, algorithm)
			assertCipherRoundTrip(t, key, cipherPlaintext(algorithm), nil)
		})
	}
}

// TestKMSSignVerify is the basic RSA-PSS sign/verify smoke test.
func TestKMSSignVerify(t *testing.T) {
	ctx := t.Context()

	// Setup: Create test keys
	setupTestKeys(t)
	defer cleanupTestKeys(t)

	// Get configuration from environment variables
	restAPI := os.Getenv(SECUROSYS_HSM_RESTAPI_ENV_VAR)
	bearerToken := os.Getenv(SECUROSYS_BEARER_TOKEN_ENV_VAR)

	if restAPI == "" || bearerToken == "" {
		t.Skip("SECUROSYS_HSM_RESTAPI or SECUROSYS_BEARER_TOKEN not set, skipping test")
	}

	// Create new KMS instance
	kmsInstance := New()

	// Open KMS with configuration
	err := kmsInstance.Open(ctx, &kms.OpenOptions{
		ConfigMap: kms.ConfigMap{
			"restapi":     restAPI,
			"bearertoken": bearerToken,
			"auth":        "TOKEN",
		},
	})
	if err != nil {
		t.Fatalf("Failed to open KMS: %v", err)
	}
	defer kmsInstance.Close(ctx)

	// Test with RSA key
	key, err := kmsInstance.GetKey(ctx, &kms.KeyOptions{
		ConfigMap: kms.ConfigMap{
			"name": RSA_KEY_NAME,
		},
	})
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}

	// Test Sign
	data := []byte("Message to sign")
	signature, err := key.Sign(ctx, &kms.SignOptions{
		Data:       data,
		Prehashed:  false,
		SignerOpts: &rsa.PSSOptions{Hash: crypto.SHA256},
	})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Test Verify
	err = key.Verify(ctx, &kms.VerifyOptions{
		Signature:  signature,
		Data:       data,
		SignerOpts: &rsa.PSSOptions{Hash: crypto.SHA256},
	})
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	t.Log("Sign/Verify test passed")
}

// TestKMSSignatureAlgorithms verifies the supported signature matrix:
// selected ECDSA algorithms, EDDSA, RSA PKCS#1, and RSA-PSS.
func TestKMSSignatureAlgorithms(t *testing.T) {
	ctx := t.Context()

	setupTestKeys(t)
	defer cleanupTestKeys(t)

	kmsInstance := openTestKMS(t)
	defer kmsInstance.Close(ctx)

	ecKey := getTestKMSKey(t, kmsInstance, EC_KEY_NAME, "")
	for _, tc := range []struct {
		algorithm  string
		signerOpts crypto.SignerOpts
		prehashed  bool
	}{
		{algorithm: "NONE_WITH_ECDSA", signerOpts: crypto.Hash(0), prehashed: true},
		{algorithm: "SHA256_WITH_ECDSA", signerOpts: crypto.SHA256},
		{algorithm: "SHA384_WITH_ECDSA", signerOpts: crypto.SHA384},
		{algorithm: "SHA512_WITH_ECDSA", signerOpts: crypto.SHA512},
	} {
		t.Run("EC/"+tc.algorithm, func(t *testing.T) {
			if !containsString(helpers.EC_SIGNATURE_LIST, tc.algorithm) {
				t.Fatalf("%s is not present in EC_SIGNATURE_LIST", tc.algorithm)
			}
			assertSignVerify(t, ecKey, tc.algorithm, tc.signerOpts, tc.prehashed)
		})
	}

	edKey := getTestKMSKey(t, kmsInstance, ED_KEY_NAME, "")
	for _, algorithm := range helpers.ED_SIGNATURE_LIST {
		t.Run("ED/"+algorithm, func(t *testing.T) {
			assertSignVerify(t, edKey, algorithm, crypto.Hash(0), false)
		})
	}

	rsaKey := getTestKMSKey(t, kmsInstance, RSA_KEY_NAME, "")
	for _, tc := range []struct {
		algorithm  string
		signerOpts crypto.SignerOpts
	}{
		{algorithm: "SHA256_WITH_RSA", signerOpts: crypto.SHA256},
		{algorithm: "SHA384_WITH_RSA", signerOpts: crypto.SHA384},
		{algorithm: "SHA512_WITH_RSA", signerOpts: crypto.SHA512},
		{algorithm: "SHA256_WITH_RSA_PSS", signerOpts: &rsa.PSSOptions{Hash: crypto.SHA256}},
		{algorithm: "SHA384_WITH_RSA_PSS", signerOpts: &rsa.PSSOptions{Hash: crypto.SHA384}},
		{algorithm: "SHA512_WITH_RSA_PSS", signerOpts: &rsa.PSSOptions{Hash: crypto.SHA512}},
	} {
		t.Run("RSA/"+tc.algorithm, func(t *testing.T) {
			if !containsString(helpers.RSA_SIGNATURE_LIST, tc.algorithm) {
				t.Fatalf("%s is not present in RSA_SIGNATURE_LIST", tc.algorithm)
			}
			assertSignVerify(t, rsaKey, tc.algorithm, tc.signerOpts, false)
		})
	}
}

// TestKMSExportPublic verifies RSA public key export parses into a standard
// library public key.
func TestKMSExportPublic(t *testing.T) {
	ctx := t.Context()

	// Setup: Create test keys
	setupTestKeys(t)
	defer cleanupTestKeys(t)

	// Get configuration from environment variables
	restAPI := os.Getenv(SECUROSYS_HSM_RESTAPI_ENV_VAR)
	bearerToken := os.Getenv(SECUROSYS_BEARER_TOKEN_ENV_VAR)

	if restAPI == "" || bearerToken == "" {
		t.Skip("SECUROSYS_HSM_RESTAPI or SECUROSYS_BEARER_TOKEN not set, skipping test")
	}

	// Create new KMS instance
	kmsInstance := New()

	// Open KMS with configuration
	err := kmsInstance.Open(ctx, &kms.OpenOptions{
		ConfigMap: kms.ConfigMap{
			"restapi":     restAPI,
			"bearertoken": bearerToken,
			"auth":        "TOKEN",
		},
	})
	if err != nil {
		t.Fatalf("Failed to open KMS: %v", err)
	}
	defer kmsInstance.Close(ctx)

	// Test with RSA key
	key, err := kmsInstance.GetKey(ctx, &kms.KeyOptions{
		ConfigMap: kms.ConfigMap{
			"name": RSA_KEY_NAME,
		},
	})
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}

	// Test ExportPublic
	pubKey, err := key.ExportPublic(ctx)
	if err != nil {
		t.Fatalf("Failed to export public key: %v", err)
	}

	if pubKey == nil {
		t.Fatalf("Public key is nil")
	}

	t.Logf("Exported public key: %T", pubKey)
	t.Log("ExportPublic test passed")
}

// TestKMSWithAAD verifies AES-GCM authenticated data handling, including nonce
// propagation between Encrypt and Decrypt.
func TestKMSWithAAD(t *testing.T) {
	ctx := t.Context()

	// Setup: Create test keys
	setupTestKeys(t)
	defer cleanupTestKeys(t)

	// Get configuration from environment variables
	restAPI := os.Getenv(SECUROSYS_HSM_RESTAPI_ENV_VAR)
	bearerToken := os.Getenv(SECUROSYS_BEARER_TOKEN_ENV_VAR)

	if restAPI == "" || bearerToken == "" {
		t.Skip("SECUROSYS_HSM_RESTAPI or SECUROSYS_BEARER_TOKEN not set, skipping test")
	}

	// Create new KMS instance
	kmsInstance := New()

	// Open KMS with configuration
	err := kmsInstance.Open(ctx, &kms.OpenOptions{
		ConfigMap: kms.ConfigMap{
			"restapi":     restAPI,
			"bearertoken": bearerToken,
			"auth":        "TOKEN",
		},
	})
	if err != nil {
		t.Fatalf("Failed to open KMS: %v", err)
	}
	defer kmsInstance.Close(ctx)

	// Test GetKey with AES key
	key, err := kmsInstance.GetKey(ctx, &kms.KeyOptions{
		ConfigMap: kms.ConfigMap{
			"name": AES_KEY_NAME,
		},
	})
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}

	// Test Encrypt with AAD
	plaintext := []byte("Hello, Securosys HSM with AAD!")
	aad := []byte("additional authenticated data")
	encryptOpts := &kms.CipherOptions{
		Data: plaintext,
		AAD:  aad,
	}
	ciphertext, err := key.Encrypt(ctx, encryptOpts)
	if err != nil {
		t.Fatalf("Failed to encrypt with AAD: %v", err)
	}

	// Test Decrypt with AAD
	decrypted, err := key.Decrypt(ctx, &kms.CipherOptions{
		Data:  ciphertext,
		AAD:   aad,
		Nonce: encryptOpts.Nonce,
	})
	if err != nil {
		t.Fatalf("Failed to decrypt with AAD: %v", err)
	}

	// Verify decryption
	if string(decrypted) != string(plaintext) {
		t.Fatalf("Decrypted data does not match original. Got %s, want %s", string(decrypted), string(plaintext))
	}

	t.Log("Encrypt/Decrypt with AAD test passed")
}
