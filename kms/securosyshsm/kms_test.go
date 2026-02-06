// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package securosyshsm

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	mathrand "math/rand"
	"os"
	"testing"
	"time"

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

func TestKeystore(t *testing.T) {

	ctx := t.Context()

	kmsConfig := getKmsConfigFromEnvVars(t)
	keystore, err := NewKeyStore(kmsConfig)
	if err != nil || keystore == nil {
		t.Fatal("Failed to initialize Securosys HSM keystore")
	}
	defer keystore.Close(ctx)

	key, err := generateTestKeyAES(ctx, keystore, AES_KEY_NAME, true)
	if err != nil || key == nil {
		t.Fatal("Failed to generate AES key")
	}

	if key.GetName() != AES_KEY_NAME {
		t.Fatalf("Key label is not correct. Want %s got %s", AES_KEY_NAME, key.GetName())
	}

	if key.GetType() != kms.KeyType_AES {
		t.Fatalf("Key type is not correct. Want %d got %d", kms.KeyType_AES, key.GetType())
	}
	if key.GetLength() != 256 {
		t.Fatalf("Key size is not correct. Want %d got %d", 256, key.GetLength())
	}

	var rsaKey *PrivateKey = nil
	rsaKey, _, err = generateTestKeyRSA(ctx, keystore, RSA_KEY_NAME)
	if err != nil || rsaKey == nil {
		t.Fatal("Failed to generate RSA key")
	}

	if rsaKey.GetName() != RSA_KEY_NAME {
		t.Fatalf("Key label is not correct. Want %s got %s", RSA_KEY_NAME, key.GetName())
	}

	if rsaKey.GetType() != kms.KeyType_RSA_Private {
		t.Fatalf("Key type is not correct. Want %d got %d", kms.KeyType_RSA_Private, key.GetType())
	}

	if rsaKey.GetLength() != 2048 {
		t.Fatalf("Key size is not correct. Want %d got %d", 2048, key.GetLength())
	}

	keys, err := keystore.ListKeys(ctx)
	if err != nil || keys == nil {
		t.Fatal("ListKeys failed")
	}
	if len(keys) <= 2 {
		t.Fatalf("Incorrect ListKeys result. Expected at least 2 keys,  got %d", len(keys))
	}

	err = keystore.RemoveKey(ctx, key)
	if err != nil {
		t.Fatal("RemoveKey failed")
	}

	err = keystore.RemoveKey(ctx, rsaKey)
	if err != nil {
		t.Fatal("RemoveKey failed")
	}

}

func TestCipher(t *testing.T) {

	plaintext := "the quick brown fox jumps over the lazy dog"
	ctx := t.Context()

	kmsConfig := getKmsConfigFromEnvVars(t)
	keystore, err := NewKeyStore(kmsConfig)
	if err != nil || keystore == nil {
		t.Fatal("Failed to initialize Securosys HSM keystore")
	}
	defer keystore.Close(ctx)

	key, err := generateTestKeyAES(ctx, keystore, AES_KEY_NAME, true)
	if err != nil || key == nil {
		t.Fatal("Failed to generate AES key")
	}

	aesGcmCipher(t, key, plaintext, "")
	aesGcmCipher(t, key, plaintext, "test_aad")

	err = removeKey(ctx, key, keystore)
	if err != nil {
		t.Fatal("Failed to remove key")
	}

	// RSA cipher tests
	privateKey, publicKey, err := generateTestKeyRSA(ctx, keystore, RSA_KEY_NAME)
	if err != nil || privateKey == nil || publicKey == nil {
		t.Fatal("Failed to generate RSA key pair")
	}

	asymCipher(t, kms.CipherMode_RSA_OAEP_SHA256, privateKey, publicKey, plaintext)
	asymCipher(t, kms.CipherMode_RSA_OAEP_SHA384, privateKey, publicKey, plaintext)
	asymCipher(t, kms.CipherMode_RSA_OAEP_SHA512, privateKey, publicKey, plaintext)

	err = removeKey(ctx, privateKey, keystore)
	if err != nil {
		t.Fatal("Failed to remove key")
	}
}

func TestSignVerify(t *testing.T) {

	message := "the quick brown fox jumps over the lazy dog"
	ctx := t.Context()

	kmsConfig := getKmsConfigFromEnvVars(t)
	keystore, err := NewKeyStore(kmsConfig)
	if err != nil || keystore == nil {
		t.Fatal("Failed to initialize Securosys HSM keystore")
	}
	defer keystore.Close(ctx)

	// RSA sign/verify tests
	privateKey, publicKey, err := generateTestKeyRSA(ctx, keystore, RSA_KEY_NAME)
	if err != nil || privateKey == nil || publicKey == nil {
		t.Fatal("Failed to generate RSA key pair")
	}

	signVerify(t, kms.SignAlgo_RSA_PKCS1_PSS_SHA_256, privateKey, publicKey, message)
	signVerify(t, kms.SignAlgo_RSA_PKCS1_PSS_SHA_384, privateKey, publicKey, message)
	signVerify(t, kms.SignAlgo_RSA_PKCS1_PSS_SHA_512, privateKey, publicKey, message)

	err = removeKey(ctx, privateKey, keystore)
	if err != nil {
		t.Fatal("Failed to remove key")
	}

	// EC sign/verify tests
	privateKey, publicKey, err = generateTestKeyEC(ctx, kms.Curve_P256, keystore, EC_KEY_NAME)
	if err != nil || privateKey == nil || publicKey == nil {
		t.Fatal("Failed to generate EC key pair")
	}

	signVerify(t, kms.SignAlgo_EC_P256, privateKey, publicKey, message)

	err = removeKey(ctx, privateKey, keystore)
	if err != nil {
		t.Fatal("Failed to remove key")
	}

	privateKey, publicKey, err = generateTestKeyEC(ctx, kms.Curve_P384, keystore, EC_KEY_NAME)
	if err != nil || privateKey == nil || publicKey == nil {
		t.Fatal("Failed to generate EC key pair")
	}

	signVerify(t, kms.SignAlgo_EC_P384, privateKey, publicKey, message)

	err = removeKey(ctx, privateKey, keystore)
	if err != nil {
		t.Fatal("Failed to remove key")
	}

	privateKey, publicKey, err = generateTestKeyEC(ctx, kms.Curve_P521, keystore, EC_KEY_NAME)
	if err != nil || privateKey == nil || publicKey == nil {
		t.Fatal("Failed to generate EC key pair")
	}

	signVerify(t, kms.SignAlgo_EC_P521, privateKey, publicKey, message)

	err = removeKey(ctx, privateKey, keystore)
	if err != nil {
		t.Fatal("Failed to remove key")
	}

	// ED sign/verify tests
	privateKey, publicKey, err = generateTestKeyED(ctx, keystore, ED_KEY_NAME)
	if err != nil || privateKey == nil || publicKey == nil {
		t.Fatal("Failed to generate ED key pair")
	}

	signVerify(t, kms.SignAlgo_ED, privateKey, publicKey, message)

	err = removeKey(ctx, privateKey, keystore)
	if err != nil {
		t.Fatal("Failed to remove key")
	}

}

func TestSign_x509Certificate(t *testing.T) {

	sk := kms.Certx509SigningKey{}
	ctx := t.Context()

	kmsConfig := getKmsConfigFromEnvVars(t)
	keystore, err := NewKeyStore(kmsConfig)
	if err != nil || keystore == nil {
		t.Fatal("Failed to initialize Securosys HSM keystore")
	}
	defer keystore.Close(ctx)

	caCertTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "root.localhost",
		},
		SubjectKeyId:          []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		DNSNames:              []string{"root.localhost"},
		KeyUsage:              x509.KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign),
		SerialNumber:          big.NewInt(mathrand.Int63()),
		NotAfter:              time.Now().Add(262980 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Issue certificate with signature using ED key
	privateKey, publicKey, err := generateTestKeyED(ctx, keystore, ED_KEY_NAME)
	if err != nil || privateKey == nil || publicKey == nil {
		t.Fatal("Failed to generate ED key pair")
	}

	sk.SignPrivateKey = privateKey

	cert, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, sk.Public(), &sk)
	if err != nil || cert == nil {
		t.Fatal("Failed to sign X509 certficate using KMS signer")
	}

	err = removeKey(ctx, privateKey, keystore)
	if err != nil {
		t.Fatal("Failed to remove key")
	}

	// Issue certificate with signature using EC key
	privateKey, publicKey, err = generateTestKeyEC(ctx, kms.Curve_P256, keystore, EC_KEY_NAME)
	if err != nil || privateKey == nil || publicKey == nil {
		t.Fatal("Failed to generate EC key pair")
	}

	sk.SignPrivateKey = privateKey

	cert, err = x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, sk.Public(), &sk)
	if err != nil || cert == nil {
		t.Fatal("Failed to sign X509 certficate using KMS signer")
	}

	err = removeKey(ctx, privateKey, keystore)
	if err != nil {
		t.Fatal("Failed to remove key")
	}

	/* Disabled EC P384 and P521 tests for now

	privateKey, publicKey, err = generateTestKeyEC(ctx, kms.Curve_P384, keystore, EC_KEY_NAME)
	if err != nil || privateKey == nil || publicKey == nil {
		t.Fatal("Failed to generate EC key pair")
	}

	sk.SignPrivateKey = privateKey

	cert, err = x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, sk.Public(), &sk)
	if err != nil || cert == nil {
		t.Fatal("Failed to sign X509 certficate using KMS signer")
	}

	err = removeKey(ctx, privateKey, keystore)
	if err != nil {
		t.Fatal("Failed to remove key")
	}

	privateKey, publicKey, err = generateTestKeyEC(ctx, kms.Curve_P521, keystore, EC_KEY_NAME)
	if err != nil || privateKey == nil || publicKey == nil {
		t.Fatal("Failed to generate EC key pair")
	}

	sk.SignPrivateKey = privateKey

	cert, err = x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, sk.Public(), &sk)
	if err != nil || cert == nil {
		t.Fatal("Failed to sign X509 certficate using KMS signer")
	}

	err = removeKey(ctx, privateKey, keystore)
	if err != nil {
		t.Fatal("Failed to remove key")
	}
	*/

	// Issue certificate with signature using RSA key
	privateKey, publicKey, err = generateTestKeyRSA(ctx, keystore, RSA_KEY_NAME)
	if err != nil || privateKey == nil || publicKey == nil {
		t.Fatal("Failed to generate RSA key pair")
	}

	sk.SignPrivateKey = privateKey
	caCertTemplate.SignatureAlgorithm = x509.SHA256WithRSAPSS
	cert, err = x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, sk.Public(), &sk)
	if err != nil || cert == nil {
		t.Fatal("Failed to sign X509 certficate using KMS signer")
	}

	caCertTemplate.SignatureAlgorithm = x509.SHA384WithRSAPSS
	cert, err = x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, sk.Public(), &sk)
	if err != nil || cert == nil {
		t.Fatal("Failed to sign X509 certficate using KMS signer")
	}

	caCertTemplate.SignatureAlgorithm = x509.SHA512WithRSAPSS
	cert, err = x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, sk.Public(), &sk)
	if err != nil || cert == nil {
		t.Fatal("Failed to sign X509 certficate using KMS signer")
	}

	err = removeKey(ctx, privateKey, keystore)
	if err != nil {
		t.Fatal("Failed to remove key")
	}

}

func generateTestKeyAES(ctx context.Context, keystore kms.KeyStore, keyName string, forceNewKey bool) (*SecretKey, error) {

	key, err := keystore.GetKeyByName(ctx, keyName)
	if key != nil {
		if forceNewKey {
			err = keystore.RemoveKey(ctx, key)
		} else {
			return key.(*SecretKey), nil
		}
	}
	key, err = keystore.GenerateSecretKey(ctx, &kms.KeyAttributes{
		KeyType:     kms.KeyType_AES,
		Name:        keyName,
		BitKeyLen:   256,
		IsRemovable: true,
		CanDecrypt:  true,
		CanEncrypt:  true,
	})
	return key.(*SecretKey), err
}
func generateTestKeyRSA(ctx context.Context, keystore kms.KeyStore, keyName string) (*PrivateKey, *PublicKey, error) {
	key, err := keystore.GetKeyByName(ctx, keyName)
	if key != nil {
		err = keystore.RemoveKey(ctx, key)
	}

	privateKey, publicKey, err := keystore.GenerateKeyPair(ctx, &kms.KeyAttributes{
		KeyType:     kms.KeyType_RSA_Private,
		Name:        keyName,
		BitKeyLen:   2048,
		IsRemovable: true,
		CanDecrypt:  true,
		CanEncrypt:  true,
		CanSign:     true,
		CanVerify:   true,
	})
	return privateKey.(*PrivateKey), publicKey.(*PublicKey), err
}
func generateTestKeyEC(ctx context.Context, curve kms.Curve, keystore kms.KeyStore, keyName string) (*PrivateKey, *PublicKey, error) {
	key, err := keystore.GetKeyByName(ctx, keyName)
	if key != nil {
		err = keystore.RemoveKey(ctx, key)
	}

	privateKey, publicKey, err := keystore.GenerateKeyPair(ctx, &kms.KeyAttributes{
		KeyType:     kms.KeyType_EC_Private,
		Name:        keyName,
		Curve:       curve,
		IsRemovable: true,
		CanDecrypt:  true,
		CanEncrypt:  true,
		CanSign:     true,
		CanVerify:   true,
	})
	return privateKey.(*PrivateKey), publicKey.(*PublicKey), err
}
func generateTestKeyED(ctx context.Context, keystore kms.KeyStore, keyName string) (*PrivateKey, *PublicKey, error) {
	key, err := keystore.GetKeyByName(ctx, keyName)
	if key != nil {
		err = keystore.RemoveKey(ctx, key)
	}

	privateKey, publicKey, err := keystore.GenerateKeyPair(ctx, &kms.KeyAttributes{
		KeyType:     kms.KeyType_ED_Private,
		Name:        keyName,
		Curve:       kms.Curve_None,
		IsRemovable: true,
		CanDecrypt:  true,
		CanEncrypt:  true,
		CanSign:     true,
		CanVerify:   true,
	})
	return privateKey.(*PrivateKey), publicKey.(*PublicKey), err
}
func removeKey(ctx context.Context, key kms.Key, keystore kms.KeyStore) error {
	err := keystore.RemoveKey(ctx, key)
	return err
}

func aesGcmCipher(t *testing.T, key *SecretKey, plaintext, aad string) {

	algo := kms.CipherMode_AES_GCM96
	tagLength := 16

	ctx := t.Context()

	// Single-part encrypt
	algoParams := kms.AESGCMCipherParameters{
		Nonce: nil,
		AAD:   []byte(aad),
	}
	cipherEncrypt, err := (*key).NewCipher(ctx, kms.CipherOp_Encrypt, &kms.CipherParameters{
		Algorithm:  algo,
		Parameters: &algoParams,
	})
	if err != nil || cipherEncrypt == nil {
		t.Fatalf("Failed to initialize Cipher for algorithm %d", algo)
	}

	ciphertext, err := cipherEncrypt.Close(ctx, []byte(plaintext))
	if err != nil || ciphertext == nil {
		t.Fatalf("Failed to encrypt data for algorithm %d", algo)
	}

	// Single-part decrypt (use IV/Nonce generated by the encryption cipher)
	algoParams = kms.AESGCMCipherParameters{
		Nonce: cipherEncrypt.(*Cipher).cipherParams.Parameters.(*kms.AESGCMCipherParameters).Nonce,
		AAD:   []byte(aad),
	}
	decryptCipher, err := (*key).NewCipher(ctx, kms.CipherOp_Decrypt, &kms.CipherParameters{
		Algorithm:  algo,
		Parameters: &algoParams,
	})
	if err != nil || decryptCipher == nil {
		t.Fatalf("Failed to initialize Cipher for algorithm %d", algo)
	}

	decryptedPayload, err := decryptCipher.Close(ctx, ciphertext)
	if err != nil || decryptedPayload == nil {
		t.Fatalf("Failed to decrypt data for algorithm %d", algo)
	}

	if string(decryptedPayload) != plaintext {
		t.Fatalf("Decrypted payload mismatch. Want %s got %s", plaintext, string(decryptedPayload))
	}

	// Test MAC verification failure with wrong AAD/ciphertext

	algoParams = kms.AESGCMCipherParameters{
		Nonce: cipherEncrypt.(*Cipher).cipherParams.Parameters.(*kms.AESGCMCipherParameters).Nonce,
		AAD:   []byte("dummy_aad"),
	}

	decryptCipher, err = (*key).NewCipher(ctx, kms.CipherOp_Decrypt, &kms.CipherParameters{
		Algorithm:  algo,
		Parameters: &algoParams,
	})
	if err != nil || decryptCipher == nil {
		t.Fatalf("Failed to initialize Cipher for algorithm %d", algo)
	}

	_, err = decryptCipher.Close(ctx, ciphertext)
	if err == nil {
		t.Fatalf("Failed to detect corrupted AAD for algorithm %d", algo)
	}

	algoParams = kms.AESGCMCipherParameters{
		Nonce: cipherEncrypt.(*Cipher).cipherParams.Parameters.(*kms.AESGCMCipherParameters).Nonce,
		AAD:   []byte(aad),
	}
	decryptCipher, err = (*key).NewCipher(ctx, kms.CipherOp_Decrypt, &kms.CipherParameters{
		Algorithm:  algo,
		Parameters: &algoParams,
	})
	if err != nil || decryptCipher == nil {
		t.Fatalf("Failed to initialize Cipher for algorithm %d", algo)
	}

	ciphertext[0] = ciphertext[0] + 1 // Corrupt ciphertext
	_, err = decryptCipher.Close(ctx, ciphertext)
	if err == nil {
		t.Fatalf("Failed to detect corrupted ciphertext for algorithm %d", algo)
	}

	// Multi-part encrypt
	cipherEncrypt, err = (*key).NewCipher(ctx, kms.CipherOp_Encrypt, &kms.CipherParameters{
		Algorithm: algo,
	})
	if err != nil || cipherEncrypt == nil {
		t.Fatalf("Failed to initialize Cipher for algorithm %d", algo)
	}

	ciphertext = []byte{}
	i := 0
	for ; i < len(plaintext)-1; i++ {
		chunk, err := cipherEncrypt.Update(ctx, []byte(plaintext[i:i+1]))
		if err != nil {
			t.Fatalf("Cipher encrypt update failed for algorithm %d", algo)
		}
		if chunk != nil {
			ciphertext = append(ciphertext, chunk...)
		}
	}

	chunk, err := cipherEncrypt.Close(ctx, []byte(plaintext[i:i+1]))
	if err != nil {
		t.Fatalf("Cipher encrypt update failed for algorithm %d", algo)
	}
	if chunk != nil {
		ciphertext = append(ciphertext, chunk...)
	}

	// Multi-part decrypt (use IV/Nonce generated by the encryption cipher)
	algoParams = kms.AESGCMCipherParameters{
		Nonce: cipherEncrypt.(*Cipher).cipherParams.Parameters.(*kms.AESGCMCipherParameters).Nonce,
		AAD:   nil,
	}
	decryptCipher, err = (*key).NewCipher(ctx, kms.CipherOp_Decrypt, &kms.CipherParameters{
		Algorithm:  algo,
		Parameters: &algoParams,
	})
	if err != nil || decryptCipher == nil {
		t.Fatalf("Failed to initialize Cipher for algorithm %d", algo)
	}

	decryptedPayload = []byte{}
	i = 0
	for ; i < len(ciphertext)-tagLength-1; i++ {
		chunk, err := decryptCipher.Update(ctx, ciphertext[i:i+1])
		if err != nil {
			t.Fatalf("Cipher encrypt update failed for algorithm %d", algo)
		}
		if chunk != nil {
			decryptedPayload = append(decryptedPayload, chunk...)
		}
	}

	// The last chunk includes the tag
	chunk, err = decryptCipher.Close(ctx, []byte(ciphertext[i:i+tagLength+1]))
	if err != nil {
		t.Fatalf("Cipher encrypt update failed for algorithm %d", algo)
	}
	if chunk != nil {
		decryptedPayload = append(decryptedPayload, chunk...)
	}

	test := string(decryptedPayload)
	if test != plaintext {
		t.Fatalf("Decrypted payload mismatch. Want %s got %s", plaintext, string(decryptedPayload))
	}
}

func asymCipher(t *testing.T, algo kms.CipherAlgorithmMode, privateKey *PrivateKey, publicKey *PublicKey, plaintext string) {

	ctx := t.Context()

	// Single-part encrypt with public key
	cipherEncrypt, err := (*publicKey).NewCipher(ctx, kms.CipherOp_Encrypt, &kms.CipherParameters{
		Algorithm: algo,
	})
	if err != nil || cipherEncrypt == nil {
		t.Fatalf("Failed to initialize Cipher for algorithm %d", algo)
	}

	ciphertext, err := cipherEncrypt.Close(ctx, []byte(plaintext))
	if err != nil || ciphertext == nil {
		t.Fatalf("Failed to encrypt data for algorithm %d", algo)
	}

	// Single-part decrypt with private key
	decryptCipher, err := (*privateKey).NewCipher(ctx, kms.CipherOp_Decrypt, &kms.CipherParameters{
		Algorithm: algo,
	})
	if err != nil || decryptCipher == nil {
		t.Fatalf("Failed to initialize Cipher for algorithm %d", algo)
	}

	decryptedPayload, err := decryptCipher.Close(ctx, ciphertext)
	if err != nil || decryptedPayload == nil {
		t.Fatalf("Failed to decrypt data for algorithm %d", algo)
	}

	if string(decryptedPayload) != plaintext {
		t.Fatalf("Decrypted payload mismatch. Want %s got %s", plaintext, string(decryptedPayload))
	}

}

func signVerify(t *testing.T, algo kms.SignAlgorithm, privateKey *PrivateKey, publicKey *PublicKey, message string) {

	ctx := t.Context()

	// Single-part signing with private key
	signer, err := (*privateKey).NewRemoteDigestSigner(ctx, &kms.SignerParameters{
		Algorithm: algo,
	})
	if err != nil || signer == nil {
		t.Fatalf("Failed to initialize Signer for algorithm %d", algo)
	}

	signature, err := signer.Close(ctx, []byte(message))
	if err != nil || signature == nil {
		t.Fatalf("Failed to sign message for algorithm %d", algo)
	}

	// Single-part signature verification with public key
	verifier, err := (*publicKey).NewRemoteDigestVerifier(ctx, &kms.VerifierParameters{
		Algorithm: algo,
	})
	if err != nil || verifier == nil {
		t.Fatalf("Failed to initialize Verifier for algorithm %d", algo)
	}

	err = verifier.Close(ctx, []byte(message), signature)
	if err != nil {
		t.Fatalf("Failed to verify signature for algorithm %d", algo)
	}

	// Verify with wrong message - must fail
	verifier, err = (*publicKey).NewRemoteDigestVerifier(ctx, &kms.VerifierParameters{
		Algorithm: algo,
	})
	if err != nil || verifier == nil {
		t.Fatalf("Failed to initialize Verifier for algorithm %d", algo)
	}

	wrongMsg := []byte(message)
	wrongMsg[0] ^= 0xFF
	err = verifier.Close(ctx, wrongMsg, signature)
	if err == nil {
		t.Fatalf("Verify signature for algorithm %d must fail with wrong message", algo)
	}

}

func getKmsConfigFromEnvVars(t *testing.T) map[string]interface{} {
	t.Helper()

	// Skip tests if we are not running acceptance tests
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	var kmsConfig = map[string]interface{}{
		"restapi":     "",
		"auth":        "TOKEN",
		"bearertoken": "",
	}

	kmsConfig["restapi"] = os.Getenv(SECUROSYS_HSM_RESTAPI_ENV_VAR)
	if kmsConfig["restapi"] == "" {
		t.Fatalf("unable to get Securosys HSM REST API endpoint via environment variable %s", SECUROSYS_HSM_RESTAPI_ENV_VAR)
	}

	kmsConfig["bearertoken"] = os.Getenv(SECUROSYS_BEARER_TOKEN_ENV_VAR)
	if kmsConfig["bearertoken"] == "" {
		t.Fatalf("unable to get Securosys bearer token via environment variable %s", SECUROSYS_BEARER_TOKEN_ENV_VAR)
	}

	return kmsConfig
}
