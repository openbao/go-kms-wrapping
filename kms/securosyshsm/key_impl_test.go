// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/openbao/go-kms-wrapping/v2/kms"
	client "github.com/securosys-com/tsb-client-go"
	"github.com/securosys-com/tsb-client-go/helpers"
)

func TestMapRSAAlgorithm(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hash      crypto.Hash
		prehashed bool
		pss       bool
		want      string
	}{
		{name: "none pkcs1", hash: crypto.Hash(0), prehashed: true, want: "NONE_WITH_RSA"},
		{name: "none pss", hash: crypto.Hash(0), prehashed: true, pss: true, want: "NONE_WITH_RSA_PSS"},
		{name: "sha256 pkcs1", hash: crypto.SHA256, want: "SHA256_WITH_RSA"},
		{name: "sha384 pkcs1", hash: crypto.SHA384, want: "SHA384_WITH_RSA"},
		{name: "sha512 pkcs1", hash: crypto.SHA512, want: "SHA512_WITH_RSA"},
		{name: "sha256 pss", hash: crypto.SHA256, pss: true, want: "SHA256_WITH_RSA_PSS"},
		{name: "sha384 pss", hash: crypto.SHA384, pss: true, want: "SHA384_WITH_RSA_PSS"},
		{name: "sha512 pss", hash: crypto.SHA512, pss: true, want: "SHA512_WITH_RSA_PSS"},
		{name: "prehashed sha256 pkcs1", hash: crypto.SHA256, prehashed: true, want: "NONESHA256_WITH_RSA"},
		{name: "prehashed sha384 pkcs1", hash: crypto.SHA384, prehashed: true, want: "NONESHA384_WITH_RSA"},
		{name: "prehashed sha512 pkcs1", hash: crypto.SHA512, prehashed: true, want: "NONESHA512_WITH_RSA"},
		{name: "prehashed sha256 pss", hash: crypto.SHA256, prehashed: true, pss: true, want: "NONESHA256_WITH_RSA_PSS"},
		{name: "prehashed sha384 pss", hash: crypto.SHA384, prehashed: true, pss: true, want: "NONESHA384_WITH_RSA_PSS"},
		{name: "prehashed sha512 pss", hash: crypto.SHA512, prehashed: true, pss: true, want: "NONESHA512_WITH_RSA_PSS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mapRSAAlgorithm(tc.hash, tc.prehashed, tc.pss)
			if err != nil {
				t.Fatalf("mapRSAAlgorithm returned error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("mapRSAAlgorithm = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMapRSAAlgorithmErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		hash crypto.Hash
		pss  bool
	}{
		{name: "missing rsa hash", hash: crypto.Hash(0)},
		{name: "missing pss hash", hash: crypto.Hash(0), pss: true},
		{name: "unsupported rsa hash", hash: crypto.SHA1},
		{name: "unsupported pss hash", hash: crypto.SHA1, pss: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := mapRSAAlgorithm(tc.hash, false, tc.pss); err == nil {
				t.Fatalf("mapRSAAlgorithm = %q, want error", got)
			}
		})
	}
}

func TestMapSignAlgorithmFromOpts(t *testing.T) {
	rsaPub := &rsa.PublicKey{}
	ec256Pub := &ecdsa.PublicKey{Curve: elliptic.P256()}
	ec384Pub := &ecdsa.PublicKey{Curve: elliptic.P384()}
	ec521Pub := &ecdsa.PublicKey{Curve: elliptic.P521()}
	edPub := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))

	for _, tc := range []struct {
		name string
		opts *kms.SignOptions
		pub  crypto.PublicKey
		want string
	}{
		{name: "rsa sha256", pub: rsaPub, opts: &kms.SignOptions{SignerOpts: crypto.SHA256}, want: "SHA256_WITH_RSA"},
		{name: "rsa sha384", pub: rsaPub, opts: &kms.SignOptions{SignerOpts: crypto.SHA384}, want: "SHA384_WITH_RSA"},
		{name: "rsa sha512", pub: rsaPub, opts: &kms.SignOptions{SignerOpts: crypto.SHA512}, want: "SHA512_WITH_RSA"},
		{name: "rsa none", pub: rsaPub, opts: &kms.SignOptions{Prehashed: true, SignerOpts: crypto.Hash(0)}, want: "NONE_WITH_RSA"},
		{name: "rsa prehashed sha256", pub: rsaPub, opts: &kms.SignOptions{Prehashed: true, SignerOpts: crypto.SHA256}, want: "NONESHA256_WITH_RSA"},
		{name: "rsa pss sha256", pub: rsaPub, opts: &kms.SignOptions{SignerOpts: &rsa.PSSOptions{Hash: crypto.SHA256}}, want: "SHA256_WITH_RSA_PSS"},
		{name: "rsa pss prehashed sha256", pub: rsaPub, opts: &kms.SignOptions{Prehashed: true, SignerOpts: &rsa.PSSOptions{Hash: crypto.SHA256}}, want: "NONESHA256_WITH_RSA_PSS"},
		{name: "ecdsa prehashed", pub: ec256Pub, opts: &kms.SignOptions{Prehashed: true, SignerOpts: crypto.Hash(0)}, want: "NONE_WITH_ECDSA"},
		{name: "ecdsa p256 default hash", pub: ec256Pub, opts: &kms.SignOptions{SignerOpts: crypto.Hash(0)}, want: "SHA256_WITH_ECDSA"},
		{name: "ecdsa p384 default hash", pub: ec384Pub, opts: &kms.SignOptions{SignerOpts: crypto.Hash(0)}, want: "SHA384_WITH_ECDSA"},
		{name: "ecdsa p521 default hash", pub: ec521Pub, opts: &kms.SignOptions{SignerOpts: crypto.Hash(0)}, want: "SHA512_WITH_ECDSA"},
		{name: "ecdsa sha256", pub: ec256Pub, opts: &kms.SignOptions{SignerOpts: crypto.SHA256}, want: "SHA256_WITH_ECDSA"},
		{name: "ed25519", pub: edPub, opts: &kms.SignOptions{SignerOpts: crypto.Hash(0)}, want: "EDDSA"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mapSignAlgorithmFromOpts(tc.opts, tc.pub)
			if err != nil {
				t.Fatalf("mapSignAlgorithmFromOpts returned error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("mapSignAlgorithmFromOpts = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSignatureTypeForPublicKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		pub  crypto.PublicKey
		want client.SignatureType
	}{
		{name: "rsa uses client default (der)", pub: &rsa.PublicKey{}, want: client.SignatureTypeDER},
		{name: "ecdsa uses client default (der)", pub: &ecdsa.PublicKey{Curve: elliptic.P256()}, want: client.SignatureTypeDER},
		{name: "ed25519 uses raw", pub: ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)), want: client.SignatureTypeRAW},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := signatureTypeForPublicKey(tc.pub); got != tc.want {
				t.Fatalf("signatureTypeForPublicKey = %q, want %q", got, tc.want)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestMLKEMCiphertextEnvelopeValidation(t *testing.T) {
	for _, ciphertext := range [][]byte{
		nil,
		[]byte("not an ML-KEM envelope"),
		append([]byte(mlKEMEnvelopeMagic), 2),
	} {
		if _, _, _, err := unmarshalMLKEMEnvelope(ciphertext); err == nil {
			t.Fatalf("unmarshalMLKEMEnvelope(%x) succeeded, want error", ciphertext)
		}
	}

	if _, err := marshalMLKEMEnvelope("ciphertext", make([]byte, mlKEMNonceSize-1), make([]byte, aes.BlockSize)); err == nil {
		t.Fatal("marshalMLKEMEnvelope with invalid nonce length succeeded")
	}
}

func TestKeyCryptoAESAlgorithms(t *testing.T) {
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
}

func TestKeyCryptoRSAAlgorithms(t *testing.T) {
	ctx := t.Context()

	setupTestKeys(t)
	defer cleanupTestKeys(t)

	kmsInstance := openTestKMS(t)
	defer kmsInstance.Close(ctx)

	for _, algorithm := range helpers.RSA_CIPHER_LIST {
		t.Run("RSA/"+algorithm, func(t *testing.T) {
			key := getTestKMSKey(t, kmsInstance, RSA_KEY_NAME, algorithm)
			assertCipherRoundTrip(t, key, cipherPlaintext(algorithm), nil)
		})
	}
}

func TestKeyCryptoMLKEMAlgorithms(t *testing.T) {
	kmsInstance := openTestKMS(t)
	defer kmsInstance.Close(t.Context())

	for _, algorithm := range []string{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"} {
		t.Run(algorithm, func(t *testing.T) {
			keyName := "openbao_test_" + strings.ToLower(strings.ReplaceAll(algorithm, "-", "_")) + "_key"
			cleanup := createMLKEMTestKey(t, keyName, algorithm)
			t.Cleanup(cleanup)
			key := getTestKMSKey(t, kmsInstance, keyName, "")
			assertMLKEMCipherRoundTrip(t, key)
		})
	}
}

func TestMLKEMEncapsulateDecapsulateAESGCMWithTSB(t *testing.T) {
	tsbClient := getTestClient(t)
	if tsbClient == nil {
		return
	}

	plaintext := []byte("OpenBao ML-KEM encapsulation and AES-GCM test")
	aad := []byte("OpenBao ML-KEM integration test context")
	for _, algorithm := range []string{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"} {
		t.Run(algorithm, func(t *testing.T) {
			keyName := "openbao_test_direct_" + strings.ToLower(strings.ReplaceAll(algorithm, "-", "_")) + "_key"
			cleanup := createMLKEMTestKey(t, keyName, algorithm)
			defer cleanup()

			key, err := tsbClient.GetKey(t.Context(), keyName, "")
			if err != nil {
				t.Fatalf("GetKey returned error: %v", err)
			}
			encapsulation, _, err := tsbClient.Encapsulate(t.Context(), key.PublicKey)
			if err != nil {
				t.Fatalf("Encapsulate returned error: %v", err)
			}
			decapsulation, _, err := tsbClient.Decapsulate(t.Context(), keyName, "", encapsulation.Ciphertext)
			if err != nil {
				t.Fatalf("Decapsulate returned error: %v", err)
			}
			if decapsulation.SharedSecret != encapsulation.SharedSecret {
				t.Fatal("Decapsulate returned a different shared secret")
			}

			encryptAEAD, err := mlKEMAEAD(encapsulation.SharedSecret, encapsulation.Ciphertext)
			if err != nil {
				t.Fatalf("create encryption AEAD: %v", err)
			}
			decryptAEAD, err := mlKEMAEAD(decapsulation.SharedSecret, encapsulation.Ciphertext)
			if err != nil {
				t.Fatalf("create decryption AEAD: %v", err)
			}
			nonce := make([]byte, encryptAEAD.NonceSize())
			if _, err := cryptorand.Read(nonce); err != nil {
				t.Fatalf("generate AES-GCM nonce: %v", err)
			}
			ciphertext := encryptAEAD.Seal(nil, nonce, plaintext, aad)
			decrypted, err := decryptAEAD.Open(nil, nonce, ciphertext, aad)
			if err != nil {
				t.Fatalf("AES-GCM decrypt returned error: %v", err)
			}
			if string(decrypted) != string(plaintext) {
				t.Fatalf("decrypted data = %q, want %q", decrypted, plaintext)
			}
		})
	}
}

func TestKeySignECAlgorithms(t *testing.T) {
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
}

func TestKeySignEDAlgorithms(t *testing.T) {
	ctx := t.Context()

	setupTestKeys(t)
	defer cleanupTestKeys(t)

	kmsInstance := openTestKMS(t)
	defer kmsInstance.Close(ctx)

	edKey := getTestKMSKey(t, kmsInstance, ED_KEY_NAME, "")
	for _, algorithm := range helpers.ED_SIGNATURE_LIST {
		t.Run("ED/"+algorithm, func(t *testing.T) {
			assertSignVerify(t, edKey, algorithm, crypto.Hash(0), false)
		})
	}
}

func TestKeySignRSAAlgorithms(t *testing.T) {
	ctx := t.Context()

	setupTestKeys(t)
	defer cleanupTestKeys(t)

	kmsInstance := openTestKMS(t)
	defer kmsInstance.Close(ctx)

	rsaKey := getTestKMSKey(t, kmsInstance, RSA_KEY_NAME, "")
	for _, tc := range []struct {
		algorithm  string
		signerOpts crypto.SignerOpts
		prehashed  bool
	}{
		{algorithm: "SHA256_WITH_RSA", signerOpts: crypto.SHA256},
		{algorithm: "SHA384_WITH_RSA", signerOpts: crypto.SHA384},
		{algorithm: "SHA512_WITH_RSA", signerOpts: crypto.SHA512},
		{algorithm: "NONE_WITH_RSA", signerOpts: crypto.Hash(0), prehashed: true},
		{algorithm: "NONESHA256_WITH_RSA", signerOpts: crypto.SHA256, prehashed: true},
		{algorithm: "NONESHA384_WITH_RSA", signerOpts: crypto.SHA384, prehashed: true},
		{algorithm: "NONESHA512_WITH_RSA", signerOpts: crypto.SHA512, prehashed: true},
		{algorithm: "SHA256_WITH_RSA_PSS", signerOpts: &rsa.PSSOptions{Hash: crypto.SHA256}},
		{algorithm: "SHA384_WITH_RSA_PSS", signerOpts: &rsa.PSSOptions{Hash: crypto.SHA384}},
		{algorithm: "SHA512_WITH_RSA_PSS", signerOpts: &rsa.PSSOptions{Hash: crypto.SHA512}},
		{algorithm: "NONE_WITH_RSA_PSS", signerOpts: &rsa.PSSOptions{Hash: crypto.Hash(0)}, prehashed: true},
		{algorithm: "NONESHA256_WITH_RSA_PSS", signerOpts: &rsa.PSSOptions{Hash: crypto.SHA256}, prehashed: true},
		{algorithm: "NONESHA384_WITH_RSA_PSS", signerOpts: &rsa.PSSOptions{Hash: crypto.SHA384}, prehashed: true},
		{algorithm: "NONESHA512_WITH_RSA_PSS", signerOpts: &rsa.PSSOptions{Hash: crypto.SHA512}, prehashed: true},
	} {
		t.Run("RSA/"+tc.algorithm, func(t *testing.T) {
			if !containsString(helpers.RSA_SIGNATURE_LIST, tc.algorithm) {
				t.Fatalf("%s is not present in RSA_SIGNATURE_LIST", tc.algorithm)
			}
			assertSignVerify(t, rsaKey, tc.algorithm, tc.signerOpts, tc.prehashed)
		})
	}
}

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
		Data: ciphertext,
		AAD:  aad,
	})
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("Decrypted data does not match original. Got %x, want %x", decrypted, plaintext)
	}
}

func assertMLKEMCipherRoundTrip(t *testing.T, key kms.Key) {
	t.Helper()

	plaintext := []byte("OpenBao Securosys ML-KEM cipher test")
	aad := []byte("ML-KEM AAD")
	ciphertext, err := key.Encrypt(t.Context(), &kms.CipherOptions{
		Data: plaintext,
		AAD:  aad,
	})
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	decrypted, err := key.Decrypt(t.Context(), &kms.CipherOptions{
		Data: ciphertext,
		AAD:  aad,
	})
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("Decrypted data does not match original. Got %x, want %x", decrypted, plaintext)
	}

	_, err = key.Decrypt(t.Context(), &kms.CipherOptions{
		Data: ciphertext,
		AAD:  []byte("invalid ML-KEM AAD"),
	})
	if err == nil {
		t.Fatal("Decrypt with invalid AAD succeeded")
	}

	tampered := bytes.Clone(ciphertext)
	tampered[len(tampered)-1] ^= 1
	if _, err := key.Decrypt(t.Context(), &kms.CipherOptions{Data: tampered, AAD: aad}); err == nil {
		t.Fatal("Decrypt with tampered ciphertext succeeded")
	}
}

func assertSignVerify(t *testing.T, key kms.Key, algorithm string, signerOpts crypto.SignerOpts, prehashed bool) {
	t.Helper()

	data := []byte("OpenBao Securosys signature test")
	signData, err := signerInput(data, signerOpts, prehashed)
	if err != nil {
		t.Fatalf("Failed to prepare signing input for %s: %v", algorithm, err)
	}

	signature, err := key.Sign(t.Context(), &kms.SignOptions{
		Data:       signData,
		Prehashed:  prehashed,
		SignerOpts: signerOpts,
	})
	if err != nil {
		t.Fatalf("Failed to sign with %s: %v", algorithm, err)
	}

	err = key.Verify(t.Context(), &kms.VerifyOptions{
		Signature:  signature,
		Data:       signData,
		Prehashed:  prehashed,
		SignerOpts: signerOpts,
	})
	if err != nil {
		t.Fatalf("Failed to verify with %s: %v", algorithm, err)
	}
}

func signerInput(data []byte, signerOpts crypto.SignerOpts, prehashed bool) ([]byte, error) {
	if !prehashed || signerOpts == nil || signerOpts.HashFunc() == crypto.Hash(0) {
		return data, nil
	}

	switch signerOpts.HashFunc() {
	case crypto.SHA256:
		digest := sha256.Sum256(data)
		return digest[:], nil
	case crypto.SHA384:
		digest := sha512.Sum384(data)
		return digest[:], nil
	case crypto.SHA512:
		digest := sha512.Sum512(data)
		return digest[:], nil
	default:
		return nil, fmt.Errorf("unsupported prehash function: %v", signerOpts.HashFunc())
	}
}

func cipherPlaintext(algorithm string) []byte {
	if algorithm == "RSA_NO_PADDING" {
		plaintext := make([]byte, 256)
		copy(plaintext[len(plaintext)-32:], []byte("openbao securosys rsa no padding"))
		return plaintext
	}
	return []byte("OpenBao Securosys cipher test!!!")
}

func testSecurosysKey(t *testing.T, hostURL string) *securosysKey {
	t.Helper()

	tsbClient, err := client.NewTSBClient(hostURL, client.AuthStruct{})
	if err != nil {
		t.Fatalf("failed to create test client: %v", err)
	}

	return &securosysKey{
		client: &client.SecurosysClient{TSBClient: tsbClient},
	}
}
