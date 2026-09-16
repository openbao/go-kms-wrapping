// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openbao/go-kms-wrapping/v2/kms"
	client "github.com/securosys-com/tsb-client-go"
	"github.com/securosys-com/tsb-client-go/helpers"
	"github.com/stretchr/testify/require"
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
			require.NoError(t, err, "mapRSAAlgorithm returned error")
			require.Equal(t, tc.want, got)
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
			_, err := mapRSAAlgorithm(tc.hash, false, tc.pss)
			require.Error(t, err)
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
			require.NoError(t, err, "mapSignAlgorithmFromOpts returned error")
			require.Equal(t, tc.want, got)
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
			require.Equal(t, tc.want, signatureTypeForPublicKey(tc.pub))
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
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
			require.Contains(t, helpers.EC_SIGNATURE_LIST, tc.algorithm)
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
			require.Contains(t, helpers.RSA_SIGNATURE_LIST, tc.algorithm)
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
	require.NoError(t, err, "Failed to encrypt")

	decrypted, err := key.Decrypt(t.Context(), &kms.CipherOptions{
		Data: ciphertext,
		AAD:  aad,
	})
	require.NoError(t, err, "Failed to decrypt")
	require.Equal(t, plaintext, decrypted)
}

func assertMLKEMCipherRoundTrip(t *testing.T, key kms.Key) {
	t.Helper()

	plaintext := []byte("OpenBao Securosys ML-KEM cipher test")
	aad := []byte("ML-KEM AAD")
	ciphertext, err := key.Encrypt(t.Context(), &kms.CipherOptions{
		Data: plaintext,
		AAD:  aad,
	})
	require.NoError(t, err, "Failed to encrypt")

	decrypted, err := key.Decrypt(t.Context(), &kms.CipherOptions{
		Data: ciphertext,
		AAD:  aad,
	})
	require.NoError(t, err, "Failed to decrypt")
	require.Equal(t, plaintext, decrypted)

	_, err = key.Decrypt(t.Context(), &kms.CipherOptions{
		Data: ciphertext,
		AAD:  []byte("invalid ML-KEM AAD"),
	})
	require.Error(t, err, "Decrypt with invalid AAD succeeded")

	tampered := bytes.Clone(ciphertext)
	tampered[len(tampered)-1] ^= 1
	_, err = key.Decrypt(t.Context(), &kms.CipherOptions{Data: tampered, AAD: aad})
	require.Error(t, err, "Decrypt with tampered ciphertext succeeded")
}

func assertSignVerify(t *testing.T, key kms.Key, algorithm string, signerOpts crypto.SignerOpts, prehashed bool) {
	t.Helper()

	data := []byte("OpenBao Securosys signature test")
	signData, err := signerInput(data, signerOpts, prehashed)
	require.NoError(t, err, "Failed to prepare signing input for %s", algorithm)

	signature, err := key.Sign(t.Context(), &kms.SignOptions{
		Data:       signData,
		Prehashed:  prehashed,
		SignerOpts: signerOpts,
	})
	require.NoError(t, err, "Failed to sign with %s", algorithm)

	err = key.Verify(t.Context(), &kms.VerifyOptions{
		Signature:  signature,
		Data:       signData,
		Prehashed:  prehashed,
		SignerOpts: signerOpts,
	})
	require.NoError(t, err, "Failed to verify with %s", algorithm)
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

const mlDSA44KeyName = "openbao_test_ml_dsa_44_key"

func TestKMSPostQuantumSignatureAlgorithms(t *testing.T) {
	key := getTestMLDSAKey(t)
	assertSignVerify(t, key, "ML_DSA", crypto.Hash(0), false)
}

func TestNativeGoX509CertificateUsesKMSMLDSASign(t *testing.T) {
	key := getTestMLDSAKey(t)
	assertMLDSAX509Certificate(t, key)
}

func getTestMLDSAKey(t *testing.T) kms.Key {
	t.Helper()

	ctx := t.Context()
	tsbClient := getTestClient(t)
	if tsbClient == nil {
		return nil
	}

	attrs := map[string]bool{
		"extractable": false,
		"token":       true,
		"sign":        true,
		"verify":      true,
		"encrypt":     false,
		"decrypt":     false,
		"wrap":        false,
		"unwrap":      false,
		"derive":      false,
		"destroyable": true,
	}

	_, err := tsbClient.CreateOrUpdateKey(ctx, mlDSA44KeyName, "", attrs, "ML-DSA-44", 0, nil, "", false)
	if err != nil {
		skipIfTSBAuthError(t, err)
		t.Logf("Key creation warning for %s: %v", mlDSA44KeyName, err)
	}
	t.Cleanup(func() {
		if err := tsbClient.RemoveKey(context.Background(), mlDSA44KeyName); err != nil {
			t.Logf("Key cleanup warning for %s: %v", mlDSA44KeyName, err)
		}
	})

	kmsInstance := openTestKMS(t)
	t.Cleanup(func() {
		if err := kmsInstance.Close(context.Background()); err != nil {
			t.Logf("KMS cleanup warning: %v", err)
		}
	})

	return getTestKMSKey(t, kmsInstance, mlDSA44KeyName, "")
}

func assertMLDSAX509Certificate(t *testing.T, key kms.Key) {
	t.Helper()

	signer, err := kms.NewSigner(t.Context(), key)
	require.NoError(t, err, "failed to create KMS signer")

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: mlDSA44KeyName,
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	require.NoError(t, err, "failed to create ML-DSA certificate")

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err, "failed to parse ML-DSA certificate")
	require.IsType(t, (*mldsa.PublicKey)(nil), cert.PublicKey)
	require.NoError(t, cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature), "failed to verify ML-DSA certificate signature")
}

func skipIfTSBAuthError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if strings.Contains(err.Error(), "JWT signature is invalid") ||
		strings.Contains(err.Error(), "status: 401") {
		t.Skipf("TSB credentials are not accepted: %v", err)
	}
}

func testSecurosysKey(t *testing.T, hostURL string) *securosysKey {
	t.Helper()

	tsbClient, err := client.NewTSBClient(hostURL, client.AuthStruct{})
	require.NoError(t, err, "failed to create test client")

	return &securosysKey{
		client: &client.SecurosysClient{TSBClient: tsbClient},
	}
}
