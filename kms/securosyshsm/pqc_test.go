// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0

//go:build go1.27

package securosyshsm

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openbao/go-kms-wrapping/v2/kms"
)

const mlDSA44KeyName = "openbao_test_ml_dsa_44_key"

func init() {
	loadPQCEnvFile()
}

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

	key := getTestKMSKey(t, kmsInstance, mlDSA44KeyName, "")
	return key
}

func assertMLDSAX509Certificate(t *testing.T, key kms.Key) {
	t.Helper()

	signer, err := kms.NewSigner(t.Context(), key)
	if err != nil {
		t.Fatalf("failed to create KMS signer: %v", err)
	}

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
	if err != nil {
		t.Fatalf("failed to create ML-DSA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse ML-DSA certificate: %v", err)
	}
	if _, ok := cert.PublicKey.(*mldsa.PublicKey); !ok {
		t.Fatalf("certificate public key = %T, want *mldsa.PublicKey", cert.PublicKey)
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Fatalf("failed to verify ML-DSA certificate signature: %v", err)
	}
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

func loadPQCEnvFile() {
	for _, path := range []string{".env", "../.env", "../../.env"} {
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			key = strings.TrimSpace(key)
			value = strings.Trim(strings.TrimSpace(value), `"'`)
			if key != "" && os.Getenv(key) == "" {
				_ = os.Setenv(key, value)
			}
		}
		return
	}
}
