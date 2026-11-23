// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azurekeyvault

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"maps"
	"math/big"
	"os"
	"testing"
	"time"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

func roundtrip(t *testing.T, ow *Wrapper) {
	t.Helper()

	input := []byte("foobar")
	ciphertext0, err := ow.Encrypt(t.Context(), input)
	require.NoError(t, err)
	require.NotEqual(t, ciphertext0, input)

	ciphertext1, err := ow.Encrypt(t.Context(), input)
	require.NoError(t, err)
	require.NotEqual(t, ciphertext1, input)
	require.NotEqual(t, ciphertext1, ciphertext0)

	plaintext0, err := ow.Decrypt(t.Context(), ciphertext0)
	require.NoError(t, err)
	require.Equal(t, input, plaintext0)

	plaintext1, err := ow.Decrypt(t.Context(), ciphertext1)
	require.NoError(t, err)
	require.Equal(t, input, plaintext1)

	corruptedCipher := &wrapping.BlobInfo{
		Ciphertext: bytes.Clone(ciphertext0.Ciphertext),
		Iv:         ciphertext0.Iv,
		KeyInfo:    ciphertext0.KeyInfo,
	}
	corruptedCipher.Ciphertext[0] ^= 0xff
	_, err = ow.Decrypt(t.Context(), corruptedCipher)
	require.Error(t, err)
}

func TestAccWrapper(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	baseConfig := map[string]string{
		"environment": "azurecloud",
		"vault_name":  os.Getenv(EnvAzureKeyVaultWrapperVaultName),
		"key_name":    os.Getenv(EnvAzureKeyVaultWrapperKeyName),
	}

	// Setup cert path.
	tempDir := t.TempDir()
	clientCertFile, err := os.CreateTemp(tempDir, "client-cert.pem")
	require.NoError(t, err)
	clientCert := os.Getenv("AZUREKEYVAULT_CERT_CLIENT_CERT")
	_, err = clientCertFile.Write([]byte(clientCert))
	clientCertFile.Close()
	t.Setenv(EnvVaultAzureKeyVaultCertificatePath, clientCertFile.Name())

	tests := []struct {
		name           string
		authMethod     string
		config         map[string]string
		disableEnvVars bool
	}{
		{
			name:       "client_secret without env vars",
			authMethod: "client_secret",
			config: map[string]string{
				"tenant_id":     os.Getenv("AZURE_TENANT_ID"),
				"client_id":     os.Getenv("AZURE_CLIENT_ID"),
				"client_secret": os.Getenv("AZURE_CLIENT_SECRET"),
			},
			disableEnvVars: true,
		},
		{
			name:       "client_secret with env vars",
			authMethod: "client_secret",
		},
		{
			name:       "certificate without env vars",
			authMethod: "certificate",
			config: map[string]string{
				"tenant_id":     os.Getenv("AZUREKEYVAULT_TENANT_ID"),
				"client_id":     os.Getenv("AZURE_CLIENT_ID"),
				"cert_bytes":    os.Getenv("AZUREKEYVAULT_CERT_CLIENT_CERT"),
				"cert_password": os.Getenv(EnvVaultAzureKeyVaultCertificatePassword),
			},
			disableEnvVars: true,
		},
		{
			name:       "certificate with env vars",
			authMethod: "certificate",
		},
		{
			name:       "environment",
			authMethod: "environment",
		},
		{
			name:       "managed_identity without env vars",
			authMethod: "managed_identity",
			config: map[string]string{
				"tenant_id":       os.Getenv("AZUREKEYVAULT_TENANT_ID"),
				"client_id":       os.Getenv("AZURE_CLIENT_ID"),
				"client_secret":   os.Getenv("AZURE_CLIENT_SECRET"),
				"managed_id_kind": "CLIENT_ID",
			},
			disableEnvVars: true,
		},
		{
			// TODO: managed_id_kind
			name:       "managed_identity with env vars",
			authMethod: "managed_identity",
		},
		// needs AZURE_FEDERATED_TOKEN_FILE env
		// {
		// 	name:       "workload_identity with env vars",
		// 	authMethod: "workload_identity",
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configMap := make(map[string]string, len(baseConfig)+len(tt.config))
			maps.Copy(configMap, baseConfig)
			maps.Copy(configMap, tt.config)
			configMap["auth_method"] = tt.authMethod
			configMap["key_not_required"] = "false"

			s := NewWrapper()
			opts := []wrapping.Option{wrapping.WithConfigMap(configMap), wrapping.WithDisallowEnvVars(tt.disableEnvVars)}

			_, err := s.SetConfig(t.Context(), opts...)
			require.NoError(t, err)

			roundtrip(t, s)
		})
	}
}

func TestWrapper_getCredential_CertificateCredential(t *testing.T) {
	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create a self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Create a temporary file to store the certificate and key
	certFile, err := os.CreateTemp("", "cert.pem")
	require.NoError(t, err)
	defer func(name string) {
		require.NoError(t, os.Remove(name))
	}(certFile.Name())

	// Write the certificate to the file
	require.NoError(t, pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))

	// Write the private key to the file
	require.NoError(t, pem.Encode(certFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}))
	require.NoError(t, certFile.Close())

	// Create a wrapper and test the getCredential method
	v := &Wrapper{
		tenantID:   "test-tenant-id",
		clientID:   "test-client-id",
		certPath:   certFile.Name(),
		authMethod: CertificateCredential,
	}

	cred, err := v.getCredential()
	require.NoError(t, err)
	require.NotNil(t, cred)
}
