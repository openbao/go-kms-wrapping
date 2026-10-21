// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azurekeyvault

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

func TestAzureKeyVault_SetConfig(t *testing.T) {
	s := NewWrapper()
	os.Unsetenv("AZURE_TENANT_ID")

	// Attempt to set config, expect failure due to missing config
	_, err := s.SetConfig(t.Context())
	require.Error(t, err)

	t.Setenv("AZURE_TENANT_ID", "tenant_id")
	t.Setenv(EnvVaultAzureKeyVaultVaultName, "vault_name")
	t.Setenv(EnvVaultAzureKeyVaultKeyName, "key_name")

	_, err = s.SetConfig(t.Context(), wrapping.WithConfigMap(map[string]string{
		"key_not_required": "true",
	}))
	require.NoError(t, err)
}

func TestMapAuthMethod(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wrapper  *Wrapper
		expected authenticationMethod
	}{
		{
			"Empty String",
			"",
			&Wrapper{},
			DefaultAzureCredential,
		},
		{
			"Managed Identity",
			"managed_identity",
			&Wrapper{},
			ManagedIdentityCredential,
		},
		{
			"Client Secret",
			"client_secret",
			&Wrapper{},
			ClientSecretCredential,
		},
		{
			"Workload Identity",
			"workload_identity",
			&Wrapper{},
			WorkloadIdentityCredential,
		},
		{
			"Certificate",
			"certificate",
			&Wrapper{},
			CertificateCredential,
		},
		{
			"Environment",
			"environment",
			&Wrapper{},
			EnvironmentCredential,
		},
		{
			"Default",
			"default",
			&Wrapper{},
			DefaultAzureCredential,
		},
		{
			"Invalid Input",
			"invalid_input",
			&Wrapper{},
			DefaultAzureCredential,
		},
		{
			"Mixed Case Input",
			"Managed_Identity",
			&Wrapper{},
			ManagedIdentityCredential,
		},
		{
			"Leading/Tailing Whitespace",
			" client_secret ",
			&Wrapper{},
			DefaultAzureCredential,
		},
		{
			"No specification with wrapper properties set to client_secret",
			"",
			&Wrapper{tenantID: "tenant", clientID: "client", clientSecret: "secret"},
			ClientSecretCredential,
		},
		{
			"No specification with wrapper properties set to certificate",
			"",
			&Wrapper{certPath: "./somepath/cert.pem"},
			CertificateCredential,
		},
		{
			"No specification with wrapper properties set to managed identity",
			"",
			&Wrapper{clientID: "client"},
			ManagedIdentityCredential,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.wrapper.configureAuthMethod(tt.input)
			require.Equal(t, tt.expected, tt.wrapper.authMethod)
		})
	}
}

func TestAzureKeyVault_IgnoreEnv(t *testing.T) {
	config := map[string]string{
		"tenant_id":        "a-tenant-id",
		"client_id":        "a-client-id",
		"client_secret":    "a-client-secret",
		"environment":      "azurecloud",
		"resource":         "a-resource",
		"vault_name":       "a-vault-name",
		"key_name":         "a-key-name",
		"auth_method":      "client_secret",
		"cert_path":        "/cert/someCert.pem",
		"cert_password":    "somePassword",
		"key_not_required": "true",
	}
	s := NewWrapper()
	_, err := s.SetConfig(t.Context(),
		wrapping.WithConfigMap(config),
		wrapping.WithDisallowEnvVars(true))
	require.NoError(t, err)
	require.Equal(t, config["tenant_id"], s.tenantID)
	require.Equal(t, config["client_id"], s.clientID)
	require.Equal(t, config["client_secret"], s.clientSecret)
	require.Equal(t, config["environment"], s.environment)
	require.Equal(t, "https://"+config["resource"]+"/", s.resource)
	require.Equal(t, config["vault_name"], s.vaultName)
	require.Equal(t, config["key_name"], s.keyName)
	require.Equal(t, config["cert_path"], s.certPath)
	require.Equal(t, config["cert_password"], s.certPassword)
	require.Equal(t, ClientSecretCredential, s.authMethod)
}

func TestAzureKeyVault_Lifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	s := NewWrapper()
	_, err := s.SetConfig(t.Context())
	require.NoError(t, err)

	// Test Encrypt and Decrypt calls
	input := []byte("foo")
	swi, err := s.Encrypt(t.Context(), input, nil)
	require.NoError(t, err)

	pt, err := s.Decrypt(t.Context(), swi, nil)
	require.NoError(t, err)
	require.Equal(t, input, pt)
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

func TestCreds_getCertificate(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	ctx := t.Context()

	clientID := os.Getenv("TEST_AZURE_CLIENT_ID")
	tenantID := os.Getenv("TEST_AZURE_TENANT_ID")
	vaultName := os.Getenv("TEST_VAULT_NAME")
	keyName := os.Getenv("TEST_KEY_NAME")
	plaintextInput := []byte("foo")
	expectedOutput := "foo"

	config := map[string]string{
		"environment": "azurecloud",
		"resource":    "vault.azure.net",
		"vault_name":  vaultName,
		"key_name":    keyName,
		"auth_method": "certificate",
		"cert_path":   "test-data/azure-app.crt",
		"client_id":   clientID,
		"tenant_id":   tenantID,
	}

	wrapper := NewWrapper()

	setConfig := func() {
		t.Helper()
		t.Log("--- SetConfig ---")
		_, err := wrapper.SetConfig(ctx,
			wrapping.WithConfigMap(config),
			wrapping.WithDisallowEnvVars(true))
		require.NoError(t, err)
	}

	encrypt := func(data []byte) *wrapping.BlobInfo {
		t.Helper()
		t.Log("--- Encrypt ---")
		blobInfo, err := wrapper.Encrypt(ctx, data)
		require.NoError(t, err)
		return blobInfo
	}

	decrypt := func(blobInfo *wrapping.BlobInfo) []byte {
		t.Helper()
		t.Log("--- Decrypt ---")
		plaintext, err := wrapper.Decrypt(ctx, blobInfo)
		require.NoError(t, err)
		return plaintext
	}

	setConfig()
	blobInfo := encrypt(plaintextInput)
	plaintext := decrypt(blobInfo)
	t.Log(string(plaintext))

	require.Equal(t, expectedOutput, string(plaintext))
}

func TestWrapper_getManagedIdentityID(t *testing.T) {
	tests := []struct {
		name           string
		managedIdKind  managedIdentityKind
		clientID       string
		resourceID     string
		expectedResult azidentity.ManagedIDKind
	}{
		{
			name:           "ClientID case",
			managedIdKind:  clientId,
			clientID:       "test-client-id",
			resourceID:     "test-resource-id",
			expectedResult: azidentity.ClientID("test-client-id"),
		},
		{
			name:           "ResourceID case",
			managedIdKind:  resourceId,
			clientID:       "test-client-id",
			resourceID:     "test-resource-id",
			expectedResult: azidentity.ResourceID("test-resource-id"),
		},
		{
			name:           "Undefined managed ID kind case with ClientID",
			managedIdKind:  undefined,
			clientID:       "fallback-client-id",
			resourceID:     "ignored-resource-id",
			expectedResult: azidentity.ClientID("fallback-client-id"),
		},
		{
			name:           "Default case with unknown managed ID kind",
			managedIdKind:  99, // Unknown value
			clientID:       "test-client-id",
			resourceID:     "test-resource-id",
			expectedResult: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wrapper := &Wrapper{
				clientID:      tc.clientID,
				resourceID:    tc.resourceID,
				managedIdKind: tc.managedIdKind,
			}
			require.Equal(t, tc.expectedResult, wrapper.getManagedIdentityID())
		})
	}
}
