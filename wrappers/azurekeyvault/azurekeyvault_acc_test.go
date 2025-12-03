// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azurekeyvault

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"math/big"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/Azure/go-autorest/autorest/azure"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

func TestAzureKeyVault_SetConfig(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	s := NewWrapper()
	tenantID := os.Getenv("AZURE_TENANT_ID")
	os.Unsetenv("AZURE_TENANT_ID")

	// Attempt to set config, expect failure due to missing config
	_, err := s.SetConfig(context.Background())
	if err == nil {
		t.Fatal("expected error when Azure Key Vault config values are not provided")
	}

	os.Setenv("AZURE_TENANT_ID", tenantID)

	_, err = s.SetConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

func TestMapAuthMethod(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected authenticationMethod
	}{
		{"Empty String", "", Automatic},
		{"Managed Identity", "managed_identity", ManagedIdentityCredential},
		{"Client Secret", "client_secret", ClientSecretCredential},
		{"Workload Identity", "workload_identity", WorkloadIdentityCredential},
		{"Certificate", "certificate", CertificateCredential},
		{"Environment", "environment", EnvironmentCredential},
		{"Default", "default", DefaultAzureCredential},
		{"Invalid Input", "invalid_input", Automatic},
		{"Mixed Case Input", "Managed_Identity", ManagedIdentityCredential},
		{"Leading/Tailing Whitespace", " client_secret ", Automatic},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapAuthMethod(tt.input)
			if result != tt.expected {
				t.Errorf("mapAuthMethod(%q) = %v; want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestAzureKeyVault_IgnoreEnv(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	expectedErr := `error fetching Azure Key Vault wrapper key information: Get "https://a-vault-name.a-resource/keys/a-key-name/?api-version=7.4": dial tcp: lookup a-vault-name.a-resource: no such host`

	s := NewWrapper()

	// Setup environment values to ignore for the following values
	for _, envVar := range []string{
		"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
		"AZURE_ENVIRONMENT", "AZURE_AD_RESOURCE", EnvAzureKeyVaultWrapperVaultName,
		EnvVaultAzureKeyVaultVaultName, EnvAzureKeyVaultWrapperKeyName, EnvVaultAzureKeyVaultKeyName,
	} {
		oldVal := os.Getenv(envVar)
		os.Setenv(envVar, "envValue")
		defer os.Setenv(envVar, oldVal)
	}
	config := map[string]string{
		"disallow_env_vars": "true",
		"tenant_id":         "a-tenant-id",
		"client_id":         "a-client-id",
		"client_secret":     "a-client-secret",
		"environment":       azure.PublicCloud.Name,
		"resource":          "a-resource",
		"vault_name":        "a-vault-name",
		"key_name":          "a-key-name",
		"auth_method":       "managed_identity",
		"cert_path":         "/cert/someCert.pem",
		"cert_password":     "somePassword",
	}
	_, err := s.SetConfig(context.Background(), wrapping.WithConfigMap(config))
	require.Equal(t, expectedErr, err.Error())
	require.Equal(t, config["tenant_id"], s.tenantID)
	require.Equal(t, config["client_id"], s.clientID)
	require.Equal(t, config["client_secret"], s.clientSecret)
	require.Equal(t, config["environment"], s.environment.Name)
	require.Equal(t, "https://"+config["resource"]+"/", s.resource)
	require.Equal(t, config["vault_name"], s.vaultName)
	require.Equal(t, config["key_name"], s.keyName)
	require.Equal(t, mapAuthMethod(config["auth_method"]), s.authMethod)
	require.Equal(t, config["cert_path"], s.certPath)
	require.Equal(t, config["cert_password"], s.certPass)
}

func TestAzureKeyVault_Lifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	s := NewWrapper()
	_, err := s.SetConfig(context.Background())
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	// Test Encrypt and Decrypt calls
	input := []byte("foo")
	swi, err := s.Encrypt(context.Background(), input, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	pt, err := s.Decrypt(context.Background(), swi, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
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
		err := os.Remove(name)
		if err != nil {
			t.Fatal(err)
		}
	}(certFile.Name())

	// Write the certificate to the file
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	require.NoError(t, err)

	// Write the private key to the file
	err = pem.Encode(certFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	require.NoError(t, err)

	err = certFile.Close()
	require.NoError(t, err)

	// Create a wrapper and test the getCredential method
	v := &Wrapper{
		tenantID: "test-tenant-id",
		clientID: "test-client-id",
		certPath: certFile.Name(),
	}

	cred, err := v.getCredential(CertificateCredential)
	require.NoError(t, err)
	require.NotNil(t, cred)
}

func TestCreds_getCertificate(t *testing.T) {
	ctx := context.Background()

	clientID := os.Getenv("TEST_AZURE_CLIENT_ID")
	tenantID := os.Getenv("TEST_AZURE_TENANT_ID")
	vaultName := os.Getenv("TEST_VAULT_NAME")
	keyName := os.Getenv("TEST_KEY_NAME")
	plaintextInput := []byte("foo")
	expectedOutput := "foo"

	config := map[string]string{
		"disallow_env_vars": "true",
		"environment":       azure.PublicCloud.Name,
		"resource":          "vault.azure.net",
		"vault_name":        vaultName,
		"key_name":          keyName,
		"auth_method":       "certificate",
		"cert_path":         "test-data/azure-app.crt",
		"client_id":         clientID,
		"tenant_id":         tenantID,
	}

	wrapper := NewWrapper()

	setConfig := func() {
		t.Helper()
		t.Log("--- SetConfig ---")
		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(config))
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
			result := wrapper.getManagedIdentityID()

			if result != tc.expectedResult {
				t.Errorf("unexpected result: got %v, want %v", result, tc.expectedResult)
			}
		})
	}
}
