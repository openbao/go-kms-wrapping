// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azurekeyvault

import (
	"os"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/Azure/go-autorest/autorest/azure"
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
		"environment":      azure.PublicCloud.Name,
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
	require.Equal(t, config["environment"], s.environment.Name)
	require.Equal(t, "https://"+config["resource"]+"/", s.resource)
	require.Equal(t, config["vault_name"], s.vaultName)
	require.Equal(t, config["key_name"], s.keyName)
	require.Equal(t, config["cert_path"], s.certPath)
	require.Equal(t, config["cert_password"], s.certPassword)
	require.Equal(t, ClientSecretCredential, s.authMethod)
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
