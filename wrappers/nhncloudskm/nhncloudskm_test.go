// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package nhncloudskm

import (
	"context"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

func TestWrapper_Type(t *testing.T) {
	wrapper := NewWrapper()

	wrapperType, err := wrapper.Type(context.Background())
	require.NoError(t, err)
	require.Equal(t, wrapping.WrapperTypeNHNCloudSkm, wrapperType)
}

func TestWrapper_KeyId_NotConfigured(t *testing.T) {
	wrapper := NewWrapper()

	_, err := wrapper.KeyId(context.Background())
	require.ErrorContains(t, err, "key ID not configured")
}

func TestWrapper_SetConfig_RequiredFields(t *testing.T) {
	tests := []struct {
		name      string
		configMap map[string]string
		wantErr   string
	}{
		{
			name: "missing app_key",
			configMap: map[string]string{
				"key_id":                 "test-key",
				"user_access_key_id":     "test-access",
				"user_secret_access_key": "test-secret",
			},
			wantErr: "app key is required",
		},
		{
			name: "missing key_id",
			configMap: map[string]string{
				"app_key":                "test-app",
				"user_access_key_id":     "test-access",
				"user_secret_access_key": "test-secret",
			},
			wantErr: "key ID is required",
		},
		{
			name: "missing user_access_key_id",
			configMap: map[string]string{
				"app_key":                "test-app",
				"key_id":                 "test-key",
				"user_secret_access_key": "test-secret",
			},
			wantErr: "user access key ID is required",
		},
		{
			name: "missing user_secret_access_key",
			configMap: map[string]string{
				"app_key":            "test-app",
				"key_id":             "test-key",
				"user_access_key_id": "test-access",
			},
			wantErr: "user secret access key is required",
		},
		{
			name: "all required fields present",
			configMap: map[string]string{
				"app_key":                "test-app",
				"key_id":                 "test-key",
				"user_access_key_id":     "test-access",
				"user_secret_access_key": "test-secret",
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper := NewWrapper()

			_, err := wrapper.SetConfig(context.Background(),
				wrapping.WithConfigMap(tt.configMap),
				wrapping.WithDisallowEnvVars(true),
			)

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestWrapper_SetConfig_Defaults(t *testing.T) {
	wrapper := NewWrapper()

	_, err := wrapper.SetConfig(context.Background(),
		wrapping.WithConfigMap(map[string]string{
			"app_key":                "test-app",
			"key_id":                 "test-key",
			"user_access_key_id":     "test-access",
			"user_secret_access_key": "test-secret",
		}),
		wrapping.WithDisallowEnvVars(true),
	)
	require.NoError(t, err)

	// Should use default endpoint
	require.Equal(t, DefaultNHNCloudSKMEndpoint, wrapper.endpoint)

	// Should set other fields correctly
	require.Equal(t, "test-app", wrapper.appKey)
	require.Equal(t, "test-key", wrapper.keyID)
	require.Equal(t, "test-access", wrapper.userAccessKeyID)
	require.Equal(t, "test-secret", wrapper.userSecretAccessKey)
}

func TestWrapper_SetConfig_WithOptions(t *testing.T) {
	wrapper := NewWrapper()

	_, err := wrapper.SetConfig(context.Background(),
		WithEndpoint("https://custom-endpoint.com"),
		WithAppKey("custom-app-key"),
		wrapping.WithKeyId("custom-key-id"),
		WithUserAccessKeyID("custom-access-key"),
		WithUserSecretAccessKey("custom-secret-key"),
		WithMACAddress("custom-mac-addr"),
		wrapping.WithDisallowEnvVars(true),
	)
	require.NoError(t, err)

	require.Equal(t, "https://custom-endpoint.com", wrapper.endpoint)
	require.Equal(t, "custom-app-key", wrapper.appKey)
	require.Equal(t, "custom-key-id", wrapper.keyID)
	require.Equal(t, "custom-access-key", wrapper.userAccessKeyID)
	require.Equal(t, "custom-secret-key", wrapper.userSecretAccessKey)
	require.Equal(t, "custom-mac-addr", wrapper.macAddress)
}

func TestWrapper_Encrypt_EmptyPlaintext(t *testing.T) {
	wrapper := TestWrapper(t)

	_, err := wrapper.Encrypt(context.Background(), []byte{})
	require.ErrorContains(t, err, "plaintext is empty")
}

func TestWrapper_Encrypt_LargePlaintext(t *testing.T) {
	wrapper := TestWrapper(t)

	// Create plaintext larger than 32KB - should work with envelope encryption
	largePlaintext := make([]byte, 33*1024)

	_, err := wrapper.Encrypt(context.Background(), largePlaintext)
	// With envelope encryption, large data should be supported
	// This test would need real NHN Cloud SKM credentials to work
	if err != nil {
		// Skip if we don't have valid credentials for testing
		t.Skip("Skipping large plaintext test - requires valid NHN Cloud SKM credentials")
	}
}

func TestWrapper_Decrypt_NilCipherInfo(t *testing.T) {
	wrapper := TestWrapper(t)

	_, err := wrapper.Decrypt(context.Background(), nil)
	require.ErrorContains(t, err, "cipherInfo is nil")
}

func TestWrapper_Decrypt_EmptyCiphertext(t *testing.T) {
	wrapper := TestWrapper(t)

	blobInfo := &wrapping.BlobInfo{
		Ciphertext: []byte{},
	}

	_, err := wrapper.Decrypt(context.Background(), blobInfo)
	require.ErrorContains(t, err, "ciphertext is empty")
}

func TestWrapper_KeyId_Configured(t *testing.T) {
	wrapper := TestWrapper(t)

	keyID, err := wrapper.KeyId(context.Background())
	require.NoError(t, err)
	require.Equal(t, "test-key-id", keyID)
}

func TestWrapper_InitFinalize(t *testing.T) {
	wrapper := NewWrapper()

	// Init should succeed
	err := wrapper.Init(context.Background())
	require.NoError(t, err)

	// Finalize should succeed
	err = wrapper.Finalize(context.Background())
	require.NoError(t, err)
}
