// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package nhncloudskm

import (
	"context"
	"os"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNHNCloudSKM_Acceptance(t *testing.T) {
	// Skip if not running acceptance tests
	if os.Getenv("NHNCLOUD_SKM_ACCEPTANCE_TESTS") == "" {
		t.Skip("Skipping NHN Cloud SKM acceptance tests. Set NHNCLOUD_SKM_ACCEPTANCE_TESTS=1 to run.")
	}

	wrapper := TestWrapper_WithEnv(t)

	// Run basic functionality tests
	t.Run("Basic", func(t *testing.T) {
		TestWrapper_Basic(t, wrapper)
	})

	t.Run("EncryptDecrypt", func(t *testing.T) {
		TestWrapper_EncryptDecrypt(t, wrapper)
	})

	t.Run("EmptyPlaintext", func(t *testing.T) {
		TestWrapper_EmptyPlaintext(t, wrapper)
	})

	t.Run("LargePlaintext", func(t *testing.T) {
		TestWrapper_LargePlaintext(t, wrapper)
	})

	t.Run("KeyRotation", func(t *testing.T) {
		TestWrapper_KeyRotation(t, wrapper)
	})
}

func TestNHNCloudSKM_SetConfig_Acceptance(t *testing.T) {
	// Skip if not running acceptance tests
	if os.Getenv("NHNCLOUD_SKM_ACCEPTANCE_TESTS") == "" {
		t.Skip("Skipping NHN Cloud SKM acceptance tests. Set NHNCLOUD_SKM_ACCEPTANCE_TESTS=1 to run.")
	}

	wrapper := NewWrapper()

	// Test configuration with environment variables
	_, err := wrapper.SetConfig(context.Background())
	require.NoError(t, err)

	// Verify configuration was loaded
	assert.NotEmpty(t, wrapper.endpoint)
	assert.NotEmpty(t, wrapper.appKey)
	assert.NotEmpty(t, wrapper.keyID)
	assert.NotEmpty(t, wrapper.userAccessKeyID)
	assert.NotEmpty(t, wrapper.userSecretAccessKey)
	// MAC address is optional
}

func TestNHNCloudSKM_SetConfig_WithConfigMap_Acceptance(t *testing.T) {
	// Skip if not running acceptance tests
	if os.Getenv("NHNCLOUD_SKM_ACCEPTANCE_TESTS") == "" {
		t.Skip("Skipping NHN Cloud SKM acceptance tests. Set NHNCLOUD_SKM_ACCEPTANCE_TESTS=1 to run.")
	}

	wrapper := NewWrapper()

	// Get values from environment for testing
	configMap := map[string]string{
		"endpoint":               os.Getenv(EnvNHNCloudSKMEndpoint),
		"app_key":                os.Getenv(EnvNHNCloudSKMAppKey),
		"key_id":                 os.Getenv(EnvNHNCloudSKMKeyID),
		"user_access_key_id":     os.Getenv(EnvNHNCloudSKMUserAccessKeyID),
		"user_secret_access_key": os.Getenv(EnvNHNCloudSKMUserSecretAccessKey),
		"mac_address":            os.Getenv(EnvNHNCloudSKMMACAddress),
	}

	_, err := wrapper.SetConfig(context.Background(), wrapping.WithConfigMap(configMap))
	require.NoError(t, err)

	// Verify configuration was set
	assert.Equal(t, configMap["endpoint"], wrapper.endpoint)
	assert.Equal(t, configMap["app_key"], wrapper.appKey)
	assert.Equal(t, configMap["key_id"], wrapper.keyID)
	assert.Equal(t, configMap["user_access_key_id"], wrapper.userAccessKeyID)
	assert.Equal(t, configMap["user_secret_access_key"], wrapper.userSecretAccessKey)
	assert.Equal(t, configMap["mac_address"], wrapper.macAddress)
}

func TestNHNCloudSKM_SetConfig_WithOptions_Acceptance(t *testing.T) {
	// Skip if not running acceptance tests
	if os.Getenv("NHNCLOUD_SKM_ACCEPTANCE_TESTS") == "" {
		t.Skip("Skipping NHN Cloud SKM acceptance tests. Set NHNCLOUD_SKM_ACCEPTANCE_TESTS=1 to run.")
	}

	wrapper := NewWrapper()

	// Get values from environment for testing
	endpoint := os.Getenv(EnvNHNCloudSKMEndpoint)
	appKey := os.Getenv(EnvNHNCloudSKMAppKey)
	keyID := os.Getenv(EnvNHNCloudSKMKeyID)
	accessKeyID := os.Getenv(EnvNHNCloudSKMUserAccessKeyID)
	secretKey := os.Getenv(EnvNHNCloudSKMUserSecretAccessKey)
	macAddr := os.Getenv(EnvNHNCloudSKMMACAddress)

	_, err := wrapper.SetConfig(context.Background(),
		WithEndpoint(endpoint),
		WithAppKey(appKey),
		wrapping.WithKeyId(keyID),
		WithUserAccessKeyID(accessKeyID),
		WithUserSecretAccessKey(secretKey),
		WithMACAddress(macAddr),
	)
	require.NoError(t, err)

	// Verify configuration was set
	assert.Equal(t, endpoint, wrapper.endpoint)
	assert.Equal(t, appKey, wrapper.appKey)
	assert.Equal(t, keyID, wrapper.keyID)
	assert.Equal(t, accessKeyID, wrapper.userAccessKeyID)
	assert.Equal(t, secretKey, wrapper.userSecretAccessKey)
	assert.Equal(t, macAddr, wrapper.macAddress)
}

func TestNHNCloudSKM_RealEncryption_Acceptance(t *testing.T) {
	// Skip if not running acceptance tests
	if os.Getenv("NHNCLOUD_SKM_ACCEPTANCE_TESTS") == "" {
		t.Skip("Skipping NHN Cloud SKM acceptance tests. Set NHNCLOUD_SKM_ACCEPTANCE_TESTS=1 to run.")
	}

	wrapper := TestWrapper_WithEnv(t)
	ctx := context.Background()

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "simple text",
			plaintext: []byte("hello world"),
		},
		{
			name:      "json data",
			plaintext: []byte(`{"key": "value", "number": 42, "array": [1,2,3]}`),
		},
		{
			name:      "binary data",
			plaintext: []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC},
		},
		{
			name:      "empty string",
			plaintext: []byte(""),
		},
		{
			name:      "unicode text",
			plaintext: []byte("안녕하세요 Hello 🌍"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Skip empty plaintext as it's expected to fail
			if len(tc.plaintext) == 0 {
				_, err := wrapper.Encrypt(ctx, tc.plaintext)
				assert.Error(t, err, "empty plaintext should fail")
				return
			}

			// Encrypt
			blobInfo, err := wrapper.Encrypt(ctx, tc.plaintext)
			require.NoError(t, err, "encryption should succeed")
			require.NotNil(t, blobInfo, "blob info should not be nil")
			require.NotEmpty(t, blobInfo.Ciphertext, "ciphertext should not be empty")
			require.NotNil(t, blobInfo.KeyInfo, "key info should not be nil")
			require.NotEmpty(t, blobInfo.KeyInfo.KeyId, "key ID should not be empty")

			// Decrypt
			decrypted, err := wrapper.Decrypt(ctx, blobInfo)
			require.NoError(t, err, "decryption should succeed")
			assert.Equal(t, tc.plaintext, decrypted, "decrypted data should match original")
		})
	}
}

func TestNHNCloudSKM_ErrorHandling_Acceptance(t *testing.T) {
	// Skip if not running acceptance tests
	if os.Getenv("NHNCLOUD_SKM_ACCEPTANCE_TESTS") == "" {
		t.Skip("Skipping NHN Cloud SKM acceptance tests. Set NHNCLOUD_SKM_ACCEPTANCE_TESTS=1 to run.")
	}

	ctx := context.Background()
	plaintext := []byte("test data")

	t.Run("invalid credentials", func(t *testing.T) {
		wrapper := NewWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"endpoint":               "https://api-keymanager.nhncloudservice.com",
			"app_key":                "invalid-app-key",
			"key_id":                 "invalid-key-id",
			"user_access_key_id":     "invalid-access-key",
			"user_secret_access_key": "invalid-secret-key",
		}))
		require.NoError(t, err)

		// Encrypt should fail with authentication error
		_, err = wrapper.Encrypt(ctx, plaintext)
		assert.Error(t, err, "encryption with invalid credentials should fail")
	})

	t.Run("invalid endpoint", func(t *testing.T) {
		wrapper := NewWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"endpoint":               "https://invalid-endpoint.example.com",
			"app_key":                "test-app-key",
			"key_id":                 "test-key-id",
			"user_access_key_id":     "test-access-key",
			"user_secret_access_key": "test-secret-key",
		}))
		require.NoError(t, err)

		// Encrypt should fail with network error
		_, err = wrapper.Encrypt(ctx, plaintext)
		assert.Error(t, err, "encryption with invalid endpoint should fail")
	})
}
