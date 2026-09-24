// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package ovhcloudkms

import (
	"bytes"
	"os"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

// This test executes real calls. The calls themselves should be free,
// but the OKMS key used is generally not free.
//
// To run this test, the following env variables need to be set or provided
// with `withConfigMap` wrapper option:
//   - OVHCLOUDKMS_KEY_ID / withConfigMap["key_id"]
//   - OVHCLOUDKMS_ENDPOINT / withConfigMap["endpoint"]
//   - OVHCLOUDKMS_ID / withConfigMap["kms_id"]
//
// You can choose the auth type by setting corresponding env variables
// or providing them with `withConfigMap` wrapper option.
// token:
//   - OVHCLOUDKMS_TOKEN / withConfigMap["token"]
//
// or mTLS:
//   - OVHCLOUDKMS_CLIENT_CERT / withConfigMap["client_cert_bytes"]
//   - OVHCLOUDKMS_CLIENT_KEY / withConfigMap["client_key_bytes"]
//
// optionally:
//   - OVHCLOUDKMS_CA_CERT / withConfigMap["ca_cert_bytes"]
func TestAccWrapper(t *testing.T) {
	roundtrip := func(t *testing.T, ow *Wrapper) {
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

	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	keyId := os.Getenv(EnvOkmsKeyId)
	if keyId == "" {
		t.SkipNow()
	}

	t.Run("Certificate authorization with env vars", func(t *testing.T) {
		// Need to unset the token otherwise we fail due to ambiguous authentication setup.
		token := os.Getenv(EnvOkmsToken)
		os.Unsetenv(EnvOkmsToken)
		defer os.Setenv(EnvOkmsToken, token)

		tempDir := t.TempDir()
		clientCertFile, err := os.CreateTemp(tempDir, "client-cert.pem")
		require.NoError(t, err)

		clientCert := os.Getenv("OVHCLOUDKMS_CERT_CLIENT_CERT")
		_, err = clientCertFile.Write([]byte(clientCert))
		clientCertFile.Close()
		t.Setenv(EnvOkmsClientCert, clientCertFile.Name())

		clientKeyFile, err := os.CreateTemp(tempDir, "client-key.pem")
		require.NoError(t, err)
		clientKey := os.Getenv("OVHCLOUDKMS_CERT_CLIENT_KEY")
		_, err = clientKeyFile.Write([]byte(clientKey))
		t.Setenv(EnvOkmsClientKey, clientKeyFile.Name())

		ow := NewWrapper()
		_, err = ow.SetConfig(t.Context())
		require.NoError(t, err)
		roundtrip(t, ow)
	})

	t.Run("Certificate authorization with disallow env vars", func(t *testing.T) {
		configMap := map[string]string{
			"key_id":            keyId,
			"endpoint":          os.Getenv(EnvOkmsEndpoint),
			"kms_id":            os.Getenv(EnvOkmsId),
			"client_cert_bytes": os.Getenv("OVHCLOUDKMS_CERT_CLIENT_CERT"),
			"client_key_bytes":  os.Getenv("OVHCLOUDKMS_CERT_CLIENT_KEY"),
		}
		ow := NewWrapper()
		_, err := ow.SetConfig(t.Context(), wrapping.WithConfigMap(configMap), wrapping.WithDisallowEnvVars(true))
		require.NoError(t, err)
		roundtrip(t, ow)
	})

	t.Run("Credentials authorization with env vars", func(t *testing.T) {
		ow := NewWrapper()
		_, err := ow.SetConfig(t.Context())
		require.NoError(t, err)
		roundtrip(t, ow)
	})

	t.Run("Credentials authorization with disallow env vars", func(t *testing.T) {
		configMap := map[string]string{
			"key_id":   keyId,
			"endpoint": os.Getenv(EnvOkmsEndpoint),
			"kms_id":   os.Getenv(EnvOkmsId),
			"token":    os.Getenv(EnvOkmsToken),
		}
		ow := NewWrapper()
		_, err := ow.SetConfig(t.Context(), wrapping.WithConfigMap(configMap), wrapping.WithDisallowEnvVars(true))
		require.NoError(t, err)
		roundtrip(t, ow)
	})
}
