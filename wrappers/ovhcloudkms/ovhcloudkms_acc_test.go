// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package ovhcloudkms

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

// This test executes real calls. The calls themselves should be free,
// but the OKMS key used is generally not free.
//
// To run this test, the following env variables need to be set:
// (values of these envs can be propagated to the wrapper creation
// to simulate env-less creation mode, env keys are then paired with
// corresponding map keys `withConfigMap[key]`)
//   - OVHCLOUDKMS_KEY_ID / withConfigMap["key_id"]
//   - OVHCLOUDKMS_ENDPOINT / withConfigMap["endpoint"]
//   - OVHCLOUDKMS_ID / withConfigMap["kms_id"]
//
// You can choose the auth type by setting corresponding env variables.
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
	// unsetEnvs ensures that any env used for scaffolding the test won't leak
	// into actual wrapper creation logic.
	unsetEnvs := func(t *testing.T) {
		t.Helper()
		t.Setenv(EnvOkmsEndpoint, "")
		t.Setenv(EnvOkmsId, "")
		t.Setenv(EnvOkmsToken, "")
		t.Setenv("OVHCLOUDKMS_CERT_CLIENT_CERT", "")
		t.Setenv("OVHCLOUDKMS_CERT_CLIENT_KEY", "")
	}

	// roundtrip verifies the encryption/decryption operations through
	// real calls to KMS.
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

	t.Run("cert_auth", func(t *testing.T) {
		t.Run("env", func(t *testing.T) {
			// Need to unset the token otherwise we fail due to ambiguous authentication setup.
			token := os.Getenv(EnvOkmsToken)
			os.Unsetenv(EnvOkmsToken)
			defer os.Setenv(EnvOkmsToken, token)
			tempDir := t.TempDir()

			clientCert := os.Getenv("OVHCLOUDKMS_CERT_CLIENT_CERT")
			clientCertFilename := fmt.Sprintf("%s/%s", tempDir, "client-cert.pem")
			require.NoError(t, os.WriteFile(clientCertFilename, []byte(clientCert), 0o600))
			t.Setenv(EnvOkmsClientCert, clientCertFilename)

			clientKey := os.Getenv("OVHCLOUDKMS_CERT_CLIENT_KEY")
			clientKeyFilename := fmt.Sprintf("%s/%s", tempDir, "client-key.pem")
			require.NoError(t, os.WriteFile(clientKeyFilename, []byte(clientKey), 0o600))
			t.Setenv(EnvOkmsClientKey, clientKeyFilename)

			ow := NewWrapper()
			_, err := ow.SetConfig(t.Context())
			require.NoError(t, err)
			roundtrip(t, ow)
		})

		t.Run("no_env", func(t *testing.T) {
			configMap := map[string]string{
				"key_id":            keyId,
				"endpoint":          os.Getenv(EnvOkmsEndpoint),
				"kms_id":            os.Getenv(EnvOkmsId),
				"client_cert_bytes": os.Getenv("OVHCLOUDKMS_CERT_CLIENT_CERT"),
				"client_key_bytes":  os.Getenv("OVHCLOUDKMS_CERT_CLIENT_KEY"),
			}
			ow := NewWrapper()
			unsetEnvs(t)

			_, err := ow.SetConfig(t.Context(), wrapping.WithConfigMap(configMap), wrapping.WithDisallowEnvVars(true))
			require.NoError(t, err)
			roundtrip(t, ow)
		})
	})

	t.Run("credentials_auth", func(t *testing.T) {
		t.Run("env", func(t *testing.T) {
			ow := NewWrapper()
			_, err := ow.SetConfig(t.Context())
			require.NoError(t, err)
			roundtrip(t, ow)
		})

		t.Run("no_env", func(t *testing.T) {
			configMap := map[string]string{
				"key_id":   keyId,
				"endpoint": os.Getenv(EnvOkmsEndpoint),
				"kms_id":   os.Getenv(EnvOkmsId),
				"token":    os.Getenv(EnvOkmsToken),
			}
			ow := NewWrapper()
			unsetEnvs(t)

			_, err := ow.SetConfig(t.Context(), wrapping.WithConfigMap(configMap), wrapping.WithDisallowEnvVars(true))
			require.NoError(t, err)
			roundtrip(t, ow)
		})
	})
}
