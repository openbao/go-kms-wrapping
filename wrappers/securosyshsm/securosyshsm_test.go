// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	client "github.com/securosys-com/tsb-client-go"
	"github.com/stretchr/testify/require"
)

func TestSecurosysHSMWrapper(t *testing.T) {
	s := NewWrapper()
	require.NotNil(t, s)
}

func TestSecurosysHSMWrapperKeyIdReturnsConfiguredKeyLabel(t *testing.T) {
	w := NewWrapper()
	w.configuredKeyName = "configured-key"

	keyID, err := w.KeyId(t.Context())
	require.NoError(t, err)
	require.Equal(t, "configured-key", keyID)
}

// TestSecurosysHSMWrapper_Lifecycle is an HSM-backed test for the
// wrapper path: SetConfig, Encrypt, Decrypt, and Finalize through the public
// wrapping.Wrapper interface.
func TestSecurosysHSMWrapper_Lifecycle(t *testing.T) {
	if os.Getenv(securosysHSMRestAPIEnvVar) == "" || os.Getenv(securosysBearerTokenEnvVar) == "" {
		t.Skipf("set %s and %s to run Securosys HSM lifecycle test", securosysHSMRestAPIEnvVar, securosysBearerTokenEnvVar)
	}

	s := NewWrapper()
	config := map[string]string{
		"tsb_api_endpoint": os.Getenv(securosysHSMRestAPIEnvVar),
		"auth":             securosysHSMTestAuthType,
		"bearer_token":     os.Getenv(securosysBearerTokenEnvVar),
		"key_label":        securosysHSMTestKeyLabel,
	}
	testEncryptionRoundTrip(t, s, wrapping.WithConfigMap(config))
}

func TestSecurosysHSMWrapper_MLKEMLifecycle(t *testing.T) {
	restAPI := strings.TrimSpace(os.Getenv(securosysHSMRestAPIEnvVar))
	bearerToken := strings.TrimSpace(os.Getenv(securosysBearerTokenEnvVar))
	if restAPI == "" || bearerToken == "" {
		t.Skipf("set %s and %s to run Securosys HSM ML-KEM lifecycle tests", securosysHSMRestAPIEnvVar, securosysBearerTokenEnvVar)
	}

	tsbClient, err := client.NewTSBClient(restAPI, client.AuthStruct{
		AuthType:    securosysHSMTestAuthType,
		BearerToken: bearerToken,
		AppName:     "OpenBao - Securosys HSM Wrapper ML-KEM Test",
	})
	require.NoError(t, err, "create TSB client")

	attributes := map[string]bool{
		"decrypt":     false,
		"encrypt":     false,
		"extractable": false,
		"sign":        false,
		"unwrap":      true,
		"verify":      false,
		"wrap":        true,
		"destroyable": true,
	}
	for _, algorithm := range []string{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"} {
		t.Run(algorithm, func(t *testing.T) {
			keyLabel := "openbao_wrapper_test_" + strings.ToLower(strings.ReplaceAll(algorithm, "-", "_"))
			_, err := tsbClient.CreateOrUpdateKey(t.Context(), keyLabel, "", attributes, algorithm, 0, nil, "", false)
			require.NoError(t, err, "create %s key", algorithm)
			t.Cleanup(func() {
				if err := tsbClient.RemoveKey(context.Background(), keyLabel); err != nil {
					t.Logf("remove %s test key: %v", algorithm, err)
				}
			})

			wrapper := NewWrapper()
			t.Cleanup(func() { _ = wrapper.Finalize(context.Background()) })
			testEncryptionRoundTrip(t, wrapper, wrapping.WithConfigMap(map[string]string{
				"tsb_api_endpoint": restAPI,
				"auth":             securosysHSMTestAuthType,
				"bearer_token":     bearerToken,
				"key_label":        keyLabel,
			}))
		})
	}
}

func TestGetOptsAppliesConfigMap(t *testing.T) {
	opts, err := getOpts(wrapping.WithConfigMap(map[string]string{
		"check_every": "10",
	}))
	require.NoError(t, err)
	require.Equal(t, "10", opts.WithConfigMap["check_every"])
}

func TestSecurosysKMSConfigMapRemapsWrapperConfig(t *testing.T) {
	opts, err := getOpts(wrapping.WithConfigMap(map[string]string{
		"tsb_api_endpoint":     "https://test.com",
		"auth":                 "TOKEN",
		"bearer_token":         "token",
		"key_label":            "wrapper-key",
		"key_password":         "secret",
		"check_every":          "20",
		"approval_timeout":     "600",
		"application_key_pair": "{}",
		"api_keys":             "{}",
	}))
	require.NoError(t, err)

	provider := securosysKMSConfigMap(opts)

	require.Equal(t, "https://test.com", provider["rest_api"])
	require.NotContains(t, provider, "tsb_api_endpoint")
	require.NotContains(t, provider, "key_label")
	require.NotContains(t, provider, "key_password")
	require.Equal(t, "TOKEN", provider["auth"])
	require.Equal(t, "token", provider["bearer_token"])
}

func TestSecurosysKMSKeyConfigMapUsesKeyLabel(t *testing.T) {
	opts := &options{
		withKeyLabel:    "ml-kem-key",
		withKeyPassword: "secret",
	}
	config := securosysKMSKeyConfigMap(opts)
	require.Equal(t, "ml-kem-key", config["name"])
	require.Equal(t, "secret", config["password"])
	require.NotContains(t, config, "cipher_algorithm")
}

// TestSecurosysHSMWrapperEncryptDecryptWithClient uses a mock client to verify
// wrapper payload parsing and base64 handling without reaching an HSM.
func TestSecurosysHSMWrapperEncryptDecryptWithClient(t *testing.T) {
	w := NewWrapper()
	client := &mockSecurosysHSMClient{}
	w.client = client

	input := []byte("foo")
	blob, err := w.Encrypt(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, "v1", blob.KeyInfo.KeyId)

	plaintext, err := w.Decrypt(context.Background(), blob)
	require.NoError(t, err)
	require.Equal(t, input, plaintext)
	require.Equal(t, "v1", client.decryptKeyName)
}

func TestSecurosysHSMWrapperDecryptUsesConfiguredKeyNameFallback(t *testing.T) {
	client := &mockSecurosysHSMClient{}
	w := NewWrapper()
	w.client = client
	w.configuredKeyName = "configured-key"

	plaintext, err := w.Decrypt(t.Context(), &wrapping.BlobInfo{
		Ciphertext: []byte("securosys:::Wm05dg=="),
	})
	require.NoError(t, err)
	require.Equal(t, "foo", string(plaintext))
	require.Equal(t, "configured-key", client.decryptKeyName)
}

func TestSecurosysHSMWrapperMLKEMEncryptDecrypt(t *testing.T) {
	key := &mockMLKEMKey{ciphertext: []byte{0, 1, 2, ':', 0xff, 4}}
	client := &SecurosysHSMClient{key: key, keyLabel: "ml-kem-key"}
	wrapper := NewWrapper()
	wrapper.client = client

	plaintext := []byte("OpenBao wrapper ML-KEM payload")
	blob, err := wrapper.Encrypt(t.Context(), plaintext)
	require.NoError(t, err)
	parsed, err := parseCiphertext(blob.Ciphertext)
	require.NoError(t, err)
	require.Equal(t, "ml-kem-key", parsed.keyName)
	require.Empty(t, parsed.nonce, "ML-KEM envelope must contain its nonce")
	decodedCiphertext, err := base64.StdEncoding.DecodeString(parsed.ciphertext)
	require.NoError(t, err)
	require.Equal(t, key.ciphertext, decodedCiphertext)

	decrypted, err := wrapper.Decrypt(t.Context(), blob)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

// TestSecurosysHSMWrapperRejectsInvalidCiphertext verifies the wrapper rejects
// malformed ciphertext before calling the client.
func TestSecurosysHSMWrapperRejectsInvalidCiphertext(t *testing.T) {
	w := NewWrapper()
	w.client = &mockSecurosysHSMClient{}

	_, err := w.Decrypt(context.Background(), &wrapping.BlobInfo{
		Ciphertext: []byte("securosys:v1:ciphertext:extra"),
	})
	require.Error(t, err)
}

func TestParseCiphertext(t *testing.T) {
	tests := []struct {
		name       string
		ciphertext []byte
		wantErr    bool
	}{
		{
			name:       "valid",
			ciphertext: []byte("securosys:v1:nonce:ciphertext"),
		},
		{
			name:       "wrong prefix",
			ciphertext: []byte("other:v1:nonce:ciphertext"),
			wantErr:    true,
		},
		{
			name:       "missing key name uses configured fallback",
			ciphertext: []byte("securosys::nonce:ciphertext"),
		},
		{
			name:       "missing payload",
			ciphertext: []byte("securosys:v1:nonce:"),
			wantErr:    true,
		},
		{
			name:       "too many parts",
			ciphertext: []byte("securosys:v1:nonce:ciphertext:extra"),
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := parseCiphertext(tt.ciphertext)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			wantKeyName := "v1"
			if tt.name == "missing key name uses configured fallback" {
				wantKeyName = ""
			}
			require.Equal(t, wantKeyName, parsed.keyName)
			require.Equal(t, "nonce", parsed.nonce)
			require.Equal(t, "ciphertext", parsed.ciphertext)
		})
	}
}

// testEncryptionRoundTrip is shared by acceptance tests and validates that a
// configured wrapper can round-trip arbitrary plaintext.
func testEncryptionRoundTrip(t *testing.T, w *Wrapper, opt ...wrapping.Option) {
	require.NotNil(t, w)
	_, err := w.SetConfig(context.Background(), opt...)
	require.NoError(t, err)
	input := []byte("foo")
	swi, err := w.Encrypt(context.Background(), input, nil)
	require.NoError(t, err)

	pt, err := w.Decrypt(context.Background(), swi, nil)
	require.NoError(t, err)
	require.Equal(t, input, pt)
}

type mockSecurosysHSMClient struct {
	decryptKeyName string
}

func (m *mockSecurosysHSMClient) Close() {}

func (m *mockSecurosysHSMClient) Encrypt(_ context.Context, plaintext []byte) ([]byte, string, error) {
	return plaintext, "v1", nil
}

func (m *mockSecurosysHSMClient) Decrypt(_ context.Context, ciphertext []byte, keyName string) ([]byte, error) {
	m.decryptKeyName = keyName
	return ciphertext, nil
}

type mockMLKEMKey struct {
	kms.UnimplementedKey
	ciphertext []byte
	plaintext  []byte
}

func (m *mockMLKEMKey) Encrypt(_ context.Context, opts *kms.CipherOptions) ([]byte, error) {
	m.plaintext = append([]byte(nil), opts.Data...)
	return append([]byte(nil), m.ciphertext...), nil
}

func (m *mockMLKEMKey) Decrypt(_ context.Context, opts *kms.CipherOptions) ([]byte, error) {
	if !reflect.DeepEqual(opts.Data, m.ciphertext) {
		return nil, fmt.Errorf("ML-KEM ciphertext = %x, want %x", opts.Data, m.ciphertext)
	}
	return append([]byte(nil), m.plaintext...), nil
}
