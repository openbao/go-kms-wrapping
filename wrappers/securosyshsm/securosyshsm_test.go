// Copyright (c) HashiCorp, Inc.
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
)

func TestSecurosysHSMWrapper(t *testing.T) {
	s := NewWrapper()
	if s == nil {
		t.Fatal("expected wrapper")
	}
}

// TestSecurosysHSMWrapper_Lifecycle is an HSM-backed test for the
// wrapper path: SetConfig, Encrypt, Decrypt, and Finalize through the public
// wrapping.Wrapper interface.
func TestSecurosysHSMWrapper_Lifecycle(t *testing.T) {
	if os.Getenv(SECUROSYS_HSM_RESTAPI_ENV_VAR) == "" || os.Getenv(SECUROSYS_BEARER_TOKEN_ENV_VAR) == "" {
		t.Skipf("set %s and %s to run Securosys HSM lifecycle test", SECUROSYS_HSM_RESTAPI_ENV_VAR, SECUROSYS_BEARER_TOKEN_ENV_VAR)
	}

	s := NewWrapper()
	config := map[string]string{
		"tsb_api_endpoint": os.Getenv(SECUROSYS_HSM_RESTAPI_ENV_VAR),
		"auth":             SECUROSYS_HSM_TEST_AUTH_TYPE,
		"bearer_token":     os.Getenv(SECUROSYS_BEARER_TOKEN_ENV_VAR),
		"key_label":        SECUROSYS_HSM_TEST_KEY_LABEL,
	}
	testEncryptionRoundTrip(t, s, wrapping.WithConfigMap(config))
}

func TestSecurosysHSMWrapper_MLKEMLifecycle(t *testing.T) {
	restAPI := strings.TrimSpace(os.Getenv(SECUROSYS_HSM_RESTAPI_ENV_VAR))
	bearerToken := strings.TrimSpace(os.Getenv(SECUROSYS_BEARER_TOKEN_ENV_VAR))
	if restAPI == "" || bearerToken == "" {
		t.Skipf("set %s and %s to run Securosys HSM ML-KEM lifecycle tests", SECUROSYS_HSM_RESTAPI_ENV_VAR, SECUROSYS_BEARER_TOKEN_ENV_VAR)
	}

	tsbClient, err := client.NewTSBClient(restAPI, client.AuthStruct{
		AuthType:    SECUROSYS_HSM_TEST_AUTH_TYPE,
		BearerToken: bearerToken,
		AppName:     "OpenBao - Securosys HSM Wrapper ML-KEM Test",
	})
	if err != nil {
		t.Fatalf("create TSB client: %v", err)
	}

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
			if _, err := tsbClient.CreateOrUpdateKey(t.Context(), keyLabel, "", attributes, algorithm, 0, nil, "", false); err != nil {
				t.Fatalf("create %s key: %v", algorithm, err)
			}
			t.Cleanup(func() {
				if err := tsbClient.RemoveKey(context.Background(), keyLabel); err != nil {
					t.Logf("remove %s test key: %v", algorithm, err)
				}
			})

			wrapper := NewWrapper()
			t.Cleanup(func() { _ = wrapper.Finalize(context.Background()) })
			testEncryptionRoundTrip(t, wrapper, wrapping.WithConfigMap(map[string]string{
				"tsb_api_endpoint": restAPI,
				"auth":             SECUROSYS_HSM_TEST_AUTH_TYPE,
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
	if err != nil {
		t.Fatal(err)
	}

	if opts.WithConfigMap["check_every"] != "10" {
		t.Fatalf("expected check_every 10, got %q", opts.WithConfigMap["check_every"])
	}
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
	if err != nil {
		t.Fatal(err)
	}

	provider := securosysKMSConfigMap(opts)

	if provider["rest_api"] != "https://test.com" {
		t.Fatalf("expected rest_api remap, got %#v", provider["rest_api"])
	}
	if _, ok := provider["tsb_api_endpoint"]; ok {
		t.Fatal("expected tsb_api_endpoint to be remapped, not copied")
	}
	if _, ok := provider["key_label"]; ok {
		t.Fatal("expected key_label to stay out of provider config")
	}
	if _, ok := provider["key_password"]; ok {
		t.Fatal("expected key_password to stay out of provider config")
	}
	if provider["auth"] != "TOKEN" || provider["bearer_token"] != "token" {
		t.Fatalf("unexpected provider auth config: %#v", provider)
	}
}

func TestSecurosysKMSKeyConfigMapUsesKeyLabel(t *testing.T) {
	opts := &options{
		withKeyLabel:    "ml-kem-key",
		withKeyPassword: "secret",
	}
	config := securosysKMSKeyConfigMap(opts)
	if config["name"] != "ml-kem-key" || config["password"] != "secret" {
		t.Fatalf("unexpected key config: %#v", config)
	}
	if _, ok := config["cipher_algorithm"]; ok {
		t.Fatal("cipher_algorithm must be resolved from TSB key attributes")
	}
}

// TestSecurosysHSMWrapperEncryptDecryptWithClient uses a mock client to verify
// wrapper payload parsing and base64 handling without reaching an HSM.
func TestSecurosysHSMWrapperEncryptDecryptWithClient(t *testing.T) {
	w := NewWrapper()
	w.client = &mockSecurosysHSMClient{}

	input := []byte("foo")
	blob, err := w.Encrypt(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}

	if blob.KeyInfo.KeyId != "v1" {
		t.Fatalf("expected key id v1, got %q", blob.KeyInfo.KeyId)
	}

	plaintext, err := w.Decrypt(context.Background(), blob)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(input, plaintext) {
		t.Fatalf("expected %s, got %s", input, plaintext)
	}
}

func TestSecurosysHSMWrapperMLKEMEncryptDecrypt(t *testing.T) {
	key := &mockMLKEMKey{ciphertext: []byte{0, 1, 2, ':', 0xff, 4}}
	client := &SecurosysHSMClient{key: key, keyLabel: "ml-kem-key"}
	wrapper := NewWrapper()
	wrapper.client = client

	plaintext := []byte("OpenBao wrapper ML-KEM payload")
	blob, err := wrapper.Encrypt(t.Context(), plaintext)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	parsed, err := parseCiphertext(blob.Ciphertext)
	if err != nil {
		t.Fatalf("parseCiphertext returned error: %v", err)
	}
	if parsed.keyID != "ml-kem-key" {
		t.Fatalf("key id = %q, want ml-kem-key", parsed.keyID)
	}
	if parsed.nonce != "" {
		t.Fatalf("ML-KEM envelope must contain its nonce, wrapper nonce = %q", parsed.nonce)
	}
	decodedCiphertext, err := base64.StdEncoding.DecodeString(parsed.ciphertext)
	if err != nil {
		t.Fatalf("decode wrapper ciphertext: %v", err)
	}
	if !reflect.DeepEqual(decodedCiphertext, key.ciphertext) {
		t.Fatalf("wrapped ciphertext = %x, want %x", decodedCiphertext, key.ciphertext)
	}

	decrypted, err := wrapper.Decrypt(t.Context(), blob)
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}
	if !reflect.DeepEqual(decrypted, plaintext) {
		t.Fatalf("decrypted plaintext = %q, want %q", decrypted, plaintext)
	}
}

// TestSecurosysHSMWrapperRejectsInvalidCiphertext verifies the wrapper rejects
// malformed ciphertext before calling the client.
func TestSecurosysHSMWrapperRejectsInvalidCiphertext(t *testing.T) {
	w := NewWrapper()
	w.client = &mockSecurosysHSMClient{}

	_, err := w.Decrypt(context.Background(), &wrapping.BlobInfo{
		Ciphertext: []byte("securosys:v1:ciphertext:extra"),
	})
	if err == nil {
		t.Fatal("expected invalid ciphertext error")
	}
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
			name:       "missing key id",
			ciphertext: []byte("securosys::nonce:ciphertext"),
			wantErr:    true,
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
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if parsed.keyID != "v1" || parsed.nonce != "nonce" || parsed.ciphertext != "ciphertext" {
				t.Fatalf("unexpected parsed ciphertext: %#v", parsed)
			}
		})
	}
}

// testEncryptionRoundTrip is shared by acceptance tests and validates that a
// configured wrapper can round-trip arbitrary plaintext.
func testEncryptionRoundTrip(t *testing.T, w *Wrapper, opt ...wrapping.Option) {
	if w == nil {
		t.Fatal("expected wrapper")
	}
	if _, err := w.SetConfig(context.Background(), opt...); err != nil {
		t.Fatal(err)
	}
	input := []byte("foo")
	swi, err := w.Encrypt(context.Background(), input, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	pt, err := w.Decrypt(context.Background(), swi, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}
}

type mockSecurosysHSMClient struct{}

func (m *mockSecurosysHSMClient) Close() {}

func (m *mockSecurosysHSMClient) Encrypt(_ context.Context, plaintext []byte) ([]byte, string, error) {
	return plaintext, "v1", nil
}

func (m *mockSecurosysHSMClient) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
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
