// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"context"
	"encoding/base64"
	"os"
	"reflect"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

func TestSecurosysHSMWrapper(t *testing.T) {
	s := NewWrapper()
	if s == nil {
		t.Fatal("expected wrapper")
	}
}

// TestSecurosysHSMWrapper_Lifecycle is an HSM-backed acceptance test for the
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

// TestGetOptsAppliesLocalOptionsWithoutConfigMap verifies local option
// functions still work when no plugin-style config map is provided.
func TestGetOptsAppliesLocalOptionsWithoutConfigMap(t *testing.T) {
	opts, err := getOpts(WithCheckEvery("10"))
	if err != nil {
		t.Fatal(err)
	}

	if opts.withCheckEvery != "10" {
		t.Fatalf("expected check_every 10, got %q", opts.withCheckEvery)
	}
}

// TestSecurosysHSMWrapperEncryptDecryptWithClient uses a mock client to verify
// wrapper payload parsing and base64 handling without reaching an HSM.
func TestSecurosysHSMWrapperEncryptDecryptWithClient(t *testing.T) {
	w := NewWrapper()
	w.hsmClient = &mockSecurosysHSMClient{}
	w.client = w.hsmClient

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

// TestSecurosysHSMWrapperRejectsInvalidCiphertext verifies the wrapper rejects
// malformed ciphertext before calling the client.
func TestSecurosysHSMWrapperRejectsInvalidCiphertext(t *testing.T) {
	w := NewWrapper()
	w.hsmClient = &mockSecurosysHSMClient{}

	_, err := w.Decrypt(context.Background(), &wrapping.BlobInfo{
		Ciphertext: []byte("securosys:v1:ciphertext:extra"),
	})
	if err == nil {
		t.Fatal("expected invalid ciphertext error")
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

// mockSecurosysHSMClient returns the same payload shape as SecurosysHSMClient:
// securosys:<key-label>:<base64 nonce>:<base64 ciphertext>.
type mockSecurosysHSMClient struct{}

func (m *mockSecurosysHSMClient) Close() {}

func (m *mockSecurosysHSMClient) Encrypt(plaintext string) ([]byte, error) {
	return []byte("securosys:v1::" + base64.StdEncoding.EncodeToString([]byte(plaintext))), nil
}

func (m *mockSecurosysHSMClient) Decrypt(ciphertext string, _ string) ([]byte, error) {
	plaintext, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
