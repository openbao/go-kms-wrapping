// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package scwkms

import (
	"context"
	"os"
	"reflect"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScwKmsWrapper_MissingKeyId(t *testing.T) {
	s := NewWrapper()
	s.client = &mockClient{keyId: scwTestKeyId}

	_, err := s.SetConfig(context.Background())
	require.Error(t, err, "expected error when Scaleway KMS key ID is not provided")
}

func TestScwKmsWrapper_SetConfigFromEnv(t *testing.T) {
	s := NewWrapper()
	s.client = &mockClient{keyId: scwTestKeyId}

	old := os.Getenv(EnvScwKmsWrapperKeyId)
	os.Setenv(EnvScwKmsWrapperKeyId, scwTestKeyId)
	defer os.Setenv(EnvScwKmsWrapperKeyId, old)

	_, err := s.SetConfig(context.Background())
	require.NoError(t, err)
	require.Equal(t, scwTestKeyId, s.keyId)
}

func TestScwKmsWrapper_DisallowEnvVars(t *testing.T) {
	wrapper := NewScwKmsTestWrapper()

	// Set env vars that should be ignored
	for _, envVar := range []string{EnvScwKmsWrapperKeyId, "SCW_ACCESS_KEY", "SCW_SECRET_KEY", "SCW_DEFAULT_REGION"} {
		old := os.Getenv(envVar)
		os.Setenv(envVar, "should-be-ignored")
		defer os.Setenv(envVar, old)
	}

	config := map[string]string{
		"disallow_env_vars": "true",
		"kms_key_id":        scwTestKeyId,
		"access_key":        "SCWEXPLICITKEY",
		"secret_key":        "explicit-secret",
		"region":            "nl-ams",
	}

	_, err := wrapper.SetConfig(context.Background(), wrapping.WithConfigMap(config))
	assert.NoError(t, err)

	require.Equal(t, "SCWEXPLICITKEY", wrapper.accessKey)
	require.Equal(t, "explicit-secret", wrapper.secretKey)
	require.Equal(t, scwTestKeyId, wrapper.keyId)
	require.Equal(t, "nl-ams", wrapper.region)
	require.True(t, wrapper.disallowEnvVars)
}

func TestScwKmsWrapper_Lifecycle(t *testing.T) {
	s := NewScwKmsTestWrapper()
	testEncryptionRoundTrip(t, s)
}

func TestScwKmsWrapper_LifecycleWithOptions(t *testing.T) {
	s := NewScwKmsTestWrapper()

	input := []byte("hello scaleway kms")
	aad := []byte("additional authenticated data")

	encrypted, err := s.Encrypt(context.Background(), input, wrapping.WithAad(aad))
	require.NoError(t, err)
	require.NotNil(t, encrypted)

	decrypted, err := s.Decrypt(context.Background(), encrypted, wrapping.WithAad(aad))
	require.NoError(t, err)
	require.Equal(t, input, decrypted)
}

func TestScwKmsWrapper_Type(t *testing.T) {
	s := NewWrapper()
	wrapperType, err := s.Type(context.Background())
	require.NoError(t, err)
	require.Equal(t, wrapping.WrapperTypeScwKms, wrapperType)
}

func TestScwKmsWrapper_KeyId(t *testing.T) {
	s := NewScwKmsTestWrapper()
	keyId, err := s.KeyId(context.Background())
	require.NoError(t, err)
	require.Equal(t, scwTestKeyId, keyId)
}

// This test executes real calls. The calls themselves should be free,
// but the KMS key used may not be free depending on Scaleway pricing.
//
// To run this test, the following env variables need to be set:
//   - SCW_KMS_WRAPPER_KEY_ID
//   - SCW_ACCESS_KEY
//   - SCW_SECRET_KEY
//   - SCW_DEFAULT_REGION
func TestAccScwKmsWrapper_Lifecycle(t *testing.T) {
	if os.Getenv(EnvScwKmsWrapperKeyId) == "" {
		t.SkipNow()
	}

	s := NewWrapper()
	testEncryptionRoundTrip(t, s)
}

func testEncryptionRoundTrip(t *testing.T, w *Wrapper) {
	w.SetConfig(context.Background())
	input := []byte("foo bar baz")

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
