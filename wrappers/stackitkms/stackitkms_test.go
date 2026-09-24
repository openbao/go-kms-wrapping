// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package stackitkms

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stackitcloud/stackit-sdk-go/services/kms/v1api"
	"github.com/stretchr/testify/require"
)

const (
	testProjectId = "11111111-1111-1111-1111-111111111111"
	testKeyRingId = "22222222-2222-2222-2222-222222222222"
	testKeyId     = "33333333-3333-3333-3333-333333333333"
	testRegion    = "eu01"
)

// fakeKmsClient implements kmsClient in memory. Its "ciphertext" is tagged
// with the key/version used, so decrypting with the wrong version fails.
type fakeKmsClient struct {
	key      v1api.Key
	versions []v1api.Version

	encryptCalls []string
	decryptCalls []string
}

func newFakeKmsClient(purpose v1api.Purpose, versions ...v1api.Version) *fakeKmsClient {
	return &fakeKmsClient{
		key: v1api.Key{
			Id:        testKeyId,
			KeyRingId: testKeyRingId,
			Purpose:   purpose,
			State:     "active",
		},
		versions: versions,
	}
}

func fakeVersion(number int64, state v1api.VersionState, disabled bool) v1api.Version {
	return v1api.Version{
		KeyId:     testKeyId,
		KeyRingId: testKeyRingId,
		Number:    number,
		State:     state,
		Disabled:  disabled,
	}
}

func xorWith(b []byte, k byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ k
	}
	return out
}

func (f *fakeKmsClient) encrypt(_ context.Context, keyId string, version int64, plaintext []byte) ([]byte, error) {
	f.encryptCalls = append(f.encryptCalls, keyVersionId(keyId, version))
	prefix := fmt.Sprintf("%s/%d:", keyId, version)
	return append([]byte(prefix), xorWith(plaintext, byte(version))...), nil
}

func (f *fakeKmsClient) decrypt(_ context.Context, keyId string, version int64, wrappedKey []byte) ([]byte, error) {
	f.decryptCalls = append(f.decryptCalls, keyVersionId(keyId, version))
	prefix := fmt.Sprintf("%s/%d:", keyId, version)
	if !bytes.HasPrefix(wrappedKey, []byte(prefix)) {
		return nil, fmt.Errorf("ciphertext was not encrypted by key version %s/%d", keyId, version)
	}
	return xorWith(wrappedKey[len(prefix):], byte(version)), nil
}

func (f *fakeKmsClient) getKey(_ context.Context, keyId string) (*v1api.Key, error) {
	if keyId != f.key.Id {
		return nil, fmt.Errorf("key %q not found", keyId)
	}
	key := f.key
	return &key, nil
}

func (f *fakeKmsClient) getVersion(_ context.Context, keyId string, version int64) (*v1api.Version, error) {
	for i := range f.versions {
		if f.versions[i].KeyId == keyId && f.versions[i].Number == version {
			v := f.versions[i]
			return &v, nil
		}
	}
	return nil, fmt.Errorf("version %d of key %q not found", version, keyId)
}

func (f *fakeKmsClient) listVersions(_ context.Context, keyId string) ([]v1api.Version, error) {
	if keyId != f.key.Id {
		return nil, fmt.Errorf("key %q not found", keyId)
	}
	return f.versions, nil
}

func testConfigMap(overrides map[string]string) map[string]string {
	m := map[string]string{
		"project_id":  testProjectId,
		"region":      testRegion,
		"key_ring_id": testKeyRingId,
		"key_id":      testKeyId,
	}
	for k, v := range overrides {
		if v == "" {
			delete(m, k)
			continue
		}
		m[k] = v
	}
	return m
}

func testWrapper(t *testing.T, fake *fakeKmsClient, overrides map[string]string) *Wrapper {
	t.Helper()
	w := NewWrapper()
	w.newClient = func(clientConfig) (kmsClient, error) { return fake, nil }
	_, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(testConfigMap(overrides)))
	require.NoError(t, err)
	return w
}

func TestWrapperRoundtrip(t *testing.T) {
	fake := newFakeKmsClient(
		v1api.PURPOSE_SYMMETRIC_ENCRYPT_DECRYPT,
		fakeVersion(1, v1api.VERSIONSTATE_ACTIVE, false),
	)
	w := testWrapper(t, fake, nil)
	ctx := context.Background()

	plaintext := []byte("the quick brown fox")
	blob, err := w.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	require.False(t, bytes.Contains(blob.Ciphertext, plaintext), "ciphertext contains plaintext")
	require.Equal(t, testKeyId+"/1", blob.KeyInfo.KeyId)

	decrypted, err := w.Decrypt(ctx, blob)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestWrapperRoundtripWithAad(t *testing.T) {
	fake := newFakeKmsClient(
		v1api.PURPOSE_SYMMETRIC_ENCRYPT_DECRYPT,
		fakeVersion(1, v1api.VERSIONSTATE_ACTIVE, false),
	)
	w := testWrapper(t, fake, nil)
	ctx := context.Background()

	plaintext := []byte("with additional data")
	blob, err := w.Encrypt(ctx, plaintext, wrapping.WithAad([]byte("aad")))
	require.NoError(t, err)

	decrypted, err := w.Decrypt(ctx, blob, wrapping.WithAad([]byte("aad")))
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)

	_, err = w.Decrypt(ctx, blob, wrapping.WithAad([]byte("other")))
	require.Error(t, err, "Decrypt with wrong AAD must fail")
}

func TestLatestVersionResolution(t *testing.T) {
	fake := newFakeKmsClient(
		v1api.PURPOSE_SYMMETRIC_ENCRYPT_DECRYPT,
		fakeVersion(1, v1api.VERSIONSTATE_ACTIVE, false),
		fakeVersion(2, v1api.VERSIONSTATE_ACTIVE, false),
		fakeVersion(3, v1api.VERSIONSTATE_ACTIVE, true),    // disabled
		fakeVersion(4, v1api.VERSIONSTATE_CREATING, false), // not active yet
	)
	w := testWrapper(t, fake, nil)

	keyId, err := w.KeyId(context.Background())
	require.NoError(t, err)
	require.Equal(t, testKeyId+"/2", keyId, "highest enabled active version")
}

func TestExplicitVersion(t *testing.T) {
	fake := newFakeKmsClient(
		v1api.PURPOSE_SYMMETRIC_ENCRYPT_DECRYPT,
		fakeVersion(1, v1api.VERSIONSTATE_ACTIVE, false),
		fakeVersion(2, v1api.VERSIONSTATE_ACTIVE, false),
	)
	w := testWrapper(t, fake, map[string]string{"key_version": "1"})

	blob, err := w.Encrypt(context.Background(), []byte("pinned"))
	require.NoError(t, err)
	require.Equal(t, testKeyId+"/1", blob.KeyInfo.KeyId)
}

func TestDecryptAfterRotation(t *testing.T) {
	ctx := context.Background()

	fakeV1 := newFakeKmsClient(
		v1api.PURPOSE_SYMMETRIC_ENCRYPT_DECRYPT,
		fakeVersion(1, v1api.VERSIONSTATE_ACTIVE, false),
	)
	blob, err := testWrapper(t, fakeV1, nil).Encrypt(ctx, []byte("pre-rotation"))
	require.NoError(t, err)

	// A wrapper configured after rotation to version 2 must still decrypt
	// the old blob with version 1.
	fakeV2 := newFakeKmsClient(
		v1api.PURPOSE_SYMMETRIC_ENCRYPT_DECRYPT,
		fakeVersion(1, v1api.VERSIONSTATE_ACTIVE, false),
		fakeVersion(2, v1api.VERSIONSTATE_ACTIVE, false),
	)
	w := testWrapper(t, fakeV2, nil)

	decrypted, err := w.Decrypt(ctx, blob)
	require.NoError(t, err)
	require.Equal(t, []byte("pre-rotation"), decrypted)
	require.Equal(t, []string{testKeyId + "/1"}, fakeV2.decryptCalls)

	// New encryptions use the current version and change the reported key id.
	newBlob, err := w.Encrypt(ctx, []byte("post-rotation"))
	require.NoError(t, err)
	require.Equal(t, testKeyId+"/2", newBlob.KeyInfo.KeyId)
}

func TestSetConfigMissingParameters(t *testing.T) {
	for _, param := range []string{"project_id", "region", "key_ring_id", "key_id"} {
		t.Run(param, func(t *testing.T) {
			w := NewWrapper()
			w.newClient = func(clientConfig) (kmsClient, error) {
				t.Fatal("client must not be created when configuration is incomplete")
				return nil, nil
			}
			_, err := w.SetConfig(context.Background(),
				wrapping.WithConfigMap(testConfigMap(map[string]string{param: ""})))
			require.Error(t, err, "SetConfig without %s must fail", param)
		})
	}
}

func TestSetConfigRejectsBadKeyVersion(t *testing.T) {
	for _, bad := range []string{"zero", "0", "-1", "1.5"} {
		w := NewWrapper()
		w.newClient = func(clientConfig) (kmsClient, error) {
			t.Fatal("client must not be created when configuration is invalid")
			return nil, nil
		}
		_, err := w.SetConfig(context.Background(),
			wrapping.WithConfigMap(testConfigMap(map[string]string{"key_version": bad})))
		require.Error(t, err, "SetConfig with key_version=%q must fail", bad)
	}
}

func TestSetConfigRejectsWrongPurpose(t *testing.T) {
	fake := newFakeKmsClient(
		v1api.PURPOSE_ASYMMETRIC_SIGN_VERIFY,
		fakeVersion(1, v1api.VERSIONSTATE_ACTIVE, false),
	)
	w := NewWrapper()
	w.newClient = func(clientConfig) (kmsClient, error) { return fake, nil }
	_, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(testConfigMap(nil)))
	require.Error(t, err, "SetConfig with a sign/verify key must fail")
}

func TestSetConfigRejectsUnusableVersion(t *testing.T) {
	fake := newFakeKmsClient(
		v1api.PURPOSE_SYMMETRIC_ENCRYPT_DECRYPT,
		fakeVersion(1, v1api.VERSIONSTATE_ACTIVE, true), // disabled
	)

	// Explicitly pinned unusable version.
	w := NewWrapper()
	w.newClient = func(clientConfig) (kmsClient, error) { return fake, nil }
	_, err := w.SetConfig(context.Background(),
		wrapping.WithConfigMap(testConfigMap(map[string]string{"key_version": "1"})))
	require.Error(t, err, "SetConfig with a disabled pinned version must fail")

	// No usable version to auto-resolve.
	w = NewWrapper()
	w.newClient = func(clientConfig) (kmsClient, error) { return fake, nil }
	_, err = w.SetConfig(context.Background(), wrapping.WithConfigMap(testConfigMap(nil)))
	require.Error(t, err, "SetConfig with no usable version must fail")
}

func TestSetConfigEnvVars(t *testing.T) {
	fake := newFakeKmsClient(
		v1api.PURPOSE_SYMMETRIC_ENCRYPT_DECRYPT,
		fakeVersion(1, v1api.VERSIONSTATE_ACTIVE, false),
	)

	t.Setenv(envKMSProjectID, testProjectId)
	t.Setenv(envKMSRegion, testRegion)
	t.Setenv(envKMSKeyRingID, testKeyRingId)
	t.Setenv(envKMSKeyID, testKeyId)

	w := NewWrapper()
	var gotConfig clientConfig
	w.newClient = func(cc clientConfig) (kmsClient, error) {
		gotConfig = cc
		return fake, nil
	}
	_, err := w.SetConfig(context.Background())
	require.NoError(t, err, "SetConfig from environment")
	require.Equal(t, testProjectId, gotConfig.projectId)
	require.Equal(t, testRegion, gotConfig.region)
	require.Equal(t, testKeyRingId, gotConfig.keyRingId)

	// With WithDisallowEnvVars the same environment must not be consulted.
	w = NewWrapper()
	w.newClient = func(clientConfig) (kmsClient, error) { return fake, nil }
	_, err = w.SetConfig(context.Background(), wrapping.WithDisallowEnvVars(true))
	require.Error(t, err, "SetConfig with WithDisallowEnvVars and no config must fail")

	w = NewWrapper()
	w.newClient = func(cc clientConfig) (kmsClient, error) {
		gotConfig = cc
		return fake, nil
	}
	_, err = w.SetConfig(context.Background(),
		wrapping.WithConfigMap(testConfigMap(nil)), wrapping.WithDisallowEnvVars(true))
	require.NoError(t, err)
	require.True(t, gotConfig.disallowEnvVars)
}

func TestSetConfigMetadata(t *testing.T) {
	fake := newFakeKmsClient(
		v1api.PURPOSE_SYMMETRIC_ENCRYPT_DECRYPT,
		fakeVersion(1, v1api.VERSIONSTATE_ACTIVE, false),
	)
	w := NewWrapper()
	w.newClient = func(clientConfig) (kmsClient, error) { return fake, nil }
	cfg, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(testConfigMap(nil)))
	require.NoError(t, err)

	want := map[string]string{
		"project_id":  testProjectId,
		"region":      testRegion,
		"key_ring_id": testKeyRingId,
		"key_id":      testKeyId,
		"key_version": "1",
	}
	require.Equal(t, want, cfg.Metadata)
}

func TestDecryptRejectsInvalidBlob(t *testing.T) {
	fake := newFakeKmsClient(
		v1api.PURPOSE_SYMMETRIC_ENCRYPT_DECRYPT,
		fakeVersion(1, v1api.VERSIONSTATE_ACTIVE, false),
	)
	w := testWrapper(t, fake, nil)
	ctx := context.Background()

	_, err := w.Decrypt(ctx, nil)
	require.Error(t, err, "Decrypt of nil blob must fail")
	_, err = w.Decrypt(ctx, &wrapping.BlobInfo{Ciphertext: []byte("x")})
	require.Error(t, err, "Decrypt of blob without key info must fail")
}

func TestUnconfiguredWrapper(t *testing.T) {
	w := NewWrapper()
	ctx := context.Background()
	_, err := w.Encrypt(ctx, []byte("x"))
	require.Error(t, err, "Encrypt on unconfigured wrapper must fail")
	_, err = w.Decrypt(ctx, &wrapping.BlobInfo{})
	require.Error(t, err, "Decrypt on unconfigured wrapper must fail")
}

func TestParseKeyVersionId(t *testing.T) {
	keyId, version, ok := parseKeyVersionId(testKeyId + "/7")
	require.True(t, ok)
	require.Equal(t, testKeyId, keyId)
	require.Equal(t, int64(7), version)

	for _, bad := range []string{"", testKeyId, testKeyId + "/", testKeyId + "/x", testKeyId + "/0", testKeyId + "/-1", "/1"} {
		_, _, ok := parseKeyVersionId(bad)
		require.False(t, ok, "parseKeyVersionId(%q) must not parse", bad)
	}
}
