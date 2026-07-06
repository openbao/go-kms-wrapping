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
	if _, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(testConfigMap(overrides))); err != nil {
		t.Fatalf("SetConfig failed: %v", err)
	}
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
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if bytes.Contains(blob.Ciphertext, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}
	if got, want := blob.KeyInfo.KeyId, testKeyId+"/1"; got != want {
		t.Fatalf("blob KeyId = %q, want %q", got, want)
	}
	if blob.KeyInfo.Mechanism != StackitKmsEnvelopeAesGcmEncrypt {
		t.Fatalf("blob Mechanism = %d, want %d", blob.KeyInfo.Mechanism, StackitKmsEnvelopeAesGcmEncrypt)
	}

	decrypted, err := w.Decrypt(ctx, blob)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypt = %q, want %q", decrypted, plaintext)
	}
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
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := w.Decrypt(ctx, blob, wrapping.WithAad([]byte("aad")))
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypt = %q, want %q", decrypted, plaintext)
	}

	if _, err := w.Decrypt(ctx, blob, wrapping.WithAad([]byte("other"))); err == nil {
		t.Fatal("Decrypt with wrong AAD succeeded, want error")
	}
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
	if err != nil {
		t.Fatalf("KeyId failed: %v", err)
	}
	if want := testKeyId + "/2"; keyId != want {
		t.Fatalf("KeyId = %q, want %q (highest enabled active version)", keyId, want)
	}
}

func TestExplicitVersion(t *testing.T) {
	fake := newFakeKmsClient(
		v1api.PURPOSE_SYMMETRIC_ENCRYPT_DECRYPT,
		fakeVersion(1, v1api.VERSIONSTATE_ACTIVE, false),
		fakeVersion(2, v1api.VERSIONSTATE_ACTIVE, false),
	)
	w := testWrapper(t, fake, map[string]string{"key_version": "1"})

	blob, err := w.Encrypt(context.Background(), []byte("pinned"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if got, want := blob.KeyInfo.KeyId, testKeyId+"/1"; got != want {
		t.Fatalf("blob KeyId = %q, want %q", got, want)
	}
}

func TestDecryptAfterRotation(t *testing.T) {
	ctx := context.Background()

	fakeV1 := newFakeKmsClient(
		v1api.PURPOSE_SYMMETRIC_ENCRYPT_DECRYPT,
		fakeVersion(1, v1api.VERSIONSTATE_ACTIVE, false),
	)
	blob, err := testWrapper(t, fakeV1, nil).Encrypt(ctx, []byte("pre-rotation"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// A wrapper configured after rotation to version 2 must still decrypt
	// the old blob with version 1.
	fakeV2 := newFakeKmsClient(
		v1api.PURPOSE_SYMMETRIC_ENCRYPT_DECRYPT,
		fakeVersion(1, v1api.VERSIONSTATE_ACTIVE, false),
		fakeVersion(2, v1api.VERSIONSTATE_ACTIVE, false),
	)
	w := testWrapper(t, fakeV2, nil)

	decrypted, err := w.Decrypt(ctx, blob)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, []byte("pre-rotation")) {
		t.Fatalf("Decrypt = %q, want %q", decrypted, "pre-rotation")
	}
	if len(fakeV2.decryptCalls) != 1 || fakeV2.decryptCalls[0] != testKeyId+"/1" {
		t.Fatalf("decrypt calls = %v, want exactly one call with version 1", fakeV2.decryptCalls)
	}

	// New encryptions use the current version and change the reported key id.
	newBlob, err := w.Encrypt(ctx, []byte("post-rotation"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if got, want := newBlob.KeyInfo.KeyId, testKeyId+"/2"; got != want {
		t.Fatalf("blob KeyId = %q, want %q", got, want)
	}
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
			if err == nil {
				t.Fatalf("SetConfig without %s succeeded, want error", param)
			}
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
		if err == nil {
			t.Fatalf("SetConfig with key_version=%q succeeded, want error", bad)
		}
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
	if err == nil {
		t.Fatal("SetConfig with a sign/verify key succeeded, want error")
	}
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
	if err == nil {
		t.Fatal("SetConfig with a disabled pinned version succeeded, want error")
	}

	// No usable version to auto-resolve.
	w = NewWrapper()
	w.newClient = func(clientConfig) (kmsClient, error) { return fake, nil }
	_, err = w.SetConfig(context.Background(), wrapping.WithConfigMap(testConfigMap(nil)))
	if err == nil {
		t.Fatal("SetConfig with no usable version succeeded, want error")
	}
}

func TestSetConfigEnvVars(t *testing.T) {
	fake := newFakeKmsClient(
		v1api.PURPOSE_SYMMETRIC_ENCRYPT_DECRYPT,
		fakeVersion(1, v1api.VERSIONSTATE_ACTIVE, false),
	)

	t.Setenv(EnvStackitKmsProjectId, testProjectId)
	t.Setenv(EnvStackitKmsRegion, testRegion)
	t.Setenv(EnvStackitKmsKeyRingId, testKeyRingId)
	t.Setenv(EnvStackitKmsKeyId, testKeyId)

	w := NewWrapper()
	var gotConfig clientConfig
	w.newClient = func(cc clientConfig) (kmsClient, error) {
		gotConfig = cc
		return fake, nil
	}
	if _, err := w.SetConfig(context.Background()); err != nil {
		t.Fatalf("SetConfig from environment failed: %v", err)
	}
	if gotConfig.projectId != testProjectId || gotConfig.region != testRegion || gotConfig.keyRingId != testKeyRingId {
		t.Fatalf("client config = %+v, want values from environment", gotConfig)
	}

	// With WithDisallowEnvVars the same environment must not be consulted.
	w = NewWrapper()
	w.newClient = func(clientConfig) (kmsClient, error) { return fake, nil }
	if _, err := w.SetConfig(context.Background(), wrapping.WithDisallowEnvVars(true)); err == nil {
		t.Fatal("SetConfig with WithDisallowEnvVars and no config succeeded, want error")
	}
}

func TestSetConfigMetadata(t *testing.T) {
	fake := newFakeKmsClient(
		v1api.PURPOSE_SYMMETRIC_ENCRYPT_DECRYPT,
		fakeVersion(1, v1api.VERSIONSTATE_ACTIVE, false),
	)
	w := NewWrapper()
	w.newClient = func(clientConfig) (kmsClient, error) { return fake, nil }
	cfg, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(testConfigMap(nil)))
	if err != nil {
		t.Fatalf("SetConfig failed: %v", err)
	}

	want := map[string]string{
		"project_id":  testProjectId,
		"region":      testRegion,
		"key_ring_id": testKeyRingId,
		"key_id":      testKeyId,
		"key_version": "1",
	}
	for k, v := range want {
		if cfg.Metadata[k] != v {
			t.Errorf("metadata[%q] = %q, want %q", k, cfg.Metadata[k], v)
		}
	}
	for _, secret := range []string{"token", "service_account_key", "private_key"} {
		if _, ok := cfg.Metadata[secret]; ok {
			t.Errorf("metadata leaks %q", secret)
		}
	}
}

func TestDecryptRejectsForeignBlob(t *testing.T) {
	fake := newFakeKmsClient(
		v1api.PURPOSE_SYMMETRIC_ENCRYPT_DECRYPT,
		fakeVersion(1, v1api.VERSIONSTATE_ACTIVE, false),
	)
	w := testWrapper(t, fake, nil)
	ctx := context.Background()

	if _, err := w.Decrypt(ctx, nil); err == nil {
		t.Fatal("Decrypt of nil blob succeeded, want error")
	}
	if _, err := w.Decrypt(ctx, &wrapping.BlobInfo{Ciphertext: []byte("x")}); err == nil {
		t.Fatal("Decrypt of blob without key info succeeded, want error")
	}
	blob := &wrapping.BlobInfo{
		Ciphertext: []byte("x"),
		KeyInfo:    &wrapping.KeyInfo{Mechanism: 0xdead, WrappedKey: []byte("y")},
	}
	if _, err := w.Decrypt(ctx, blob); err == nil {
		t.Fatal("Decrypt of blob with foreign mechanism succeeded, want error")
	}
}

func TestUnconfiguredWrapper(t *testing.T) {
	w := NewWrapper()
	ctx := context.Background()
	if _, err := w.Encrypt(ctx, []byte("x")); err == nil {
		t.Fatal("Encrypt on unconfigured wrapper succeeded, want error")
	}
	if _, err := w.Decrypt(ctx, &wrapping.BlobInfo{}); err == nil {
		t.Fatal("Decrypt on unconfigured wrapper succeeded, want error")
	}
}

func TestParseKeyVersionId(t *testing.T) {
	keyId, version, ok := parseKeyVersionId(testKeyId + "/7")
	if !ok || keyId != testKeyId || version != 7 {
		t.Fatalf("parseKeyVersionId = (%q, %d, %t), want (%q, 7, true)", keyId, version, ok, testKeyId)
	}

	for _, bad := range []string{"", testKeyId, testKeyId + "/", testKeyId + "/x", testKeyId + "/0", testKeyId + "/-1", "/1"} {
		if _, _, ok := parseKeyVersionId(bad); ok {
			t.Errorf("parseKeyVersionId(%q) ok = true, want false", bad)
		}
	}
}
