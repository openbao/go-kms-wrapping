// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package scalewaykms

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync/atomic"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	keymanager "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
	"github.com/stretchr/testify/require"
)

// fakeKeyManager is an in-memory stand-in for the Scaleway Key Manager API. It
// "wraps" a data key by base64-encoding it with a fixed prefix, which is enough
// to exercise the wrapper's envelope round-trip without real credentials.
type fakeKeyManager struct {
	keyID string
}

const testKeyID = "11111111-1111-1111-1111-111111111111"
const fakeWrapPrefix = "scw-wrapped:"

func (f *fakeKeyManager) Encrypt(req *keymanager.EncryptRequest, _ ...scw.RequestOption) (*keymanager.EncryptResponse, error) {
	ct := append([]byte(fakeWrapPrefix), []byte(base64.StdEncoding.EncodeToString(req.Plaintext))...)
	return &keymanager.EncryptResponse{KeyID: f.keyID, Ciphertext: ct}, nil
}

func (f *fakeKeyManager) Decrypt(req *keymanager.DecryptRequest, _ ...scw.RequestOption) (*keymanager.DecryptResponse, error) {
	trimmed := bytes.TrimPrefix(req.Ciphertext, []byte(fakeWrapPrefix))
	pt, err := base64.StdEncoding.DecodeString(string(trimmed))
	if err != nil {
		return nil, err
	}
	return &keymanager.DecryptResponse{KeyID: f.keyID, Plaintext: pt}, nil
}

func (f *fakeKeyManager) GetKey(req *keymanager.GetKeyRequest, _ ...scw.RequestOption) (*keymanager.Key, error) {
	algo := keymanager.KeyAlgorithmSymmetricEncryptionAes256Gcm
	usage := &keymanager.KeyUsage{SymmetricEncryption: &algo}
	return &keymanager.Key{ID: req.KeyID, Usage: usage, State: keymanager.KeyStateEnabled}, nil
}

func newTestWrapper(t *testing.T) *Wrapper {
	t.Helper()
	k := &Wrapper{
		keyId:        testKeyID,
		region:       scw.RegionFrPar,
		currentKeyId: new(atomic.Value),
		client:       &fakeKeyManager{keyID: testKeyID},
	}
	k.currentKeyId.Store(k.keyId)
	return k
}

func TestScalewayKmsWrapper_Type(t *testing.T) {
	k := newTestWrapper(t)
	typ, err := k.Type(context.Background())
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	if typ != Type {
		t.Fatalf("expected %q, got %q", Type, typ)
	}
}

func TestScalewayKmsWrapper_EncryptDecrypt(t *testing.T) {
	k := newTestWrapper(t)
	ctx := context.Background()

	input := []byte("a-master-key-to-wrap")
	blob, err := k.Encrypt(ctx, input)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	if bytes.Equal(input, blob.Ciphertext) {
		t.Fatal("ciphertext should differ from input")
	}
	if blob.KeyInfo == nil || len(blob.KeyInfo.WrappedKey) == 0 {
		t.Fatal("expected a wrapped data key in the blob key info")
	}

	pt, err := k.Decrypt(ctx, blob)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	if !bytes.Equal(input, pt) {
		t.Fatalf("expected %q, got %q", input, pt)
	}
}

func TestScalewayKmsWrapper_EncryptIsNonDeterministic(t *testing.T) {
	k := newTestWrapper(t)
	ctx := context.Background()

	input := make([]byte, 32)
	if _, err := rand.Read(input); err != nil {
		t.Fatalf("err: %s", err)
	}

	blob1, err := k.Encrypt(ctx, input)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	blob2, err := k.Encrypt(ctx, input)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	if bytes.Equal(blob1.Ciphertext, blob2.Ciphertext) {
		t.Fatal("re-encrypting the same input should produce a different ciphertext")
	}
}

func TestScalewayKmsWrapper_DecryptRejectsCorruptedInput(t *testing.T) {
	k := newTestWrapper(t)
	ctx := context.Background()

	blob, err := k.Encrypt(ctx, []byte("foo"))
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	corrupted := &wrapping.BlobInfo{
		Ciphertext: bytes.Clone(blob.Ciphertext),
		Iv:         blob.Iv,
		KeyInfo:    blob.KeyInfo,
	}
	corrupted.Ciphertext[0] ^= 0xff
	if _, err := k.Decrypt(ctx, corrupted); err == nil {
		t.Fatal("decrypting corrupted ciphertext should return an error")
	}
}

func TestScalewayKmsWrapper_DecryptRejectsNilKeyInfo(t *testing.T) {
	k := newTestWrapper(t)
	if _, err := k.Decrypt(context.Background(), &wrapping.BlobInfo{}); err == nil {
		t.Fatal("decrypting with nil key info should return an error")
	}
}

func TestScalewayKmsWrapper_ConfigFromEnv(t *testing.T) {
	const envProject = "44444444-4444-4444-4444-444444444444"

	for _, tc := range []struct {
		name        string
		cfg         map[string]string
		wantRegion  scw.Region
		wantProject string
	}{
		{
			name:        "env supplies region and project",
			cfg:         map[string]string{"key_id": testKeyID},
			wantRegion:  scw.RegionNlAms,
			wantProject: envProject,
		},
		{
			name:        "config map overrides env",
			cfg:         map[string]string{"key_id": testKeyID, "region": "fr-par"},
			wantRegion:  scw.RegionFrPar,
			wantProject: envProject,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SCW_CONFIG_PATH", t.TempDir()+"/absent.yaml")
			t.Setenv("SCW_ACCESS_KEY", "SCWXXXXXXXXXXXXXXXXX")
			t.Setenv("SCW_SECRET_KEY", "22222222-2222-2222-2222-222222222222")
			t.Setenv("SCW_DEFAULT_REGION", "nl-ams")
			t.Setenv("SCW_DEFAULT_PROJECT_ID", envProject)

			opts, err := getOpts(wrapping.WithConfigMap(tc.cfg))
			require.NoError(t, err)

			client, region, projectID, err := getScalewayKeyManagerClient(opts)
			require.NoError(t, err)
			require.NotNil(t, client)
			require.Equal(t, tc.wantRegion, region)
			require.Equal(t, tc.wantProject, projectID)
		})
	}
}

func TestScalewayKmsWrapper_DisallowEnvVars(t *testing.T) {
	base := map[string]string{
		"key_id":     testKeyID,
		"access_key": "SCWYYYYYYYYYYYYYYYYY",
		"secret_key": "33333333-3333-3333-3333-333333333333",
	}

	for _, tc := range []struct {
		name     string
		disallow bool
		wantErr  bool
		want     scw.Region
	}{
		{name: "env allowed", disallow: false, want: scw.RegionNlAms},
		{name: "env disallowed", disallow: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SCW_ACCESS_KEY", "SCWXXXXXXXXXXXXXXXXX")
			t.Setenv("SCW_SECRET_KEY", "22222222-2222-2222-2222-222222222222")
			t.Setenv("SCW_DEFAULT_REGION", "nl-ams")

			opts, err := getOpts(
				wrapping.WithDisallowEnvVars(tc.disallow),
				wrapping.WithConfigMap(base))
			require.NoError(t, err)

			_, region, _, err := getScalewayKeyManagerClient(opts)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, region)
		})
	}
}
