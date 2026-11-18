// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package incertkms

import (
	"testing"

	"github.com/google/uuid"
	kmssdk "github.com/incert-kms/kms-sdk-go"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIncertKmsWrapper(t *testing.T) {
	newIncertKmsTestWrapper(t)
}

func TestIncertKmsWrapper_Type(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	w := newIncertKmsTestWrapper(t)

	typ, err := w.Type(t.Context())
	require.NoError(err)
	assert.Equal(Type, typ)
}

func TestIncertKmsWrapper_Lifecycle(t *testing.T) {
	w := newIncertKmsTestWrapper(t)
	testEncryptionRoundTrip(t, w)
	require.NoError(t, w.Finalize(t.Context()))
}

func TestIncertKmsWrapper_SetConfig_RequiredFields(t *testing.T) {
	cases := []struct {
		name    string
		config  map[string]string
		wantErr string
	}{
		{
			name:    "missing username",
			config:  nil,
			wantErr: "username is required",
		},
		{
			name: "missing password",
			config: map[string]string{
				"url":      "http://localhost:3000",
				"username": "opo",
			},
			wantErr: "password is required",
		},
		{
			name: "invalid vslot uuid",
			config: map[string]string{
				"url":      "http://localhost:3000",
				"username": "opo",
				"password": "Parizer1!",
				"vslot":    "not-a-uuid",
			},
			wantErr: "invalid vslot format",
		},
		{
			name: "invalid key uuid",
			config: map[string]string{
				"url":      "http://localhost:3000",
				"username": "opo",
				"password": "Parizer1!",
				"key":      "not-a-uuid",
			},
			wantErr: "invalid key format",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			w := NewWrapper()
			_, err := w.SetConfig(t.Context(), wrapping.WithConfigMap(tc.config))
			require.Error(err)
			require.ErrorContains(err, tc.wantErr)
		})
	}
}

func TestIncertKmsWrapper_KeyByName(t *testing.T) {
	aesKey := func(name string) kmssdk.KeySearchResult {
		return kmssdk.KeySearchResult{ID: uuid.New(), Name: name, AlgType: "AES"}
	}

	cases := []struct {
		name    string
		results []kmssdk.KeySearchResult
		want    int // index into results of the key that must be selected
		wantErr string
	}{
		{
			name:    "exact match selected",
			results: []kmssdk.KeySearchResult{aesKey(incertkmsTestKeyName)},
			want:    0,
		},
		{
			name: "newest exact match wins over partial matches",
			results: []kmssdk.KeySearchResult{
				aesKey(incertkmsTestKeyName + "-rotated"),
				aesKey(incertkmsTestKeyName),
				aesKey(incertkmsTestKeyName),
			},
			want: 1,
		},
		{
			name:    "no keys",
			results: nil,
			wantErr: "no key named",
		},
		{
			name:    "partial name match ignored",
			results: []kmssdk.KeySearchResult{aesKey(incertkmsTestKeyName + "-old")},
			wantErr: "no key named",
		},
		{
			name: "non-AES key rejected",
			results: []kmssdk.KeySearchResult{
				{ID: uuid.New(), Name: incertkmsTestKeyName, AlgType: "RSA"},
			},
			wantErr: "unsupported algorithm type",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			f := newFakeKMS(t)
			f.searchResults = tc.results

			w := NewWrapper()
			_, err := w.SetConfig(t.Context(), wrapping.WithConfigMap(f.config(map[string]string{
				"key_name": incertkmsTestKeyName,
			})))
			if tc.wantErr != "" {
				require.ErrorContains(err, tc.wantErr)
				return
			}
			require.NoError(err)

			id, err := w.KeyId(t.Context())
			require.NoError(err)
			require.Equal(tc.results[tc.want].ID.String(), id)
		})
	}
}

func TestIncertKmsWrapper_Encrypt_NilPlaintext(t *testing.T) {
	require := require.New(t)
	w := newIncertKmsTestWrapper(t)

	_, err := w.Encrypt(t.Context(), nil)
	require.Error(err, "expected error for nil plaintext")
}

func TestIncertKmsWrapper_Decrypt_NilInput(t *testing.T) {
	require := require.New(t)
	w := newIncertKmsTestWrapper(t)

	_, err := w.Decrypt(t.Context(), nil)
	require.Error(err, "expected error for nil input")
}

func TestIncertKmsWrapper_Unconfigured(t *testing.T) {
	require := require.New(t)
	w := NewWrapper()

	_, err := w.Encrypt(t.Context(), []byte("foo"))
	require.Error(err, "expected error when wrapper is unconfigured")

	_, err = w.Decrypt(t.Context(), &wrapping.BlobInfo{})
	require.Error(err, "expected error when wrapper is unconfigured")

	require.NoError(w.Finalize(t.Context()), "Finalize on an unconfigured wrapper should be a no-op")
}

func testEncryptionRoundTrip(t *testing.T, w *Wrapper) {
	t.Helper()
	require := require.New(t)
	ctx := t.Context()
	input := []byte("foo")
	swi, err := w.Encrypt(ctx, input, nil)
	require.NoError(err)

	pt, err := w.Decrypt(ctx, swi, nil)
	require.NoError(err)

	require.Equal(input, pt)
}
