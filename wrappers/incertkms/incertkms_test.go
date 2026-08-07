// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package incertkms

import (
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIncertKmsWrapper(t *testing.T) {
	_, srv := newIncertKmsTestWrapper()
	defer srv.Close()
}

func TestIncertKmsWrapper_Type(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	w, srv := newIncertKmsTestWrapper()
	defer srv.Close()

	typ, err := w.Type(t.Context())
	require.NoError(err)
	assert.Equal(Type, typ)
}

func TestIncertKmsWrapper_Lifecycle(t *testing.T) {
	w, srv := newIncertKmsTestWrapper()
	defer srv.Close()
	testEncryptionRoundTrip(t, w)
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

func TestIncertKmsWrapper_Encrypt_NilPlaintext(t *testing.T) {
	require := require.New(t)
	w, srv := newIncertKmsTestWrapper()
	defer srv.Close()

	_, err := w.Encrypt(t.Context(), nil)
	require.Error(err, "expected error for nil plaintext")
}

func TestIncertKmsWrapper_Decrypt_NilInput(t *testing.T) {
	require := require.New(t)
	w, srv := newIncertKmsTestWrapper()
	defer srv.Close()

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
