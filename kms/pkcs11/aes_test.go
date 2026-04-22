// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"crypto/rand"
	"testing"

	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/keybuilder"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/stretchr/testify/require"
)

func TestGCM(t *testing.T) {
	ctx := t.Context()
	svc := NewTestKMS(t)

	// Generate an AES key:
	label := rand.Text()
	require.NoError(t, svc.pool.Scope(ctx, func(s *session.Handle) error {
		_, err := s.GenerateKey(keybuilder.AES(32).Label(label).Build())
		return err
	}))

	// Retrieve it via GetKey:
	key, err := svc.GetKey(ctx, &kms.KeyOptions{
		ConfigMap: kms.ConfigMap{"label": label}})
	require.NoError(t, err)
	require.IsType(t, aesKey{}, key)

	roundtrip := func(t *testing.T, key kms.Key, input, aad []byte) {
		t.Helper()
		opts := &kms.CipherOptions{Data: input, AAD: aad}
		ciphertext, err := key.Encrypt(ctx, opts)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)
		require.NotEqual(t, input, ciphertext)
		plaintext, err := key.Decrypt(ctx, &kms.CipherOptions{
			Data: ciphertext, AAD: aad, Nonce: opts.Nonce})
		require.NoError(t, err)
		require.Equal(t, input, plaintext)
	}

	input, aad := []byte("foobar"), []byte("baz")
	t.Run("aad", func(t *testing.T) { roundtrip(t, key, input, aad) })
	t.Run("no-aad", func(t *testing.T) { roundtrip(t, key, input, nil) })
}
