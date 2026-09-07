// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/keybuilder"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/testvars"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

func TestWrapper(t *testing.T) {
	ctx := t.Context()
	lib, token, pin := testvars.Vars(t)

	roundtrip := func(t *testing.T, config map[string]string) {
		t.Helper()

		wrapper := NewWrapper().(interface {
			wrapping.Wrapper
			wrapping.InitFinalizer
		})

		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(config))
		require.NoError(t, err)
		defer func() {
			require.NoError(t, wrapper.Finalize(ctx))
		}()

		input := []byte("foobar")

		ciphertext0, err := wrapper.Encrypt(ctx, input)
		require.NoError(t, err)
		require.NotEqual(t, ciphertext0, input)

		ciphertext1, err := wrapper.Encrypt(ctx, input)
		require.NoError(t, err)
		require.NotEqual(t, ciphertext1, input)
		require.NotEqual(t, ciphertext1, ciphertext0)

		plaintext0, err := wrapper.Decrypt(ctx, ciphertext0)
		require.NoError(t, err)
		require.Equal(t, input, plaintext0)

		plaintext1, err := wrapper.Decrypt(ctx, ciphertext1)
		require.NoError(t, err)
		require.Equal(t, input, plaintext1)
	}

	t.Run("AES-GCM", func(t *testing.T) {
		label := rand.Text()

		// Generate an AES key:
		require.NoError(t, NewTestKMS(t).pool.Scope(ctx, func(s *session.Handle) error {
			_, err := s.GenerateKey(keybuilder.AES(32).Label(label).Build())
			return err
		}))

		roundtrip(t, map[string]string{
			"lib":         lib,
			"pin":         pin,
			"token_label": token,
			"key_label":   label,
		})
	})

	t.Run("RSA-OAEP", func(t *testing.T) {
		label := rand.Text()
		svc := NewTestKMS(t)

		// Generate an RSA key:
		require.NoError(t, svc.pool.Scope(ctx, func(s *session.Handle) error {
			_, _, err := s.GenerateKeyPair(keybuilder.RSA(4096).Label(label).Build())
			return err
		}))

		hash := "sha256"
		if svc.token.Info.ManufacturerID == "SoftHSM project" {
			hash = "sha1"
		}

		t.Run("software", func(t *testing.T) {
			roundtrip(t, map[string]string{
				"lib":           lib,
				"pin":           pin,
				"token_label":   token,
				"key_label":     label,
				"rsa_oaep_hash": hash,
			})
		})

		t.Run("hardware", func(t *testing.T) {
			roundtrip(t, map[string]string{
				"lib":                         lib,
				"pin":                         pin,
				"token_label":                 token,
				"key_label":                   label,
				"rsa_oaep_hash":               hash,
				"disable_software_encryption": "true",
			})
		})
	})

	t.Run("Rotation", func(t *testing.T) {
		label1, label2 := rand.Text(), rand.Text()

		// Generate two AES keys:
		require.NoError(t, NewTestKMS(t).pool.Scope(ctx, func(s *session.Handle) error {
			_, err1 := s.GenerateKey(keybuilder.AES(32).Label(label1).Build())
			_, err2 := s.GenerateKey(keybuilder.AES(32).Label(label2).Build())
			return errors.Join(err1, err2)
		}))

		var err error

		// Create a wrapper over each key:
		wrapper1 := NewWrapper().(interface {
			wrapping.Wrapper
			wrapping.InitFinalizer
		})
		_, err = wrapper1.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"lib":         lib,
			"pin":         pin,
			"token_label": token,
			"key_label":   label1,
		}))
		require.NoError(t, err)
		defer func() {
			require.NoError(t, wrapper1.Finalize(ctx))
		}()

		wrapper2 := NewWrapper().(interface {
			wrapping.Wrapper
			wrapping.InitFinalizer
		})
		_, err = wrapper2.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"lib":         lib,
			"pin":         pin,
			"token_label": token,
			"key_label":   label2,
		}))
		require.NoError(t, err)
		defer func() {
			require.NoError(t, wrapper2.Finalize(ctx))
		}()

		input := []byte("foobar")

		// Encrypt a blob with wrapper1:
		ciphertext, err := wrapper1.Encrypt(ctx, input)
		require.NoError(t, err)

		// ... then decrypt with wrapper2, even though it uses a different key
		// by default.
		plaintext, err := wrapper2.Decrypt(ctx, ciphertext)
		require.NoError(t, err)
		require.Equal(t, input, plaintext)
	})
}
