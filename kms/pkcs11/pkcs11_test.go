// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/keybuilder"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/testvars"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/stretchr/testify/require"
)

// NewTestKMS returns a KMS for testing.
func NewTestKMS(t *testing.T, configs ...kms.ConfigMap) *pkcs11KMS {
	svc := &pkcs11KMS{}
	lib, token, pin := testvars.Vars(t)

	config := kms.ConfigMap{
		"lib":   lib,
		"pin":   pin,
		"token": token,
	}
	for _, c := range configs {
		maps.Copy(config, c)
	}

	require.NoError(t, svc.Open(t.Context(), &kms.OpenOptions{
		ConfigMap: config,
	}))
	t.Cleanup(func() {
		require.NoError(t, svc.Close(context.Background()))
	})

	return svc
}

func TestOpen(t *testing.T) {
	ctx := t.Context()

	// Instantiate this just to grab token info.
	svc := NewTestKMS(t)

	slot := svc.token.ID
	serial := svc.token.Info.SerialNumber
	lib, token, pin := testvars.Vars(t)

	good := []kms.ConfigMap{
		{"lib": lib, "slot": slot, "pin": pin},
		{"lib": lib, "slot": strconv.FormatUint(uint64(slot), 10), "pin": pin},
		{"lib": lib, "slot": "0x" + strconv.FormatUint(uint64(slot), 16), "pin": pin},
		{"lib": lib, "token": token, "pin": pin},
		{"lib": lib, "serial": serial, "pin": pin},
		{"lib": lib, "slot": slot, "token": token, "serial": serial, "pin": pin},
		{"lib": lib, "slot": slot, "pin": pin, "disable_software_encryption": true},
		{"lib": lib, "slot": slot, "pin": pin, "disable_software_encryption": false},
		{"lib": lib, "slot": slot, "pin": pin, "disable_software_encryption": "1"},
	}

	bad := []kms.ConfigMap{
		{"lib": lib, "pin": pin},
		{"lib": "", "token": token, "pin": pin},
		{"lib": "/dev/null", "token": token, "pin": pin},
		{"lib": lib, "token": token, "pin": "bogus"},
		{"lib": lib, "serial": "bogus", "pin": pin},
		{"lib": lib, "slot": slot, "pin": pin, "disable_software_encryption": "foo"},
	}

	for i, config := range good {
		t.Run(fmt.Sprintf("good[%d]", i), func(t *testing.T) {
			svc := New()
			require.NoError(t, svc.Open(ctx, &kms.OpenOptions{ConfigMap: config}))
			require.NoError(t, svc.Close(ctx))
		})
	}

	for i, config := range bad {
		t.Run(fmt.Sprintf("bad[%d]", i), func(t *testing.T) {
			require.Error(t, New().Open(ctx, &kms.OpenOptions{ConfigMap: config}))
		})
	}
}

func TestGetKey(t *testing.T) {
	ctx := t.Context()
	svc := NewTestKMS(t)

	t.Run("SecretKey", func(t *testing.T) {
		label := rand.Text()
		require.NoError(t, svc.pool.Scope(ctx, func(s *session.Handle) error {
			_, err := s.GenerateKey(keybuilder.AES(32).Label(label).Build())
			return err
		}))

		// By label:
		key, err := svc.GetKey(ctx, &kms.KeyOptions{ConfigMap: kms.ConfigMap{"label": label}})
		require.NoError(t, err)
		require.IsType(t, aesKey{}, key)
	})

	t.Run("KeyPair", func(t *testing.T) {
		// A key pair equal IDs.
		id, label := rand.Text(), rand.Text()
		require.NoError(t, svc.pool.Scope(ctx, func(s *session.Handle) error {
			_, _, err := s.GenerateKeyPair(keybuilder.EC(keybuilder.CurveP256).ID(id).Label(label).Build())
			return err
		}))

		// By ID:
		key, err := svc.GetKey(ctx, &kms.KeyOptions{ConfigMap: kms.ConfigMap{"id": id}})
		require.NoError(t, err)
		require.IsType(t, &ecKey{}, key)

		// By label:
		key, err = svc.GetKey(ctx, &kms.KeyOptions{ConfigMap: kms.ConfigMap{"label": label}})
		require.NoError(t, err)
		require.IsType(t, &ecKey{}, key)

		// By ID and label:
		key, err = svc.GetKey(ctx, &kms.KeyOptions{ConfigMap: kms.ConfigMap{
			"id": id, "label": label,
		}})
		require.NoError(t, err)
		require.IsType(t, &ecKey{}, key)
	})

	t.Run("KeyPairMismatchedLabels", func(t *testing.T) {
		// A key pair with equal IDs, but mismatched labels.
		id, label1, label2 := rand.Text(), rand.Text(), rand.Text()
		require.NoError(t, svc.pool.Scope(ctx, func(s *session.Handle) error {
			_, _, err := s.GenerateKeyPair(
				keybuilder.EC(keybuilder.CurveP256).
					ID(id).
					PublicAttribute(pkcs11.CKA_LABEL, label1).
					PrivateAttribute(pkcs11.CKA_LABEL, label2).
					Build(),
			)
			return err
		}))

		// Find by ID:
		key, err := svc.GetKey(ctx, &kms.KeyOptions{ConfigMap: kms.ConfigMap{"id": id}})
		require.NoError(t, err)
		require.IsType(t, &ecKey{}, key)

		// Find by private key label:
		key, err = svc.GetKey(ctx, &kms.KeyOptions{ConfigMap: kms.ConfigMap{"label": label2}})
		require.NoError(t, err)
		require.IsType(t, &ecKey{}, key)

		// Find by public key label, shouldn't work:
		key, err = svc.GetKey(ctx, &kms.KeyOptions{ConfigMap: kms.ConfigMap{"label": label1}})
		require.Error(t, err)
		require.Nil(t, key)
	})

	t.Run("Weird", func(t *testing.T) {
		// A secret key and a key pair where the secret key and private key
		// match labels, but the public key doesn't.
		label1, label2 := rand.Text(), rand.Text()
		require.NoError(t, svc.pool.Scope(ctx, func(s *session.Handle) error {
			_, err1 := s.GenerateKey(keybuilder.AES(32).Label(label2).Build())
			_, _, err2 := s.GenerateKeyPair(
				keybuilder.EC(keybuilder.CurveP256).
					PublicAttribute(pkcs11.CKA_LABEL, label1).
					PrivateAttribute(pkcs11.CKA_LABEL, label2).
					Build(),
			)
			return errors.Join(err1, err2)
		}))

		// This finds the public key only, which is invalid:
		key, err := svc.GetKey(ctx, &kms.KeyOptions{ConfigMap: kms.ConfigMap{"label": label1}})
		require.Error(t, err)
		require.Nil(t, key)

		// This finds the secret key + private key, which is invalid:
		key, err = svc.GetKey(ctx, &kms.KeyOptions{ConfigMap: kms.ConfigMap{"label": label2}})
		require.Error(t, err)
		require.Nil(t, key)
	})
}
