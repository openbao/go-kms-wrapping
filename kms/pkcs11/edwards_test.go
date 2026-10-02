// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/keybuilder"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/stretchr/testify/require"
)

func TestEd25519(t *testing.T) {
	ctx := t.Context()
	svc := NewTestKMS(t)

	// Generate an Ed25519 key:
	label := rand.Text()
	require.NoError(t, svc.pool.Scope(ctx, func(s *session.Handle) error {
		_, _, err := s.GenerateKeyPair(keybuilder.Ed25519().Label(label).Build())
		return err
	}))

	// Retrieve it via GetKey:
	key, err := svc.GetKey(ctx, &kms.KeyOptions{
		ConfigMap: kms.ConfigMap{"label": label},
	})
	require.NoError(t, err)
	require.IsType(t, &edwardsKey{}, key)

	t.Run("Sign+Verify", func(t *testing.T) {
		o := &kms.SignOptions{
			Data:       []byte("foo"),
			SignerOpts: crypto.Hash(0),
		}
		signature, err := key.Sign(ctx, o)
		require.NoError(t, err)
		require.Len(t, signature, ed25519.SignatureSize)

		require.NoError(t, key.Verify(ctx, &kms.VerifyOptions{
			Data:       o.Data,
			SignerOpts: o.SignerOpts,
			Signature:  signature,
		}))

		require.ErrorIs(t, key.Verify(ctx, &kms.VerifyOptions{
			Data:       []byte("bar"),
			SignerOpts: o.SignerOpts,
			Signature:  signature,
		}), kms.ErrInvalidSignature)
	})

	t.Run("x509", func(t *testing.T) {
		signer, err := kms.NewSigner(ctx, key)
		require.NoError(t, err)
		template := &x509.Certificate{
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		certBytes, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(certBytes)
		require.NoError(t, err)
		err = cert.CheckSignatureFrom(cert)
		require.NoError(t, err)
	})

	t.Run("Unsupported", func(t *testing.T) {
		// Ed25519ph & Ed25519ctx are not available:
		o := &kms.SignOptions{
			Data:       []byte("foo"),
			Prehashed:  true,
			SignerOpts: crypto.SHA256,
		}
		_, err := key.Sign(ctx, o)
		require.ErrorContains(t, err, "pre-hashed EdDSA is not supported")
		err = key.Verify(ctx, &kms.VerifyOptions{
			Data:       o.Data,
			Prehashed:  true,
			SignerOpts: o.SignerOpts,
			Signature:  make([]byte, ed25519.SignatureSize),
		})
		require.ErrorContains(t, err, "pre-hashed EdDSA is not supported")

		_, err = key.Sign(ctx, &kms.SignOptions{
			Data:       []byte("foo"),
			SignerOpts: &ed25519.Options{Hash: crypto.Hash(0), Context: "context"},
		})
		require.ErrorContains(t, err, "Ed25519ctx is not supported")
	})
}

func TestEd448(t *testing.T) {
	ctx := t.Context()
	svc := NewTestKMS(t)

	// Generate an Ed448 key:
	label := rand.Text()
	require.NoError(t, svc.pool.Scope(ctx, func(s *session.Handle) error {
		_, _, err := s.GenerateKeyPair(keybuilder.Ed448().Label(label).Build())
		return err
	}))

	// Retrieve it via GetKey:
	key, err := svc.GetKey(ctx, &kms.KeyOptions{
		ConfigMap: kms.ConfigMap{"label": label},
	})
	require.NoError(t, err)
	require.IsType(t, &edwardsKey{}, key)

	_, err = key.ExportPublic(ctx)
	require.ErrorContains(t, err, "supports only Ed25519")

	if svc.token.Info.ManufacturerID == "Kryoptic Project" {
		t.Skip("Kryoptic does not support Ed448 signing")
	}

	o := &kms.SignOptions{
		Data:       []byte("foo"),
		SignerOpts: crypto.Hash(0),
	}
	signature, err := key.Sign(ctx, o)
	require.NoError(t, err)
	require.Len(t, signature, 114)
}
