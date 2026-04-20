// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/keybuilder"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/stretchr/testify/require"
)

func TestECDSA(t *testing.T) {
	ctx := t.Context()
	svc := NewTestKMS(t)

	curves := map[string]struct {
		oid  asn1.ObjectIdentifier
		hash crypto.Hash
	}{
		"p-256": {keybuilder.CurveP256, crypto.SHA256},
		"p-384": {keybuilder.CurveP384, crypto.SHA384},
		"p-521": {keybuilder.CurveP521, crypto.SHA512},
	}

	for name, curve := range curves {
		t.Run(name, func(t *testing.T) {
			// Generate an EC key with the given curve:
			label := rand.Text()
			require.NoError(t, svc.pool.Scope(ctx, func(s *session.Handle) error {
				_, _, err := s.GenerateKeyPair(keybuilder.EC(curve.oid).Label(label).Build())
				return err
			}))

			// Retrieve it via GetKey:
			key, err := svc.GetKey(ctx, &kms.KeyOptions{
				ConfigMap: kms.ConfigMap{"label": label}})
			require.NoError(t, err)
			require.IsType(t, &ecKey{}, key)

			t.Run("Sign+Verify", func(t *testing.T) {
				h := curve.hash.New()
				_, _ = h.Write([]byte("foo"))
				digest := h.Sum(nil)

				// Plain message:
				o := &kms.SignOptions{
					Data:       []byte("foo"),
					SignerOpts: curve.hash,
				}
				signature, err := key.Sign(ctx, o)
				require.NoError(t, err)
				require.NotEmpty(t, signature)
				require.NoError(t, key.Verify(ctx, &kms.VerifyOptions{
					Data:       o.Data,
					SignerOpts: curve.hash,
					Signature:  signature,
				}))

				// Pre-hashed:
				o = &kms.SignOptions{
					Data:       digest,
					Prehashed:  true,
					SignerOpts: curve.hash,
				}
				signature, err = key.Sign(ctx, o)
				require.NoError(t, err)
				require.NotEmpty(t, signature)
				require.NoError(t, key.Verify(ctx, &kms.VerifyOptions{
					Data:       o.Data,
					Prehashed:  true,
					SignerOpts: o.SignerOpts,
					Signature:  signature,
				}))
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
		})
	}
}
