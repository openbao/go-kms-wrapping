// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/keybuilder"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/pkcs11v3"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/stretchr/testify/require"
)

func TestMLDSA(t *testing.T) {
	ctx := t.Context()
	svc := NewTestKMS(t)

	if svc.token.Info.ManufacturerID == "SoftHSM project" {
		t.Skip("SoftHSM does not support ML-DSA yet")
	}

	for params, ckp := range map[mldsa.Parameters]uint{
		mldsa.MLDSA44(): pkcs11v3.CKP_ML_DSA_44,
		mldsa.MLDSA65(): pkcs11v3.CKP_ML_DSA_65,
		mldsa.MLDSA87(): pkcs11v3.CKP_ML_DSA_87,
	} {
		t.Run(params.String(), func(t *testing.T) {
			// Generate an ML-DSA key with the given parameter set:
			label := rand.Text()
			require.NoError(t, svc.pool.Scope(ctx, func(s *session.Handle) error {
				_, _, err := s.GenerateKeyPair(keybuilder.MLDSA(ckp).Label(label).Build())
				return err
			}))

			// Retrieve it via GetKey:
			key, err := svc.GetKey(ctx, &kms.KeyOptions{
				ConfigMap: kms.ConfigMap{"label": label},
			})
			require.NoError(t, err)
			require.IsType(t, &mldsaKey{}, key)

			t.Run("Sign+Verify", func(t *testing.T) {
				o := &kms.SignOptions{
					Data:       []byte("foo"),
					SignerOpts: crypto.Hash(0),
				}
				signature, err := key.Sign(ctx, o)
				require.NoError(t, err)
				require.Len(t, signature, params.SignatureSize())
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
				// HashML-DSA, ML-DSA Mu and context are not available:
				o := &kms.SignOptions{
					Data:       []byte("foo"),
					Prehashed:  true,
					SignerOpts: crypto.SHA256,
				}
				_, err := key.Sign(ctx, o)
				require.ErrorContains(t, err, "HashML-DSA is not supported")
				err = key.Verify(ctx, &kms.VerifyOptions{
					Data:       o.Data,
					Prehashed:  true,
					SignerOpts: o.SignerOpts,
					Signature:  make([]byte, mldsa.MLDSA44SignatureSize),
				})
				require.ErrorContains(t, err, "HashML-DSA is not supported")

				_, err = key.Sign(ctx, &kms.SignOptions{
					Data:       []byte("foo"),
					SignerOpts: crypto.MLDSAMu,
				})
				require.ErrorContains(t, err, "external ML-DSA Mu is not supported")
				err = key.Verify(ctx, &kms.VerifyOptions{
					Data:       []byte("foo"),
					SignerOpts: crypto.MLDSAMu,
					Signature:  make([]byte, params.SignatureSize()),
				})
				require.ErrorContains(t, err, "external ML-DSA Mu is not supported")

				_, err = key.Sign(ctx, &kms.SignOptions{
					Data:       []byte("foo"),
					SignerOpts: &mldsa.Options{Context: "context"},
				})
				require.ErrorContains(t, err, "context parameter is not supported")
			})
		})
	}
}
