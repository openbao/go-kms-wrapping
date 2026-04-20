// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/keybuilder"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/stretchr/testify/require"
)

func TestOAEP(t *testing.T) {
	ctx := t.Context()
	svc := NewTestKMS(t)

	// Generate an RSA key:
	label := rand.Text()
	require.NoError(t, svc.pool.Scope(ctx, func(s *session.Handle) error {
		_, _, err := s.GenerateKeyPair(keybuilder.RSA(4096).Label(label).Build())
		return err
	}))

	hashes := []string{"default", "sha1", "sha224", "sha256", "sha384", "sha512"}
	if svc.token.Info.ManufacturerID == "SoftHSM project" {
		// SoftHSM only supports OAEP over SHA-1, special case it here.
		hashes = []string{"sha1"}
	}

	roundtrip := func(t *testing.T, key kms.Key) {
		t.Helper()
		input := []byte("foobar")
		ciphertext, err := key.Encrypt(ctx, &kms.CipherOptions{Data: input})
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)
		require.NotEqual(t, input, ciphertext)
		plaintext, err := key.Decrypt(ctx, &kms.CipherOptions{Data: ciphertext})
		require.NoError(t, err)
		require.Equal(t, input, plaintext)
	}

	for name, config := range map[string]kms.ConfigMap{
		"software": {
			"disable_software_encryption": false,
		},
		"hardware": {
			"disable_software_encryption": true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, hash := range hashes {
				t.Run(hash, func(t *testing.T) {
					svc := NewTestKMS(t, config)
					// Retrieve the key via GetKey from a KMS with above
					// parameters set:
					config := kms.ConfigMap{"label": label}
					if hash != "default" {
						config["rsa_oaep_hash"] = hash
					}
					key, err := svc.GetKey(ctx, &kms.KeyOptions{ConfigMap: config})
					require.NoError(t, err)
					require.IsType(t, &rsaKey{}, key)
					roundtrip(t, key)
				})
			}
		})
	}
}

func TestPSS(t *testing.T) {
	ctx := t.Context()
	svc := NewTestKMS(t)

	// Generate an RSA key:
	label := rand.Text()
	require.NoError(t, svc.pool.Scope(ctx, func(s *session.Handle) error {
		_, _, err := s.GenerateKeyPair(keybuilder.RSA(4096).Label(label).Build())
		return err
	}))

	// Retrieve it via GetKey:
	key, err := svc.GetKey(ctx, &kms.KeyOptions{
		ConfigMap: kms.ConfigMap{"label": label}})
	require.NoError(t, err)
	require.IsType(t, &rsaKey{}, key)

	hashes := map[crypto.Hash]x509.SignatureAlgorithm{
		crypto.SHA256: x509.SHA256WithRSAPSS,
		crypto.SHA384: x509.SHA384WithRSAPSS,
		crypto.SHA512: x509.SHA512WithRSAPSS,
	}

	for hash, algo := range hashes {
		t.Run(hash.String(), func(t *testing.T) {
			t.Run("Sign+Verify", func(t *testing.T) {
				opts := &rsa.PSSOptions{
					Hash:       hash,
					SaltLength: rsa.PSSSaltLengthAuto,
				}

				h := hash.New()
				_, _ = h.Write([]byte("foo"))
				digest := h.Sum(nil)

				// Plain message:
				o := &kms.SignOptions{
					Data:       []byte("foo"),
					SignerOpts: opts,
				}
				signature, err := key.Sign(ctx, o)
				require.NoError(t, err)
				require.NotEmpty(t, signature)
				require.NoError(t, key.Verify(ctx, &kms.VerifyOptions{
					Data:       o.Data,
					SignerOpts: opts,
					Signature:  signature,
				}))

				// Pre-hashed:
				o = &kms.SignOptions{
					Data:       digest,
					Prehashed:  true,
					SignerOpts: opts,
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
					SignatureAlgorithm:    algo,
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
