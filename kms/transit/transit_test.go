// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"path"
	"testing"
	"time"

	"github.com/openbao/go-kms-wrapping/plugin/v2"
	"github.com/openbao/go-kms-wrapping/plugin/v2/plugintest"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster/docker"
	"github.com/stretchr/testify/require"
)

func TestPlugin(t *testing.T) {
	plugintest.Server(t, &plugin.ServeOpts{
		KMSFactoryFunc: New,
	})
}

func Test(t *testing.T) {
	ctx := t.Context()
	cluster, client := setupTransitEngine(t)

	// Create keys covering most of the types available in Transit.
	// See: https://openbao.org/api-docs/secret/transit/#create-key
	for _, name := range []string{
		// Symmetric key types.
		"aes128-gcm96", "aes256-gcm96", "chacha20-poly1305", "xchacha20-poly1305",
		// Asymmetric key types.
		"rsa-4096", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "ed25519",
	} {
		_, err := client.Logical().WriteWithContext(ctx, path.Join("transit/keys", name), map[string]any{
			// Keys are named by their type so they can easily be referenced in
			// the tests below.
			"type": name,
		})
		require.NoError(t, err)
	}

	opts := &kms.OpenOptions{
		ConfigMap: kms.ConfigMap{
			"token":       client.Token(),
			"address":     client.Address(),
			"mount_path":  "transit",
			"tls_ca_cert": string(cluster.CACertPEM),
		},
	}

	t.Run("Builtin", func(t *testing.T) {
		t.Parallel()
		test(t, New(), opts)
	})

	t.Run("Plugin", func(t *testing.T) {
		t.Parallel()
		raw, err := plugintest.Client(t, "TestPlugin").Dispense("kms")
		require.NoError(t, err)
		test(t, raw.(kms.KMS), opts)
	})
}

func test(t *testing.T, k kms.KMS, opts *kms.OpenOptions) {
	ctx := t.Context()

	require.NoError(t, k.Open(ctx, opts))
	defer func() {
		require.NoError(t, k.Close(ctx))
	}()

	t.Run("Encrypt+Decrypt", func(t *testing.T) {
		input, aad := []byte("foobar"), []byte("baz")

		roundtrip := func(t *testing.T, key kms.Key, input, aad []byte) {
			t.Helper()
			opts := &kms.CipherOptions{Data: input, AAD: aad}
			ciphertext, err := key.Encrypt(ctx, opts)
			require.NoError(t, err)
			require.NotEmpty(t, ciphertext)
			require.NotEqual(t, input, ciphertext)
			plaintext, err := key.Decrypt(ctx, &kms.CipherOptions{
				Data:       ciphertext,
				AAD:        aad,
				KeyVersion: opts.KeyVersion,
			})
			require.NoError(t, err)
			require.Equal(t, input, plaintext)
		}

		for _, name := range []string{
			"aes128-gcm96", "aes256-gcm96",
			"chacha20-poly1305", "xchacha20-poly1305",
		} {
			t.Run(name, func(t *testing.T) {
				key, err := k.GetKey(ctx, &kms.KeyOptions{
					ConfigMap: kms.ConfigMap{"name": name}})
				require.NoError(t, err)
				t.Run("aad", func(t *testing.T) { roundtrip(t, key, input, aad) })
				t.Run("no-aad", func(t *testing.T) { roundtrip(t, key, input, nil) })
			})
		}

		t.Run("rsa-4096", func(t *testing.T) {
			key, err := k.GetKey(ctx, &kms.KeyOptions{
				ConfigMap: kms.ConfigMap{"name": "rsa-4096"}})
			require.NoError(t, err)
			roundtrip(t, key, input, nil)
		})
	})

	t.Run("Sign+Verify", func(t *testing.T) {
		roundtrip := func(t *testing.T, key kms.Key, sopts crypto.SignerOpts) {
			t.Helper()
			h := sopts.HashFunc().New()
			_, _ = h.Write([]byte("foo"))
			digest := h.Sum(nil)

			// Plain message:
			opts := &kms.SignOptions{
				Data:       []byte("foo"),
				SignerOpts: sopts,
			}
			signature, err := key.Sign(ctx, opts)
			require.NoError(t, err)
			require.NotEmpty(t, signature)
			require.NoError(t, key.Verify(ctx, &kms.VerifyOptions{
				Data:       opts.Data,
				SignerOpts: sopts,
				Signature:  signature,
				KeyVersion: opts.KeyVersion,
			}))

			// Pre-hashed:
			opts = &kms.SignOptions{
				Data:       digest,
				Prehashed:  true,
				SignerOpts: sopts,
			}
			signature, err = key.Sign(ctx, opts)
			require.NoError(t, err)
			require.NotEmpty(t, signature)
			require.NoError(t, key.Verify(ctx, &kms.VerifyOptions{
				Data:       opts.Data,
				Prehashed:  true,
				SignerOpts: opts.SignerOpts,
				Signature:  signature,
				KeyVersion: opts.KeyVersion,
			}))
		}

		t.Run("rsa-4096", func(t *testing.T) {
			key, err := k.GetKey(ctx, &kms.KeyOptions{
				ConfigMap: kms.ConfigMap{"name": "rsa-4096"}})
			require.NoError(t, err)
			roundtrip(t, key, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA256,
			})
		})

		for name, hash := range map[string]crypto.Hash{
			"ecdsa-p256": crypto.SHA256,
			"ecdsa-p384": crypto.SHA384,
			"ecdsa-p521": crypto.SHA512,
		} {
			t.Run(name, func(t *testing.T) {
				key, err := k.GetKey(ctx, &kms.KeyOptions{
					ConfigMap: kms.ConfigMap{"name": name}})
				require.NoError(t, err)
				roundtrip(t, key, hash)
			})
		}

		t.Run("ed25519", func(t *testing.T) {
			key, err := k.GetKey(ctx, &kms.KeyOptions{
				ConfigMap: kms.ConfigMap{"name": "ed25519"}})
			require.NoError(t, err)
			opts := &kms.SignOptions{
				Data:       []byte("foo"),
				SignerOpts: &ed25519.Options{},
			}
			signature, err := key.Sign(ctx, opts)
			require.NoError(t, err)
			require.Len(t, signature, 64)
			require.NoError(t, key.Verify(ctx, &kms.VerifyOptions{
				Data:       opts.Data,
				SignerOpts: opts.SignerOpts,
				Signature:  signature,
				KeyVersion: opts.KeyVersion,
			}))
		})

		t.Run("disable_prehashing", func(t *testing.T) {
			key, err := k.GetKey(ctx, &kms.KeyOptions{
				ConfigMap: kms.ConfigMap{
					"name":               "ecdsa-p256",
					"disable_prehashing": true,
				}})
			require.NoError(t, err)
			h := crypto.SHA256.New()
			_, _ = h.Write([]byte("foo"))
			digest := h.Sum(nil)
			_, err = key.Sign(ctx, &kms.SignOptions{
				Data:       digest,
				Prehashed:  true,
				SignerOpts: crypto.SHA256,
			})
			require.ErrorContains(t, err, ErrPrehashingDisabled.Error())
		})
	})

	t.Run("ExportPublic", func(t *testing.T) {
		tests := map[string]any{
			"rsa-4096":   &rsa.PublicKey{},
			"ecdsa-p256": &ecdsa.PublicKey{},
			"ecdsa-p384": &ecdsa.PublicKey{},
			"ecdsa-p521": &ecdsa.PublicKey{},
			"ed25519":    ed25519.PublicKey{},
		}
		for name, want := range tests {
			t.Run(name, func(t *testing.T) {
				key, err := k.GetKey(ctx, &kms.KeyOptions{
					ConfigMap: kms.ConfigMap{"name": name}})
				require.NoError(t, err)
				pub, err := key.ExportPublic(ctx)
				require.NoError(t, err)
				require.IsType(t, want, pub)
			})
		}

		// Sanity check, this should of course fail as AES keys have no public
		// part.
		t.Run("aes256-gcm96", func(t *testing.T) {
			key, err := k.GetKey(ctx, &kms.KeyOptions{
				ConfigMap: kms.ConfigMap{"name": "aes256-gcm96"}})
			require.NoError(t, err)
			_, err = key.ExportPublic(ctx)
			require.Error(t, err)
		})
	})

	t.Run("x509", func(t *testing.T) {
		tests := map[string]x509.SignatureAlgorithm{
			"rsa-4096":   x509.SHA256WithRSAPSS,
			"ecdsa-p256": x509.ECDSAWithSHA256,
			"ecdsa-p384": x509.ECDSAWithSHA384,
			"ecdsa-p521": x509.ECDSAWithSHA512,
			"ed25519":    x509.PureEd25519,
		}
		for name, algo := range tests {
			t.Run(name, func(t *testing.T) {
				key, err := k.GetKey(ctx, &kms.KeyOptions{
					ConfigMap: kms.ConfigMap{"name": name}})
				require.NoError(t, err)
				signer, err := kms.NewSigner(ctx, key)
				require.NoError(t, err)

				// This is very minimal and could be expanded, but ensures basic
				// functionality with kms.NewSigner and x509.CreateCertificate.
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
		}
	})
}

// setupTransitEngine sets up an OpenBao instance in Docker with a Transit
// engine mounted in the root namespace.
func setupTransitEngine(t *testing.T) (*docker.DockerCluster, *api.Client) {
	t.Helper()

	opts := docker.DefaultOptions(t)
	opts.ClusterOptions.NumCores = 1
	cluster := docker.NewTestDockerCluster(t, opts)

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	active, err := testcluster.WaitForActiveNode(ctx, cluster)
	require.NoError(t, err)

	client := cluster.ClusterNodes[active].APIClient()
	require.NoError(t, client.Sys().Mount("transit", &api.MountInput{
		Type: "transit",
	}))

	t.Cleanup(func() {
		cluster.Cleanup()
	})

	return cluster, client
}
