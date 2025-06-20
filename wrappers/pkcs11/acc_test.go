// Copyright The OpenBao Contributors
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

// TestPool ensures that the session pool implementation
// handles concurrency and cancellation as expected.
//
// Required environment variables:
//   - BAO_HSM_LIB
//   - BAO_HSM_TOKEN_LABEL or BAO_HSM_SLOT
//   - BAO_HSM_PIN
func TestPool(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	opts, err := getWrapperOpts(nil)
	require.NoError(t, err)

	mod, info, err := acquireSlot(opts.lib, opts.slotNumber, opts.tokenLabel)
	require.NoError(t, err)
	defer func() { require.NoError(t, mod.releaseSlot(info.ID)) }()

	t.Run("basic functionality", func(t *testing.T) {
		ctx := context.Background()
		pool, err := newSessionPool(mod.ctx, info, opts.pin, 0)
		require.NoError(t, err)

		session, err := pool.get(ctx)
		require.NoError(t, err)
		require.Equal(t, pool.size, uint(1))

		session2, err := pool.get(ctx)
		require.NoError(t, err)
		require.Equal(t, pool.size, uint(2))

		pool.put(session2)
		require.Equal(t, pool.size, uint(1))

		session3, err := pool.get(ctx)
		require.NoError(t, err)
		require.Equal(t, pool.size, uint(2))

		pool.put(session)
		pool.put(session3)
		require.Equal(t, pool.size, uint(0))

		err = pool.close()
		require.NoError(t, err)

		// Pool is closed, should error
		_, err = pool.get(ctx)
		require.Error(t, err)
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		pool, err := newSessionPool(mod.ctx, info, opts.pin, 2)
		require.NoError(t, err)
		defer func() { require.NoError(t, pool.close()) }()

		// Take the only session
		session, err := pool.get(ctx)
		require.NoError(t, err)

		result := make(chan error)
		go func() {
			// Take another session, should block
			_, err := pool.get(ctx)
			result <- err
		}()

		cancel()
		require.ErrorIs(t, <-result, context.Canceled)

		pool.put(session)
	})

	t.Run("wait before closing", func(t *testing.T) {
		ctx := context.Background()
		pool, err := newSessionPool(mod.ctx, info, opts.pin, 0)
		require.NoError(t, err)

		session1, err := pool.get(ctx)
		require.NoError(t, err)

		session2, err := pool.get(ctx)
		require.NoError(t, err)

		pool.put(session1)

		returned := atomic.Bool{}
		results := make(chan error)

		go func() {
			err := pool.close()
			results <- err
			if !returned.Load() {
				results <- fmt.Errorf("pool was closed before session returned")
			} else {
				results <- nil
			}
		}()

		// Give it some time before we return the session
		<-time.After(time.Millisecond * 10)
		pool.put(session2)
		returned.Store(true)

		require.NoError(t, <-results)
		require.NoError(t, <-results)
	})

	t.Run("limits concurrency", func(t *testing.T) {
		ctx := context.Background()

		pool, err := newSessionPool(mod.ctx, info, opts.pin, 10)
		require.NoError(t, err)
		defer func() { require.NoError(t, pool.close()) }()

		concurrency := atomic.Uint64{}
		results := make(chan error)

		for range pool.max * 10 {
			go func() {
				session, err := pool.get(ctx)
				if err != nil {
					results <- err
					return
				}

				concurrency.Add(1)
				if c := concurrency.Load(); c > uint64(pool.max) {
					results <- fmt.Errorf("max_parallel exceeded: %d/%d", c, pool.max)
					return
				}

				concurrency.Add(^uint64(0))
				results <- pool.put(session)
			}()
		}

		for range pool.max * 10 {
			require.NoError(t, <-results)
		}
	})
}

// TestWrapper tests the lifecycle of a Wrapper.
//
// Required environment variables:
//   - BAO_HSM_LIB
//   - BAO_HSM_TOKEN_LABEL or BAO_HSM_SLOT
//   - BAO_HSM_PIN
//   - BAO_HSM_KEY_LABEL or BAO_HSM_KEY_ID
//
// Supported key types:
//   - AES
//   - RSA
func TestWrapper(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	ctx := context.Background()
	wrapper := NewWrapper()

	// Read all configuration directly from the tests's environment.
	_, err := wrapper.SetConfig(ctx)
	require.NoError(t, err)

	plaintext := []byte("foo")
	ciphertext, err := wrapper.Encrypt(ctx, plaintext)
	require.NoError(t, err)

	decrypted, err := wrapper.Decrypt(ctx, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)

	err = wrapper.Finalize(ctx)
	require.NoError(t, err)

	// Pool is cleaned up properly?
	require.Zero(t, wrapper.client.pool.size)

	// Module is cleaned up properly?
	require.Zero(t, len(modules))
	require.Zero(t, len(wrapper.client.mod.slots))
}

// TestExternalKey tests the lifecycle of an ExternalKey via a Provider.
//
// Required environment variables:
//   - BAO_HSM_LIB
//   - BAO_HSM_TOKEN_LABEL or BAO_HSM_SLOT
//   - BAO_HSM_PIN
//   - BAO_HSM_KEY_LABEL or BAO_HSM_KEY_ID
//
// Supported key types:
//   - RSA
//   - ECDSA
func TestExternalKey(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	ctx := context.Background()
	provider := NewProvider()

	// Provider never configures itself based on the environment, we'll do that manually:
	config := make(map[string]string)
	mergeConfigMapWithEnv(config)

	err := provider.SetConfig(ctx, wrapping.WithConfigMap(config))
	require.NoError(t, err)

	key, err := provider.GetKey(ctx, wrapping.WithConfigMap(config))
	require.NoError(t, err)
	require.NotNil(t, key)

	// Our Signers/Decrypters should handle parallel use fine.
	t.Run("group", func(t *testing.T) {
		if signer, ok := key.Signer(); ok {
			for range 100 {
				t.Run("crypto.Signer", func(t *testing.T) {
					t.Parallel()
					testSigner(t, signer)
				})
			}
		}

		if decrypter, ok := key.Decrypter(); ok {
			for range 100 {
				t.Run("crypto.Decrypter", func(t *testing.T) {
					t.Parallel()
					testDecrypter(t, decrypter)
				})
			}
		}
	})

	err = provider.Finalize(ctx)
	require.NoError(t, err)

	// Pool is cleaned up properly?
	require.Zero(t, provider.client.pool.size)

	// Module is cleaned up properly?
	require.Zero(t, len(modules))
	require.Zero(t, len(provider.client.mod.slots))
}

// testSigner ensures that a crypto.Signer works as expected.
// The key type is automatically detected based on the public key.
func testSigner(t *testing.T, signer crypto.Signer) {
	digest := []byte("sign me!")

	switch pub := signer.Public().(type) {
	case *ecdsa.PublicKey:
		signature, err := signer.Sign(rand.Reader, digest, nil)
		require.NoError(t, err)
		require.NotNil(t, signature)
		require.NotEmpty(t, signature)

		valid := ecdsa.VerifyASN1(pub, digest, signature)
		require.True(t, valid)
	case *rsa.PublicKey:
		hash := crypto.SHA256
		h := hash.New()
		_, err := h.Write(digest)
		require.NoError(t, err)
		hashed := h.Sum(nil)

		t.Run("PSS", func(t *testing.T) {
			t.Parallel()

			opts := &rsa.PSSOptions{
				Hash:       crypto.SHA256,
				SaltLength: rsa.PSSSaltLengthEqualsHash,
			}

			signature, err := signer.Sign(rand.Reader, hashed, opts)
			require.NoError(t, err)
			require.NotNil(t, signature)
			require.NotEmpty(t, signature)

			err = rsa.VerifyPSS(pub, hash, hashed, signature, opts)
			require.NoError(t, err)
		})

		t.Run("PKCS#1 v1.5", func(t *testing.T) {
			t.Parallel()

			signature, err := signer.Sign(rand.Reader, hashed, hash)
			require.NoError(t, err)
			require.NotNil(t, signature)
			require.NotEmpty(t, signature)

			err = rsa.VerifyPKCS1v15(pub, hash, hashed, signature)
			require.NoError(t, err)
		})
	default:
		panic("unsupported public key type")
	}
}

// testDecrypter ensures that a crypto.Decrypter works as expected.
// The key type is automatically detected based on the public key.
func testDecrypter(t *testing.T, decrypter crypto.Decrypter) {
	plaintext := []byte("encrypt me!")

	switch pub := decrypter.Public().(type) {
	case *rsa.PublicKey:
		t.Run("OAEP", func(t *testing.T) {
			t.Parallel()

			hash := crypto.SHA1
			ciphertext, err := rsa.EncryptOAEP(hash.New(), rand.Reader, pub, plaintext, nil)
			require.NoError(t, err)

			decrypted, err := decrypter.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: hash})
			require.NoError(t, err)

			require.NotNil(t, decrypted)
			require.NotEmpty(t, decrypted)
			require.Equal(t, decrypted, plaintext)
		})

		t.Run("PKCS#1 v1.5", func(t *testing.T) {
			t.Parallel()

			ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, plaintext)
			require.NoError(t, err)

			decrypted, err := decrypter.Decrypt(rand.Reader, ciphertext, &rsa.PKCS1v15DecryptOptions{})
			require.NoError(t, err)

			require.NotNil(t, decrypted)
			require.NotEmpty(t, decrypted)
			require.Equal(t, decrypted, plaintext)
		})
	default:
		panic("unsupported public key type")
	}
}
