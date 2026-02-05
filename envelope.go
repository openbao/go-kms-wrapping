// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package wrapping

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	fmt "fmt"

	uuid "github.com/hashicorp/go-uuid"
)

// EnvelopeEncrypt takes in plaintext and envelope encrypts it, generating an
// EnvelopeInfo value.  An empty plaintext is a valid parameter and will not cause
// an error.  Also note: if you provide a plaintext of []byte(""),
// EnvelopeDecrypt will return []byte(nil).
//
// Supported options:
//
// * wrapping.WithAad: Additional authenticated data that should be sourced from
// a separate location, and must also be provided during envelope decryption
func EnvelopeEncrypt(plaintext []byte, opt ...Option) (*EnvelopeInfo, error) {
	opts, err := GetOpts(opt...)
	if err != nil {
		return nil, err
	}

	// Generate DEK
	key, err := uuid.GenerateRandomBytes(32)
	if err != nil {
		return nil, err
	}

	aead, err := aeadEncrypter(key)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nil, plaintext, opts.WithAad)

	return &EnvelopeInfo{
		// 12 bytes = 96-bit nonce. Split these for backwards
		// compatibility with OpenBao v2.4 and lower.
		// Also see:
		// - https://github.com/openbao/openbao/issues/2230
		// - https://github.com/openbao/openbao/issues/2417
		Iv: ciphertext[:12], Ciphertext: ciphertext[12:],
		Key: key,
	}, nil
}

// EnvelopeDecrypt takes in EnvelopeInfo and potentially additional options and
// decrypts.  Also note: if you provided a plaintext of []byte("") to
// EnvelopeEncrypt, then this function will return []byte(nil).
//
// Supported options:
//
// * wrapping.WithAad: Additional authenticated data that should be sourced from
// a separate location, and must match what was provided during envelope
// encryption.
func EnvelopeDecrypt(data *EnvelopeInfo, opt ...Option) ([]byte, error) {
	// need to check data or we could panic when trying to access data.Key
	if data == nil {
		return nil, fmt.Errorf("missing envelope info: %w", ErrInvalidParameter)
	}
	opts, err := GetOpts(opt...)
	if err != nil {
		return nil, err
	}

	aead, err := aeadEncrypter(data.Key)
	if err != nil {
		return nil, err
	}

	// OpenBao v2.5.0-beta20251125 and OpenBao v2.5.0 did not return
	// a split nonce + ciphertext pair from EnvelopeEncrypt, which was
	// backwards-incompatible. For maximum compatibility, we must handle
	// both split and combined nonce + ciphertext pairs here, which is easily
	// achieved by concatenating both fields.
	// Also see:
	// - https://github.com/openbao/openbao/issues/2230
	// - https://github.com/openbao/openbao/issues/2417
	ciphertext := append(data.Iv, data.Ciphertext...)
	return aead.Open(nil, nil, ciphertext, opts.WithAad)
}

func aeadEncrypter(key []byte) (cipher.AEAD, error) {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create the GCM mode AEAD
	gcm, err := cipher.NewGCMWithRandomNonce(aesCipher)
	if err != nil {
		return nil, errors.New("failed to initialize GCM mode")
	}

	return gcm, nil
}
