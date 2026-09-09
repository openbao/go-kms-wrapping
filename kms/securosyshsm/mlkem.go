// Copyright (c) 2026 Securosys SA.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/openbao/go-kms-wrapping/v2/kms"
)

const (
	mlKEMEnvelopeMagic   = "SHSMMLKEM"
	mlKEMEnvelopeVersion = byte(1)
	mlKEMHKDFInfo        = "securosys/ml-kem/aes-256-gcm/v1"
	mlKEMNonceSize       = 12

	mlKEMVersionOffset          = len(mlKEMEnvelopeMagic)
	mlKEMCiphertextLengthOffset = mlKEMVersionOffset + 1
	mlKEMHeaderSize             = mlKEMCiphertextLengthOffset + 4
)

func isMLKEMAlgorithm(algorithm string) bool {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024":
		return true
	default:
		return false
	}
}

// encryptMLKEM implements hybrid encryption: TSB encapsulates a shared secret
// for the ML-KEM public key and that secret protects the payload with
// AES-256-GCM. The ML-KEM ciphertext and GCM nonce are carried in a versioned
// provider-specific envelope so callers only need to persist the returned
// ciphertext.
func (k *securosysKey) encryptMLKEM(ctx context.Context, opts *kms.CipherOptions) ([]byte, error) {
	if k.keyAttrs.PublicKey == "" {
		return nil, errors.New("ML-KEM key does not have a public key")
	}

	encapsulation, _, err := k.client.Encapsulate(ctx, k.keyAttrs.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM encapsulation failed: %w", err)
	}
	if encapsulation == nil || encapsulation.Ciphertext == "" || encapsulation.SharedSecret == "" {
		return nil, errors.New("ML-KEM encapsulation returned an incomplete response")
	}

	aead, err := mlKEMAEAD(encapsulation.SharedSecret, encapsulation.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM encapsulation returned an invalid shared secret: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate ML-KEM payload nonce: %w", err)
	}
	sealed := aead.Seal(nil, nonce, opts.Data, opts.AAD)

	return marshalMLKEMEnvelope(encapsulation.Ciphertext, nonce, sealed)
}

func (k *securosysKey) decryptMLKEM(ctx context.Context, opts *kms.CipherOptions) ([]byte, error) {
	kemCiphertext, nonce, sealed, err := unmarshalMLKEMEnvelope(opts.Data)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := k.decapsulateMLKEM(ctx, kemCiphertext)
	if err != nil {
		return nil, err
	}

	aead, err := mlKEMAEAD(sharedSecret, kemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decapsulation returned an invalid shared secret: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, sealed, opts.AAD)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM payload authentication failed: %w", err)
	}
	return plaintext, nil
}

func (k *securosysKey) decapsulateMLKEM(ctx context.Context, kemCiphertext string) (string, error) {
	if k.keyAttrs.Policy == nil {
		decapsulation, _, err := k.client.Decapsulate(ctx, k.keyAttrs.Label, k.password, kemCiphertext)
		if err != nil {
			return "", fmt.Errorf("ML-KEM decapsulation failed: %w", err)
		}
		if decapsulation == nil || decapsulation.SharedSecret == "" {
			return "", errors.New("ML-KEM decapsulation returned an empty shared secret")
		}
		return decapsulation.SharedSecret, nil
	}

	requestID, _, err := k.client.AsyncDecapsulate(ctx, k.keyAttrs.Label, k.password, kemCiphertext, map[string]string{})
	if err != nil {
		return "", fmt.Errorf("ML-KEM decapsulation failed: %w", err)
	}
	request, err := k.waitForRequest(ctx, requestID)
	if err != nil {
		return "", fmt.Errorf("async ML-KEM decapsulation failed: %w", err)
	}
	if request.Status != "EXECUTED" {
		return "", fmt.Errorf("ML-KEM decapsulation failed with status: %s", request.Status)
	}
	if request.Result == "" {
		return "", errors.New("ML-KEM decapsulation returned an empty shared secret")
	}
	return request.Result, nil
}

func mlKEMAEAD(encodedSecret, kemCiphertext string) (cipher.AEAD, error) {
	secret, err := base64.StdEncoding.DecodeString(encodedSecret)
	if err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, errors.New("shared secret is empty")
	}
	defer clear(secret)

	key, err := hkdf.Key(sha256.New, secret, []byte(kemCiphertext), mlKEMHKDFInfo, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func marshalMLKEMEnvelope(kemCiphertext string, nonce, sealed []byte) ([]byte, error) {
	if kemCiphertext == "" {
		return nil, errors.New("ML-KEM ciphertext is empty")
	}
	if len(nonce) != mlKEMNonceSize {
		return nil, fmt.Errorf("invalid ML-KEM payload nonce length: %d", len(nonce))
	}

	envelopeSize := mlKEMHeaderSize + len(kemCiphertext) + len(nonce) + len(sealed)
	envelope := make([]byte, 0, envelopeSize)

	envelope = append(envelope, mlKEMEnvelopeMagic...)
	envelope = append(envelope, mlKEMEnvelopeVersion)
	envelope = binary.BigEndian.AppendUint32(envelope, uint32(len(kemCiphertext)))
	envelope = append(envelope, kemCiphertext...)
	envelope = append(envelope, nonce...)
	envelope = append(envelope, sealed...)

	return envelope, nil
}

func unmarshalMLKEMEnvelope(envelope []byte) (string, []byte, []byte, error) {
	if len(envelope) < mlKEMHeaderSize || !bytes.HasPrefix(envelope, []byte(mlKEMEnvelopeMagic)) {
		return "", nil, nil, errors.New("invalid ML-KEM ciphertext envelope")
	}
	if envelope[mlKEMVersionOffset] != mlKEMEnvelopeVersion {
		return "", nil, nil, fmt.Errorf("unsupported ML-KEM ciphertext envelope version: %d", envelope[mlKEMVersionOffset])
	}

	kemLength := int(binary.BigEndian.Uint32(envelope[mlKEMCiphertextLengthOffset:]))
	if kemLength == 0 {
		return "", nil, nil, errors.New("invalid ML-KEM ciphertext length")
	}
	sealedOffset := mlKEMHeaderSize + kemLength + mlKEMNonceSize
	if sealedOffset > len(envelope) || len(envelope)-sealedOffset < aes.BlockSize {
		return "", nil, nil, errors.New("truncated ML-KEM ciphertext envelope")
	}

	kemCiphertext := string(envelope[mlKEMHeaderSize : mlKEMHeaderSize+kemLength])
	nonce := bytes.Clone(envelope[sealedOffset-mlKEMNonceSize : sealedOffset])
	sealed := bytes.Clone(envelope[sealedOffset:])
	return kemCiphertext, nonce, sealed, nil
}
