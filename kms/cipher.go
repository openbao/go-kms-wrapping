// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

import "fmt"

// CipherOperation represents the direction of the cipher operation: encrypt or decrypt.
type CipherOperation int

const (
	Encrypt CipherOperation = iota
	Decrypt
)

// CipherAlgorithm represents ciphering algorithms
type CipherAlgorithm int

const (
	Cipher_AES CipherAlgorithm = iota
)

func (c CipherAlgorithm) String() string {
	switch c {
	case Cipher_AES:
		return "aes"
	}

	return fmt.Sprintf("(unknown %d)", c)
}

// CipherAlgorithmMode represents a combination between a cipher algorithm
// and a block mode.

type CipherAlgorithmMode int

const (
	// Unsafe cipher modes have been disabled until such time as required.
	// Cipher_AES_ECB CipherAlgorithm = iota
	// Cipher_AES_CBC
	// Cipher_AES_CTR
	Cipher_AES_GCM CipherAlgorithmMode = iota + 3 // 3
)

func (c CipherAlgorithmMode) String() string {
	switch c {
	case Cipher_AES_GCM:
		return "aes-gcm"
	}

	return fmt.Sprintf("(unknown %d)", c)
}

// Padding represents the padding required by some ciphering algorithms.
type Padding int

const (
	NoPadding Padding = iota

	// PKCS5Padding has been disabled as it is not required by AES-GCM mode.
	// PKCS5Padding Padding = iota
)

func (p Padding) String() string {
	switch p {
	case NoPadding:
		return "none"
	}

	return fmt.Sprintf("(unknown %d)", p)
}

// CipherParameters defines the parameters required by a ciphering operation.
// We might want to specialize this per algorithm (provide CTR counter length, 64 bits, for example, etc.).
type CipherParameters struct {
	Algorithm CipherAlgorithmMode
	// Not every cipher algorithm requires padding.
	Padding Padding
	// Note: for encryption operations, the caller should not provide the  IV. Instead, the Cipher will generate a random IV.
	IV []byte
	// Additional authenticated data, when supported by the algorithm
	AAD []byte
	// MAC (Authentication Tag) of AEAD algorithms to be provided by the caller for decrypt operations.
	MAC []byte
}

// Cipher interface represents ciphering operations
type Cipher interface {
	// This function performs/continues a multiple-part ciphering operation, processing another data part.
	Update(input []byte) (output []byte, err error)

	// This function finishes a single or multiple-part ciphering operation, possibly processing the last data part.
	// Note: for encryption operations, the caller should not provide the IV when initalizating the Cipher.
	// Instead, the Cipher will generate a random IV that will be returned here.
	// The MAC (Authentication Tag) is returned by this function when encrypting with AEAD algorithms.
	Close(input []byte) (output []byte, iv []byte, err error)
}

// CipherFactory creates Cipher instances
type CipherFactory interface {
	// NewCipher creates a new Cipher instance
	NewCipher(operation CipherOperation, key Key, cipherParams *CipherParameters) (Cipher, error)
}
