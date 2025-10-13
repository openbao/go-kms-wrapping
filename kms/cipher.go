// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
	"fmt"
)

// CipherOperation represents the direction of the cipher operation: encrypt or decrypt.
//
// Constant values are subject to change; rely on strings for serialization.
type CipherOperation int

const (
	CipherOp_Encrypt CipherOperation = iota + 1
	CipherOp_Decrypt
)

func (c CipherOperation) String() string {
	switch c {
	case CipherOp_Encrypt:
		return "encrypt"
	case CipherOp_Decrypt:
		return "decrypt"
	}

	return fmt.Sprintf("(unknown %d)", c)
}

// CipherAlgorithm represents ciphering algorithms.
//
// Constant values are subject to change; rely on strings for serialization.
type CipherAlgorithm int

const (
	CipherAlgo_AES CipherAlgorithm = iota + 1
	CipherAlgo_RSA
)

func (c CipherAlgorithm) String() string {
	switch c {
	case CipherAlgo_AES:
		return "aes"
	case CipherAlgo_RSA:
		return "rsa"
	}

	return fmt.Sprintf("(unknown %d)", c)
}

// CipherAlgorithmMode represents a combination between a cipher algorithm
// and a block mode.
//
// Constant values are subject to change; rely on strings for serialization.
type CipherAlgorithmMode int

const (
	CipherMode_AES_GCM CipherAlgorithmMode = iota + 1

	// CipherMode_RSA_OAEP_SHA256 and related all use consistent message
	// digest and mask generation function hashes. That is, this selection
	// uses SHA-256 for both hash function invocations.
	CipherMode_RSA_OAEP_SHA256
	CipherMode_RSA_OAEP_SHA384
	CipherMode_RSA_OAEP_SHA512
)

func (c CipherAlgorithmMode) String() string {
	switch c {
	case CipherMode_AES_GCM:
		return "aes-gcm"
	case CipherMode_RSA_OAEP_SHA256:
		return "rsa-oaep-sha256"
	case CipherMode_RSA_OAEP_SHA384:
		return "rsa-oaep-sha384"
	case CipherMode_RSA_OAEP_SHA512:
		return "rsa-oaep-sha512"
	}

	return fmt.Sprintf("(unknown %d)", c)
}

func (c CipherAlgorithmMode) Algorithm() CipherAlgorithm {
	switch c {
	case CipherMode_AES_GCM:
		return CipherAlgo_AES
	case CipherMode_RSA_OAEP_SHA256, CipherMode_RSA_OAEP_SHA384, CipherMode_RSA_OAEP_SHA512:
		return CipherAlgo_RSA
	}

	return 0
}

// Padding represents the padding required by some ciphering algorithms.
type Padding int

const (
	Padding_No Padding = iota
)

func (p Padding) String() string {
	switch p {
	case Padding_No:
		return "none"
	}

	return fmt.Sprintf("(unknown %d)", p)
}

// CipherParameters defines the parameters required by a ciphering operation.
// We might want to specialize this per algorithm (provide CTR counter length, 64 bits, for example, etc.).
type CipherParameters struct {
	// Controls the choice of parameters.
	Algorithm CipherAlgorithmMode

	// Type of parameters is dependent on the choice of Algorithm.
	Parameters interface{}

	// Not every cipher algorithm requires padding.
	Padding Padding

	// Provider-specific parameters.
	ProviderParameters map[string]interface{}
}

// Globally defined provider-specific cipher parameters. Not every provider
// may support all parameters.
const (
	// When performing encrypt operations, the version of the key that was
	// ultimately used, if not specified by Key.
	//
	// Value is of type string.
	CipherKeyVersionParameter string = "key-version"
)

// AESGCMCipherParameters is used for AES-GCM operations.
//
// This will perform the standard 96-bit nonce, 16-byte tag
// AES-GCM operation.
type AESGCMCipherParameters struct {
	// Note: for encryption operations, the caller should not provide the Nonce. Instead, the Cipher will generate a random Nonce.
	Nonce []byte

	// Additional authenticated data.
	AAD []byte

	// In the future, if someone has a valid use case, nonce and tag width
	// can be specified here, though this should be discouraged.
}

// Cipher interface represents ciphering operations
type Cipher interface {
	// This function performs/continues a multiple-part ciphering operation, processing another data part.
	Update(ctx context.Context, input []byte) (output []byte, err error)

	// This function finishes a single or multiple-part ciphering operation, possibly processing the last data part.
	// Note: for encryption operations, the caller should not provide the IV when initalizating the Cipher.
	// Instead, the Cipher will generate a random IV that will be returned here prepended to the ciphertext.
	// The MAC (Authentication Tag) is returned by this function appended to the ciphertext when encrypting with AEAD algorithms.
	Close(ctx context.Context, input []byte) (output []byte, err error)
}

// CipherFactory creates Cipher instances. When invoking NewCipher, note that
// the cipher will mutate CipherParameters and thus it is not thread-safe to
// call two cipher instances with the same CipherParameters values.
//
//	aes := Factory.NewCipher(CipherOp_Encrypt, key, &CipherParameters{
//		Algorithm: CipherMode_AES_GCM,
//		Parameters: &AESGCMCipherParameters{ AAD: aad },
//	})
//
//	aes.Close(...)
//
// CipherFactory is optionally implemented by Key types.
type CipherFactory interface {
	// NewCipher creates a new Cipher instance
	NewCipher(ctx context.Context, operation CipherOperation, cipherParams *CipherParameters) (Cipher, error)
}
