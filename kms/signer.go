// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

// SignAlgorithm represents sign/verify algorithms
type SignAlgorithm int

const (
	// Insecure signing algorithms have been disabled in the first round.
	// Sign_RSA_PKCS1 SignAlgorithm = iota
	// Sign_SHA1_RSA_PKCS1 SignAlgorithm = iota
	// Sign_SHA256_RSA_PKCS1 SignAlgorithm = iota
	// Sign_SHA512_RSA_PKCS1 SignAlgorithm = iota
	// Sign_SHA1_RSA_PKCS1_PSS SignAlgorithm = iota
	Sign_SHA256_RSA_PKCS1_PSS SignAlgorithm = iota
	Sign_SHA512_RSA_PKCS1_PSS SignAlgorithm = iota
)

// SignerParameters defines the parameters required by a signing operation.
type SignerParameters struct {
	Algorithm SignAlgorithm
	// TODO - add here specific algorithm parameters, if any.
}

// Signer interface represents signing operations
type Signer interface {
	// This function continues a multiple-part signature operation, processing another data part.
	Update(data []byte) error

	// This function finishes a single or multiple-part signature operation, possibly processing the last data part, and returns the signature.
	Close(data []byte) (signature []byte, err error)
}

// SignerFactory creates Signer instances
type SignerFactory interface {
	// NewSigner creates a new Signer instance for digital signatures, using a private key.
	NewSigner(privateKey Key, signerParams *SignerParameters) (Signer, error)
}
