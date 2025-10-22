// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
)

// SignAlgorithm represents sign/verify algorithms
type SignAlgorithm int

const (
	// SignAlgo_RSA_PKCS1_PSS_SHA_256 and related constants all use consistent
	// message digest and mask generation function hashes. That is, this
	// selection uses SHA-256 for both hash function invocations.
	SignAlgo_RSA_PKCS1_PSS_SHA_256 = iota + 1
	SignAlgo_RSA_PKCS1_PSS_SHA_384
	SignAlgo_RSA_PKCS1_PSS_SHA_512

	// SignAlgo_EC_P256 and related constants all follow NIST guidelines that
	// hash function should match the size of the underlying curve. That is,
	// this selection uses SHA-256 with P-256 and will err for other key
	// types.
	SignAlgo_EC_P256
	SignAlgo_EC_P384
	SignAlgo_EC_P521

	// This ed25519 / ed448; NOT ed25519ph and ed448ph.
	SignAlgo_ED
)

func (s SignAlgorithm) String() string {
	switch s {
	case SignAlgo_RSA_PKCS1_PSS_SHA_256:
		return "rsa-pss-sha-256"
	case SignAlgo_RSA_PKCS1_PSS_SHA_384:
		return "rsa-pss-sha-384"
	case SignAlgo_RSA_PKCS1_PSS_SHA_512:
		return "rsa-pss-sha-512"
	case SignAlgo_EC_P256:
		return "p-256"
	case SignAlgo_EC_P384:
		return "p-384"
	case SignAlgo_EC_P521:
		return "p-521"
	case SignAlgo_ED:
		return "eddsa"
	}

	return fmt.Sprintf("(unknown %d)", s)
}

func (s SignAlgorithm) Hash() hash.Hash {
	switch s {
	case SignAlgo_RSA_PKCS1_PSS_SHA_256, SignAlgo_EC_P256:
		return sha256.New()
	case SignAlgo_RSA_PKCS1_PSS_SHA_384, SignAlgo_EC_P384:
		return sha512.New384()
	case SignAlgo_RSA_PKCS1_PSS_SHA_512, SignAlgo_EC_P521:
		return sha512.New()
	}

	return nil
}

// SignerParameters defines the parameters required by a signing operation.
type SignerParameters struct {
	Algorithm SignAlgorithm

	// Provider-specific parameters.
	ProviderParameters map[string]interface{}
}

// Globally defined provider-specific signature parameters. Not every provider
// may support all parameters.
const (
	// When performing sign operations, the version of the key that was
	// ultimately used, if not specified by Key.
	//
	// Value is of type string.
	SignKeyVersionParameter string = "key-version"
)

var ErrUnknownDigestAlgorithm error = errors.New("unknown digest algorithm for specified hash")
var ErrBadDigestLength error = errors.New("specified digest length does not match signature algorithm expectations")

// Signer interface represents signing operations
type Signer interface {
	// This function continues a multiple-part signature operation, processing
	// another data part.
	Update(ctx context.Context, data []byte) error

	// This function finishes a single or multiple-part signature operation,
	// processing the last data part from not-nil, and returns the signature.
	Close(ctx context.Context, data []byte) (signature []byte, err error)
}

// SignerFactory must be implemented by KMS providers which support direct
// signing over provided hashes. This differs from pre-hashed in that the hash
// algorithm OID is embedded in the signed payload.
//
// This is required to support crypto/x509 and so is required by nearly all
// KMS implementations.
type SignerFactory interface {
	// DirectSign performs a one-shot digital signatures, using a private key,
	// from a provided digest when the algorithm supports client-side signing.
	//
	// SignerParameters may be mutated by the underlying provider.
	//
	// If the specified algorithm does not support client-side hashing, such
	// as in the case of Ed25519 due to requiring prehash, digest may be the
	// full message.
	Sign(ctx context.Context, signerParams *SignerParameters, digest []byte) ([]byte, error)
}

// ServerSignerFactory creates Signer instances. Some algorithms, like RSA, support
// signing from a pre-computed digest but others like Ed25519 or ML-DSA require
// the original message. SignerFactory is optionally implemented by (private or
// public/private pair) Key types.
//
// This may be implemented.
type ServerSignerFactory interface {
	// NewSigner performs a multi-step digital signature, using a private key,
	// from the provided input message. SignerParameters may be mutated by the
	// underlying provider.
	//
	// Hashing should be implemented remotely on the server.
	NewSigner(ctx context.Context, signerParams *SignerParameters) (Signer, error)
}
