// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
	"crypto"
	"errors"
	"fmt"
)

// SignAlgorithm represents sign/verify algorithms
type SignAlgorithm int

const (
	// SignAlgo_RSA_PKCS1_PSS_SHA_256 and related constants all use consistent
	// message digest and mask generation function hashes. That is, this
	// selection uses SHA-256 for both hash function invocations. PSS salt
	// length is always equal to hash length, differing combinations are
	// presently unsupported.
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

	// This is Ed25519 / Ed448; NOT Ed25519ph and Ed448ph.
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

func (s SignAlgorithm) Hash() crypto.Hash {
	switch s {
	case SignAlgo_RSA_PKCS1_PSS_SHA_256, SignAlgo_EC_P256:
		return crypto.SHA256
	case SignAlgo_RSA_PKCS1_PSS_SHA_384, SignAlgo_EC_P384:
		return crypto.SHA384
	case SignAlgo_RSA_PKCS1_PSS_SHA_512, SignAlgo_EC_P521:
		return crypto.SHA512
	}

	return crypto.Hash(0)
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

var (
	ErrUnknownDigestAlgorithm = errors.New("unknown digest algorithm for specified hash")
	ErrBadDigestLength        = errors.New("specified digest length does not match signature algorithm expectations")
)

// Signer represents an ongoing signing operation.
type Signer interface {
	// Update continues a multiple-part signing operation, processing another
	// data part.
	Update(ctx context.Context, data []byte) error

	// Close finishes a single or multiple-part signing operation, processing
	// the last data part if not nil, and returns the signature.
	Close(ctx context.Context, data []byte) (signature []byte, err error)
}

// DigestSigner performs one-shot creation of digital signatures on pre-hashed
// messages. Use of this interface implies local crypto (message hashing)
// has already been performed, with the exception of Ed25519 and similar
// algorithms which cannot support local digesting. This interface is optionally
// implemented by (private or public/private pair) Key types.
type DigestSigner interface {
	// SignDigest performs a one-shot digital signature, using a private key,
	// from a provided digest.
	//
	// SignerParameters may be mutated by the underlying provider.
	//
	// If the specified algorithm does not support client-side hashing, such as
	// in the case of Ed25519, digest may be the full message. This is provided
	// for convenience of implementers: otherwise, implementers would require
	// two different internal key types to support Ed25519 versus RSA or ECDSA.
	SignDigest(ctx context.Context, params *SignerParameters, digest []byte) ([]byte, error)
}

// RemoteMessageSignerFactory creates Signer instances that guarantee hashing
// is performed remotely, i.e., the KMS must see the original message. This
// interface is optionally implemented by (private or public/private pair) Key
// types.
type RemoteMessageSignerFactory interface {
	// NewRemoteMessageSigner returns a multi-step Signer.
	//
	// SignerParameters may be mutated by the underlying implementation.
	NewRemoteMessageSigner(ctx context.Context, params *SignerParameters) (Signer, error)
}
