// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
)

// VerifierParameters defines the parameters required by a signature
// verification operation.
type VerifierParameters struct {
	Algorithm SignAlgorithm

	// Signature to be verified.
	Signature []byte

	// Provider-specific parameters.
	ProviderParameters map[string]interface{}
}

// Verifier represents an ongoing signature verification operation.
type Verifier interface {
	// Update continues a multiple-part verification operation, processing
	// another data part.
	Update(ctx context.Context, data []byte) error

	// Close finishes a single or multiple-part signature verification
	// operation, processing the last data part if not nil, and returns an error
	// if verification fails.
	//
	// The caller provides the signature to be verified at the end of the
	// operation. This may be nil if signature was provided as part of the
	// VerifierParameters.
	Close(ctx context.Context, data []byte, signature []byte) error
}

// DigestVerifier performs one-shot verifications of digital signatures on
// pre-hashed messages. This interface is optionally implemented by (public or
// public/private pair) Key types.
//
// See notes in DigestSigner.
type DigestVerifier interface {
	// VerifyDigest performs a one-shot verification of a digital signature,
	// using a public key, from a provided digest.
	//
	// VerifierParameters may be mutated by the underlying implementation.
	//
	// See notes in DigestSigner.
	VerifyDigest(ctx context.Context, params *VerifierParameters, digest []byte) error
}

// RemoteMessageVerifierFactory creates Verifier instances that guarantee
// hashing is performed remotely, i.e., the KMS must see the original message.
// This interface is optionally implemented by (public or public/private pair)
// Key types.
type RemoteMessageVerifierFactory interface {
	// NewRemoteMessageVerifier returns a multi-step Verifier.
	//
	// VerifierParameters may be mutated by the underlying implementation.
	NewRemoteMessageVerifier(ctx context.Context, params *VerifierParameters) (Verifier, error)
}
