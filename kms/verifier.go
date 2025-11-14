// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
)

// VerifierParameters defines the parameters required by a signing operation.
type VerifierParameters struct {
	Algorithm SignAlgorithm

	// Signature to be verified.
	Signature []byte

	// Provider-specific parameters.
	ProviderParameters map[string]interface{}
}

// Verifier represents signature verification operations.
type Verifier interface {
	// This function continues a multiple-part verification operation, processing another data part.
	Update(ctx context.Context, data []byte) error

	// The caller provides the signature to be verified at the end of the
	// operation. This may be nil if signature was provided as part of the
	// VerifierParameters.
	//
	// This function finishes a single or multiple-part signature verification
	// operation, possibly processing the last data part, and checking the
	// validity of the signature.
	//
	// The value of signature passed here, if not nil, will take precedence
	// over the one provided in the constructing parameters.
	Close(ctx context.Context, data []byte, signature []byte) error
}

// VerifierFactory creates Verifier instances. VerifierFactory is optionally
// implemented by (public or public/private pair) Key types.
//
// See notes in SignerFactory.
type VerifierFactory interface {
	// Verify performs a one-shot verification of a digital signature, from a provided digest.
	//
	// See notes in SignerFactory.
	Verify(ctx context.Context, verifierParams *VerifierParameters, digest []byte) error
}

// RemoteDigestVerifierFactory creates Verifier instances. Some algorithms, like
// RSA, support signing from a pre-computed digest but others like Ed25519 or
// ML-DSA require the original message. SignerFactory is optionally implemented
// by (private or public/private pair) Key types.
//
// This may optionally be implemented.
//
// See notes in RemoteDigestSignerFactory.
type RemoteDigestVerifierFactory interface {
	// NewVerifier performs a multi-step digital signature, using a private
	// key, from a provided input message.
	//
	// See notes in RemoteDigestSignerFactory.
	NewRemoteDigestVerifier(ctx context.Context, verifierParams *VerifierParameters) (Verifier, error)
}
