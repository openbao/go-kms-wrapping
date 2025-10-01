// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
	"fmt"
	"hash"
)

// SignerParameters defines the parameters required by a signing operation.
type VerifierParameters struct {
	Algorithm SignAlgorithm

	// Signature to be verified.
	Signature []byte

	// Provider-specific parameters.
	ProviderParameters map[string]interface{}
}

// Verifier interface represents signature verification operations
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

// NewDigestVerifier will mutate its passed verifierParams.
func NewDigestVerifier(ctx context.Context, factory VerifierFactory, publicKey Key, verifierParams *VerifierParameters) (Verifier, error) {
	hasher := verifierParams.Algorithm.Hash()
	if hasher == nil {
		return nil, fmt.Errorf("%w: %v", ErrUnknownDigestAlgorithm, verifierParams.Algorithm.String())
	}

	return &verifier{factory: factory, key: publicKey, params: verifierParams, hash: hasher}, nil
}

type verifier struct {
	factory VerifierFactory
	key     Key
	params  *VerifierParameters

	hash hash.Hash
}

func (v *verifier) Update(ctx context.Context, data []byte) error {
	_, err := v.hash.Write(data)
	return err
}

func (v *verifier) Close(ctx context.Context, data []byte, signature []byte) error {
	if err := v.Update(ctx, data); err != nil {
		return err
	}

	if signature != nil {
		v.params.Signature = signature
	}

	return v.factory.DigestVerify(ctx, v.key, v.params, v.hash.Sum(nil))
}

// VerifierFactory creates Verifier instances
type VerifierFactory interface {
	// DigestVerify performs a one-shot verification of a digital signature, from a provided digest.
	DigestVerify(ctx context.Context, publicKey Key, verifierParams *VerifierParameters, digest []byte) error

	// NewVerifier performs a multi-step digital signature, using a private
	// key, from a provided input message.
	NewVerifier(ctx context.Context, publicKey Key, verifierParams *VerifierParameters) (Verifier, error)
}
