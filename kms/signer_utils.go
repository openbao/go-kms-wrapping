// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
	"fmt"
	"hash"
)

// NewDigestSigner is a local signer which allows incremental computation of
// the hash locally, when the underlying signature algorithm supports it. If
// an algorithm doesn't, SignerParameters.Algorithm.Hash() will return nil.
func NewDigestSigner(factory SignerFactory, signerParams *SignerParameters) (Signer, error) {
	hasher := signerParams.Algorithm.Hash()
	if hasher == nil {
		return nil, fmt.Errorf("%w: %v", ErrUnknownDigestAlgorithm, signerParams.Algorithm.String())
	}

	return &signer{factory: factory, params: signerParams, hash: hasher}, nil
}

type signer struct {
	factory SignerFactory
	params  *SignerParameters

	hash hash.Hash
}

func (s *signer) Update(ctx context.Context, data []byte) error {
	_, err := s.hash.Write(data)
	return err
}

func (s *signer) Close(ctx context.Context, data []byte) ([]byte, error) {
	if err := s.Update(ctx, data); err != nil {
		return nil, err
	}

	return s.factory.Sign(ctx, s.params, s.hash.Sum(nil))
}

// NewDigestVerifier will mutate its passed verifierParams.
func NewDigestVerifier(factory VerifierFactory, verifierParams *VerifierParameters) (Verifier, error) {
	hasher := verifierParams.Algorithm.Hash()
	if hasher == nil {
		return nil, fmt.Errorf("%w: %v", ErrUnknownDigestAlgorithm, verifierParams.Algorithm.String())
	}

	return &verifier{factory: factory, params: verifierParams, hash: hasher}, nil
}

type verifier struct {
	factory VerifierFactory
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

	return v.factory.Verify(ctx, v.params, v.hash.Sum(nil))
}
