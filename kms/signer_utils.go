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
func NewDigestSigner(ctx context.Context, factory DirectSignerFactory, signerParams *SignerParameters) (Signer, error) {
	hasher := signerParams.Algorithm.Hash()
	if hasher == nil {
		return nil, fmt.Errorf("%w: %v", ErrUnknownDigestAlgorithm, signerParams.Algorithm.String())
	}

	return &signer{factory: factory, params: signerParams, hash: hasher}, nil
}

type signer struct {
	factory DirectSignerFactory
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

	return s.factory.DigestSign(ctx, s.params, s.hash.Sum(nil))
}
