// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"hash"
	"io"
)

// NewLocalMessageSigner is a signer which allows incremental local computation
// of the hash, when the underlying signature algorithm supports it (and will
// return an error otherwise).
func NewLocalMessageSigner(signer DigestSigner, params *SignerParameters) (Signer, error) {
	hash := params.Algorithm.Hash()
	if hash == crypto.Hash(0) {
		return nil, fmt.Errorf("%w: %s", ErrUnknownDigestAlgorithm, params.Algorithm)
	}

	return &localMessageSigner{signer: signer, params: params, hash: hash.New()}, nil
}

type localMessageSigner struct {
	signer DigestSigner
	params *SignerParameters
	hash   hash.Hash
}

func (s *localMessageSigner) Update(ctx context.Context, data []byte) error {
	_, err := s.hash.Write(data)
	return err
}

func (s *localMessageSigner) Close(ctx context.Context, data []byte) ([]byte, error) {
	if err := s.Update(ctx, data); err != nil {
		return nil, err
	}

	return s.signer.SignDigest(ctx, s.params, s.hash.Sum(nil))
}

// NewLocalMessageVerifier is a verifier which allows incremental local
// computation of the hash, when the underlying signature algorithm supports it
// (and will return an error otherwise).
//
// If a non-nil signature is passed to Close, the Signature field of the
// originally passed VerifierParams will be mutated.
func NewLocalMessageVerifier(verifier DigestVerifier, params *VerifierParameters) (Verifier, error) {
	hash := params.Algorithm.Hash()
	if hash == crypto.Hash(0) {
		return nil, fmt.Errorf("%w: %s", ErrUnknownDigestAlgorithm, params.Algorithm)
	}

	return &localMessageVerifier{verifier: verifier, params: params, hash: hash.New()}, nil
}

type localMessageVerifier struct {
	verifier DigestVerifier
	params   *VerifierParameters
	hash     hash.Hash
}

func (v *localMessageVerifier) Update(ctx context.Context, data []byte) error {
	_, err := v.hash.Write(data)
	return err
}

func (v *localMessageVerifier) Close(ctx context.Context, data []byte, signature []byte) error {
	if err := v.Update(ctx, data); err != nil {
		return err
	}

	if signature != nil {
		v.params.Signature = signature
	}

	return v.verifier.VerifyDigest(ctx, v.params, v.hash.Sum(nil))
}

// NewStandardSigner returns a signer that implements the standard
// [crypto.Signer] & [crypto.MessageSigner] interfaces on top of a Key.
// StandardSigner supports both DigestSigner and RemoteDigestSignerFactory
// and will dispatch to these based on the signing algorithm, the method used
// (Sign vs SignMessage) and additional configuration fields available on
// StandardSigner.
func NewStandardSigner(ctx context.Context, key Key) (*StandardSigner, error) {
	asymmetricKey, ok := key.(AsymmetricKey)
	if !ok {
		return nil, errors.New("key is not an AsymmetricKey")
	}

	pub, err := asymmetricKey.ExportComponentPublic(ctx)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
	default:
		return nil, fmt.Errorf("expected well-known crypto.PublicKey type, got %T", pub)
	}

	return &StandardSigner{key: key, pub: pub, ctx: ctx}, nil
}

// StandardSigner implements [crypto.Signer] and [crypto.MessageSigner].
type StandardSigner struct {
	// EnforceRemoteDigest should be set to true to enforce that the digest is
	// computed remotely, i.e., guarantees that the backing KMS will see the
	// original payload.
	EnforceRemoteDigest bool

	key Key
	pub crypto.PublicKey
	ctx context.Context
}

func (s *StandardSigner) Public() crypto.PublicKey {
	return s.pub
}

func (s *StandardSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	params, err := s.params(opts)
	if err != nil {
		return nil, err
	}

	if s.EnforceRemoteDigest && params.Algorithm.Hash() != crypto.Hash(0) {
		return nil, errors.New("cannot enforce remote digest policy")
	}

	if signer, ok := s.key.(DigestSigner); ok {
		return signer.SignDigest(s.ctx, params, digest)
	}

	return nil, errors.New("key is not a DigestSigner")
}

func (s *StandardSigner) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	params, err := s.params(opts)
	if err != nil {
		return nil, err
	}

	hash := params.Algorithm.Hash()
	if !s.EnforceRemoteDigest || hash == crypto.Hash(0) {
		// Prefer DigestSigner by default to use the more commonly implemented
		// API and to save bandwidth if local digests are allowed.
		if signer, ok := s.key.(DigestSigner); ok {
			// Compute the digest if needed.
			if hash != crypto.Hash(0) {
				h := hash.New()
				if _, err := h.Write(msg); err != nil {
					return nil, err
				}
				msg = h.Sum(nil)
			}
			return signer.SignDigest(s.ctx, params, msg)
		}
	}

	// Fall back to RemoteMessageSignerFactory.
	if factory, ok := s.key.(RemoteMessageSignerFactory); ok {
		signer, err := factory.NewRemoteMessageSigner(s.ctx, params)
		if err != nil {
			return nil, err
		}
		return signer.Close(s.ctx, msg)
	}

	return nil, errors.New("key is not a DigestSigner or RemoteDigestSignerFactory")
}

func (s *StandardSigner) params(opts crypto.SignerOpts) (*SignerParameters, error) {
	hash, params := opts.HashFunc(), &SignerParameters{}

	// Quoting the doc comment on crypto.MessageSigner:
	//
	// > MessageSigner.SignMessage and MessageSigner.Sign should
	// produce the same > result given the same opts. In particular,
	// MessageSigner.SignMessage > should only accept a zero opts.HashFunc if
	// the Signer would also accept > messages which are not pre-hashed.
	//
	// ...so we should still ensure that opts.HashFunc is correct, no matter if
	// this is called via Sign or SignMessage.

	switch pub := s.pub.(type) {
	case ed25519.PublicKey:
		params.Algorithm = SignAlgo_ED
		if hash != crypto.Hash(0) {
			return nil, errors.New("pre-hashed Ed25519 variants are not supported, expected opts.HashFunc() zero")
		}

	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			params.Algorithm = SignAlgo_EC_P256
		case elliptic.P384():
			params.Algorithm = SignAlgo_EC_P384
		case elliptic.P521():
			params.Algorithm = SignAlgo_EC_P521
		default:
			return nil, errors.New("unsupported elliptic curve")
		}
		if expected := params.Algorithm.Hash(); hash != expected {
			return nil, fmt.Errorf("opts.HashFunc() %s does not match expected standard hash %s for %s",
				hash, expected, params.Algorithm)
		}

	case *rsa.PublicKey:
		opts, ok := opts.(*rsa.PSSOptions)
		if !ok {
			return nil, errors.New("RSA PKCS#1 v1.5 signing is not supported")
		}
		switch opts.SaltLength {
		case rsa.PSSSaltLengthEqualsHash, rsa.PSSSaltLengthAuto:
		default:
			return nil, errors.New("custom RSA PSS salt lengths are not supported")
		}
		switch hash {
		case crypto.SHA256:
			params.Algorithm = SignAlgo_RSA_PKCS1_PSS_SHA_256
		case crypto.SHA384:
			params.Algorithm = SignAlgo_RSA_PKCS1_PSS_SHA_384
		case crypto.SHA512:
			params.Algorithm = SignAlgo_RSA_PKCS1_PSS_SHA_512
		default:
			return nil, fmt.Errorf("unsupported hash function for RSA-OAEP signing: %s", hash)
		}

	default:
		// NewStandardSigner should ensure that the public key always matches
		// one of the above well-known public key types.
		panic("unreachable")
	}

	return params, nil
}
