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

// NewDigestSigner is a local signer which allows incremental computation of
// the hash locally, when the underlying signature algorithm supports it. If
// an algorithm doesn't, SignerParameters.Algorithm.Hash() will return nil.
//
// This uses SignerFactory which means local crypto (message hashing) is
// performed. Only the digest is sent to the remote KMS provider.
func NewDigestSigner(factory SignerFactory, signerParams *SignerParameters) (Signer, error) {
	hash := signerParams.Algorithm.Hash()
	if hash == crypto.Hash(0) {
		return nil, fmt.Errorf("%w: %v", ErrUnknownDigestAlgorithm, signerParams.Algorithm.String())
	}

	return &digestSigner{factory: factory, params: signerParams, hash: hash.New()}, nil
}

type digestSigner struct {
	factory SignerFactory
	params  *SignerParameters

	hash hash.Hash
}

func (s *digestSigner) Update(ctx context.Context, data []byte) error {
	_, err := s.hash.Write(data)
	return err
}

func (s *digestSigner) Close(ctx context.Context, data []byte) ([]byte, error) {
	if err := s.Update(ctx, data); err != nil {
		return nil, err
	}

	return s.factory.Sign(ctx, s.params, s.hash.Sum(nil))
}

// NewDigestVerifier will mutate its passed verifierParams.
func NewDigestVerifier(factory VerifierFactory, verifierParams *VerifierParameters) (Verifier, error) {
	hash := verifierParams.Algorithm.Hash()
	if hash == crypto.Hash(0) {
		return nil, fmt.Errorf("%w: %v", ErrUnknownDigestAlgorithm, verifierParams.Algorithm.String())
	}

	return &digestVerifier{factory: factory, params: verifierParams, hash: hash.New()}, nil
}

type digestVerifier struct {
	factory VerifierFactory
	params  *VerifierParameters

	hash hash.Hash
}

func (v *digestVerifier) Update(ctx context.Context, data []byte) error {
	_, err := v.hash.Write(data)
	return err
}

func (v *digestVerifier) Close(ctx context.Context, data []byte, signature []byte) error {
	if err := v.Update(ctx, data); err != nil {
		return err
	}

	if signature != nil {
		v.params.Signature = signature
	}

	return v.factory.Verify(ctx, v.params, v.hash.Sum(nil))
}

// NewCryptoSigner implements crypto.Signer (and optionally
// crypto.MessageSigner) on top of a Key that implements SignerFactory or
// RemoteDigestSignerFactory. This is useful for interop with a variety of other
// packages, including x509.
//
// If key implements SignerFactory, NewCryptoSigner will return a crypto.Signer.
//
// If key does not implement SignerFactory but implements
// RemoteDigestSignerFactory, NewCryptoSigner will return a
// crypto.MessageSigner. To force remote digest signing at all times, use
// NewCryptoMessageSigner.
//
// Additionally, key must always implement AsymmetricKey.
func NewCryptoSigner(ctx context.Context, key Key) (crypto.Signer, error) {
	pub, err := exportWellKnownPublicKey(ctx, key)
	if err != nil {
		return nil, err
	}

	if factory, ok := key.(SignerFactory); ok {
		return &cryptoSigner{ctx: ctx, pub: pub, factory: factory}, nil
	}

	// The rationale behind prioritizing SignerFactory over
	// RemoteDigestSignerFactory is that crypto.SignMessage (the function that
	// x509 calls for signing) will always prefer MessageSigner over Signer if
	// it is available. For a KMS that implements both, this would choose the
	// inefficient (i.e., bandwidth-heavy) route by default. If a review of the
	// to-be-signed blob on the server side is desired, this can be requested
	// explicitly via NewCryptoMessageSigner.

	if factory, ok := key.(RemoteDigestSignerFactory); ok {
		return &cryptoMessageSigner{ctx: ctx, pub: pub, factory: factory}, nil
	}

	return nil, errors.New("key is not a SignerFactory or RemoteDigestSignerFactory")
}

// NewCryptoMessageSigner implements crypto.MessageSigner on top of a Key
// that implements RemoteDigestSignerFactory. Additionally, key must implement
// AsymmetricKey. Also see NewCryptoSigner.
func NewCryptoMessageSigner(ctx context.Context, key Key) (crypto.MessageSigner, error) {
	pub, err := exportWellKnownPublicKey(ctx, key)
	if err != nil {
		return nil, err
	}

	if factory, ok := key.(RemoteDigestSignerFactory); ok {
		return &cryptoMessageSigner{ctx: ctx, pub: pub, factory: factory}, nil
	}

	return nil, errors.New("key is not a RemoteDigestSignerFactory")

}

// exportWellKnownPublicKey exports a crypto.PublicKey and ensures it is a type
// known by the standard library.
func exportWellKnownPublicKey(ctx context.Context, key Key) (crypto.PublicKey, error) {
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
		return pub, nil
	default:
		return nil, fmt.Errorf("expected well-known crypto.PublicKey type, got %T", pub)
	}
}

type cryptoSigner struct {
	ctx     context.Context
	pub     crypto.PublicKey
	factory SignerFactory
}

type cryptoMessageSigner struct {
	ctx     context.Context
	pub     crypto.PublicKey
	factory RemoteDigestSignerFactory
}

func (s *cryptoSigner) Public() crypto.PublicKey        { return s.pub }
func (s *cryptoMessageSigner) Public() crypto.PublicKey { return s.pub }

func (s *cryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	params, err := convertSignerOpts(s.Public(), opts)
	if err != nil {
		return nil, err
	}

	if hash := params.Algorithm.Hash(); hash != crypto.Hash(0) && hash.Size() != len(digest) {
		return nil, fmt.Errorf("digest size does not match expected size for hash function: %d vs %d",
			len(digest), hash.Size())
	}

	return s.factory.Sign(s.ctx, params, digest)
}

func (s *cryptoMessageSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Quoting the doc comment on crypto.MessageSigner:
	// > Implementations which do not provide the pre-hashed Sign API should
	// > implement Signer.Sign by always returning an error.
	return nil, errors.New("Sign is unavailable, use SignMessage")
}

func (s *cryptoMessageSigner) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	params, err := convertSignerOpts(s.Public(), opts)
	if err != nil {
		return nil, err
	}

	signer, err := s.factory.NewRemoteDigestSigner(s.ctx, params)
	if err != nil {
		return nil, err
	}

	return signer.Close(s.ctx, msg)
}

// convertSignerOpts converts crypto.SignerOpts into SignerParameters and
// validates they match the given public key.
func convertSignerOpts(pub crypto.PublicKey, opts crypto.SignerOpts) (*SignerParameters, error) {
	hash, params := opts.HashFunc(), &SignerParameters{}

	// Quoting the doc comment on crypto.MessageSigner:
	//
	// > MessageSigner.SignMessage and MessageSigner.Sign should produce the same
	// > result given the same opts. In particular, MessageSigner.SignMessage
	// > should only accept a zero opts.HashFunc if the Signer would also accept
	// > messages which are not pre-hashed.
	//
	// ...so we should still ensure that opts.HashFunc is correct, no matter if
	// this is called for Signer or MessageSigner.

	switch pub := pub.(type) {
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
			// TODO: Should we support it? We'd need to add an
			// algorithm-specific parameters field to SignParameters, much like
			// with AES-GCM for CipherParameters.
			return nil, errors.New("custom RSA PSS salt length is not supported")
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
		// NewCryptoSigner/NewCryptoMessageSigner should ensure that the public
		// key always matches one of the above well-known public key types.
		panic("unreachable")
	}

	return params, nil
}
