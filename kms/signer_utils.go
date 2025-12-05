// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
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

var _ crypto.Signer = (*Certx509SigningKey)(nil)
var _ crypto.MessageSigner = (*Certx509SigningKey)(nil)

type Certx509SigningKey struct {
	SignPrivateKey Key
	SignAlgo       SignAlgorithm // If specified, use this algorithm for signing x509 certificates. Otherwise, infer from key type.
}

func (sk *Certx509SigningKey) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error) {

	var signAlgo SignAlgorithm = sk.SignAlgo
	ctx := context.Background()

	if signAlgo == SignAlgo_Unknown {
		// Infer signing algorithm from key type (see crypto/x509)
		switch (sk.SignPrivateKey).GetType() {
		case KeyType_RSA_Private:
			signAlgo = SignAlgo_RSA_PKCS1_PSS_SHA_256
		case KeyType_EC_Private:
			signAlgo = SignAlgo_EC_P256
			/* FIXME: Enable curve-based sign algorithm selection once EC key curve is implemented
			switch sk.key.key.GetCurve() {
			case "P-256":
				signAlgo = SignAlgo_EC_P256
			case "P-384":
				signAlgo = SignAlgo_EC_P384
			case "P-521":
				signAlgo = SignAlgo_EC_P521
			default:
				return nil, errors.New("unsupported EC curve for signing")
			}
			*/
		case KeyType_ED_Private:
			signAlgo = SignAlgo_ED
		default:
			return nil, errors.New("unsupported key type for signing")
		}
	}

	if signAlgo == SignAlgo_ED {
		if signerFactory, ok := (sk.SignPrivateKey).(RemoteDigestSignerFactory); ok {
			signer, err := signerFactory.NewRemoteDigestSigner(ctx, &SignerParameters{
				Algorithm: signAlgo,
			})
			if err != nil || signer == nil {
				return nil, err
			}

			signature, err = signer.Close(ctx, message)

			return signature, err

		} else {
			return nil, errors.New("provided key cannot be used for x509 certificate signing")
		}
	}

	if signerFactory, ok := (sk.SignPrivateKey).(SignerFactory); ok {
		return signerFactory.Sign(ctx, &SignerParameters{
			Algorithm: signAlgo,
		}, message)

	} else {
		return nil, errors.New("provided key cannot be used for x509 certificate signing")
	}
}

func (sk *Certx509SigningKey) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	var signAlgo SignAlgorithm = sk.SignAlgo
	ctx := context.Background()

	if signAlgo == SignAlgo_Unknown {
		// Infer signing algorithm from key type (see crypto/x509)
		switch (sk.SignPrivateKey).GetType() {
		case KeyType_RSA_Private:
			if pssOptions, ok := opts.(*rsa.PSSOptions); ok {
				switch pssOptions.Hash {
				case crypto.SHA256:
					signAlgo = SignAlgo_RSA_PKCS1_PSS_SHA_256
				case crypto.SHA384:
					signAlgo = SignAlgo_RSA_PKCS1_PSS_SHA_384
				case crypto.SHA512:
					signAlgo = SignAlgo_RSA_PKCS1_PSS_SHA_512
				default:
					return nil, errors.New("unsupported hash for RSA-PSS signing")
				}
			} else {
				return nil, errors.New("RSA PKCS #1 v1.5 signing is not supported for x509 certificates")
			}

		case KeyType_EC_Private:
			if opts.HashFunc() != crypto.SHA256 {
				return nil, errors.New("unsupported hash for ECDSA signing")
			}

			keyAttr := sk.SignPrivateKey.GetKeyAttributes()

			switch keyAttr.Curve {
			case Curve_P256:
				signAlgo = SignAlgo_EC_P256
			case Curve_P384:
				signAlgo = SignAlgo_EC_P384
			case Curve_P521:
				signAlgo = SignAlgo_EC_P521
			default:
				return nil, errors.New("unsupported EC curve for signing")
			}
		case KeyType_ED_Private:
			signAlgo = SignAlgo_ED
		default:
			return nil, errors.New("unsupported key type for signing")
		}
	}

	if signerFactory, ok := (sk.SignPrivateKey).(RemoteDigestSignerFactory); ok {
		signer, err := signerFactory.NewRemoteDigestSigner(ctx, &SignerParameters{
			Algorithm: signAlgo,
		})
		if err != nil || signer == nil {
			return nil, err
		}

		signature, err = signer.Close(ctx, msg)

		return signature, err

	} else {
		return nil, errors.New("provided key cannot be used for x509 certificate signing")
	}
}

func (sk *Certx509SigningKey) Public() crypto.PublicKey {
	// Extract the public key from the private key
	ctx := context.Background()
	if privateKey, ok := (sk.SignPrivateKey).(AsymmetricKey); ok {
		derBytes, err := privateKey.ExportPublic(ctx)
		if err != nil {
			// Return nil if we can't extract the public key
			return nil
		}

		// Parse the DER bytes into a crypto.PublicKey
		pubKey, err := x509.ParsePKIXPublicKey(derBytes)
		if err != nil {
			// Return nil if we can't parse the public key
			return nil
		}

		return pubKey
	} else {
		return nil
	}
}
