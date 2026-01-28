// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package securosyshsm

import (
	"context"
	b64 "encoding/base64"
	"errors"

	"github.com/openbao/go-kms-wrapping/kms/securosyshsm/v2/helpers"
	kms "github.com/openbao/go-kms-wrapping/v2/kms"
)

// Ensure KeyStore implements KeyStore
var _ kms.Verifier = (*verifier)(nil)

// Ensure KeyStoreFactory implements KeyStoreFactory
var _ kms.RemoteDigestVerifierFactory = (*MessageVerifierFactory)(nil)

type MessageVerifierFactory struct {
}

type verifier struct {
	key            *PublicKey
	verifierParams *kms.VerifierParameters
	buffer         []byte
	digest         bool
}

func (s *verifier) Update(ctx context.Context, data []byte) error {
	// Check for context cancellation before doing work
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	s.buffer = append(s.buffer, data...)
	return nil
}

func (s *verifier) Close(ctx context.Context, data []byte, signature []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	s.buffer = append(s.buffer, data...)
	if signature != nil {
		return s.verifySignature(signature)
	} else {
		return s.verifySignature(s.verifierParams.Signature)

	}
}

func (s *verifier) verifySignature(signature []byte) error {
	signatureAlgorithm, _ := helpers.MapSignAlgorithm(s.verifierParams.Algorithm, s.digest)
	result, _, err := s.key.client.Verify(
		s.key.GetName(),
		s.key.password,
		b64.StdEncoding.EncodeToString(s.buffer),
		signatureAlgorithm,
		b64.StdEncoding.EncodeToString(signature),
	)
	if err != nil {
		s.buffer = nil
		return err
	}
	s.buffer = nil
	if result == false {
		return errors.New("signature verification failed: provided signature is not valid")
	}
	return nil
}
func (s *verifier) DigestProvided(ctx context.Context) (err error) {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	s.digest = true
	// Check for context cancellation before doing work
	return nil
}

func (s MessageVerifierFactory) DigestVerify(ctx context.Context, verifierParams *kms.VerifierParameters, digest []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	newSigner, err := s.NewRemoteDigestVerifier(ctx, verifierParams)
	if err != nil {
		return err
	}
	verifier := newSigner.(*verifier)
	err = verifier.DigestProvided(ctx)
	if err != nil {
		return err
	}

	err = verifier.Close(ctx, digest, nil)
	if err != nil {
		return err
	}
	return nil
}

func (s MessageVerifierFactory) NewRemoteDigestVerifier(ctx context.Context, verifierParams *kms.VerifierParameters) (kms.Verifier, error) {
	publicKey := PublicKeyFromContext(ctx)
	/* FIXME: Enable key type check once PublicKey is implemented
	if publicKey.GetType() != kms.KeyType_RSA_Public && publicKey.GetType() != kms.KeyType_EC_Public && publicKey.GetType() != kms.KeyType_ED_Public {
		return nil, errors.New("invalid key type. Only RSA, EC or ED public keys are supported")
	}
	*/
	return &verifier{
		key:            publicKey,
		verifierParams: verifierParams,
		digest:         false,
	}, nil
}
