// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package securosyshsm

import (
	"context"
	b64 "encoding/base64"
	"errors"
	"time"

	"github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/helpers"
	kms "github.com/openbao/go-kms-wrapping/v2/kms"
)

// Ensure KeyStore implements KeyStore
var _ kms.Signer = (*signer)(nil)

type signer struct {
	key          *PrivateKey
	signerParams *kms.SignerParameters
	buffer       []byte
	digest       bool
}

func (s *signer) Update(ctx context.Context, data []byte) error {
	// Check for context cancellation before doing work
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	s.buffer = append(s.buffer, data...)
	return nil
}
func (s *signer) DigestProvided(ctx context.Context) (err error) {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	s.digest = true
	// Check for context cancellation before doing work
	return nil
}
func (s *signer) Close(ctx context.Context, data []byte) (signature []byte, err error) {
	// Check for context cancellation before doing work
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	s.buffer = append(s.buffer, data...)
	return s.Sign(ctx)
}

func (s *signer) Sign(ctx context.Context) ([]byte, error) {
	// Check for context cancellation before doing work
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	signatureAlgorithm, _ := helpers.MapSignAlgorithm(s.signerParams.Algorithm, s.digest)
	result, _, err := s.key.client.AsyncSign(
		s.key.GetName(),
		s.key.password,
		b64.StdEncoding.EncodeToString(s.buffer),
		"UNSPECIFIED",
		signatureAlgorithm,
		map[string]string{},
	)
	if err != nil {
		s.buffer = nil
		return nil, err
	}

	request, _, err := s.key.client.GetRequest(result)
	for request.Status == "PENDING" {
		if err != nil {
			s.buffer = nil
			return nil, err
		}
		time.Sleep(5 * time.Second)
		request, _, err = s.key.client.GetRequest(result)
	}
	if request.Status != "EXECUTED" {
		s.buffer = nil
		return nil, errors.New("Signer failed to execute. Signer returned status: " + request.Status)
	}
	s.buffer = nil
	signature, _ := b64.StdEncoding.DecodeString(request.Result)
	return signature, nil
}

type SignerFactory struct {
}

// Ensure KeyStoreFactory implements KeyStoreFactory
var _ kms.SignerFactory = (*SignerFactory)(nil)

func (s SignerFactory) DigestSign(ctx context.Context, signerParams *kms.SignerParameters, digest []byte) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	newSigner, err := s.NewSigner(ctx, signerParams)
	if err != nil {
		return nil, err
	}
	signer := newSigner.(*signer)
	err = signer.DigestProvided(ctx)
	if err != nil {
		return nil, err
	}

	bytes, err := signer.Close(ctx, digest)
	if err != nil {
		return nil, err
	}
	return bytes, nil

}

func (s SignerFactory) NewSigner(ctx context.Context, signerParams *kms.SignerParameters) (kms.Signer, error) {
	privateKey := PrivateKeyFromContext(ctx)
	if privateKey.GetType() != kms.KeyType_RSA_Private && privateKey.GetType() != kms.KeyType_EC_Private && privateKey.GetType() != kms.KeyType_ED_Private {
		return nil, errors.New("invalid key type. Only RSA, EC or ED keys are supported")
	}

	return &signer{
		key:          privateKey,
		signerParams: signerParams,
		digest:       false,
	}, nil
}
