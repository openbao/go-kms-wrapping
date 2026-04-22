// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"fmt"

	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

// newAES constructs a new aesKey.
func (p *pkcs11KMS) newAES(o object, mech *uint) (kms.Key, error) {
	var m uint
	if mech == nil {
		m = pkcs11.CKM_AES_GCM
	} else {
		m = *mech
	}

	switch m {
	// Add more if truly needed.
	case pkcs11.CKM_AES_GCM:
	default:
		return nil, fmt.Errorf("unsupported AES key mechanism: %x", m)
	}

	// Small struct compared to other key types, value receivers should be good.
	return aesKey{
		kms:    p,
		handle: o.handle,
	}, nil
}

// aesKey wraps keys of type CKK_AES.
type aesKey struct {
	kms.UnimplementedKey

	kms    *pkcs11KMS
	handle pkcs11.ObjectHandle
}

func (a aesKey) Encrypt(ctx context.Context, opts *kms.CipherOptions) ([]byte, error) {
	return session.Scope(ctx, a.kms.pool, func(s *session.Handle) ([]byte, error) {
		nonce, err := s.GenerateRandom(12) // 96-bit nonce.
		if err != nil {
			return nil, fmt.Errorf("generate nonce: %w", err)
		}
		params := pkcs11.NewGCMParams(nonce, opts.AAD, 128) // 128-bit tag.
		defer params.Free()
		if err := s.EncryptInit(pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params), a.handle); err != nil {
			return nil, err
		}
		ciphertext, err := s.Encrypt(opts.Data)
		if err != nil {
			return nil, err
		}
		opts.Nonce = params.IV()
		return ciphertext, nil
	})
}

func (a aesKey) Decrypt(ctx context.Context, opts *kms.CipherOptions) ([]byte, error) {
	return session.Scope(ctx, a.kms.pool, func(s *session.Handle) ([]byte, error) {
		params := pkcs11.NewGCMParams(opts.Nonce, opts.AAD, 128)
		defer params.Free()
		if err := s.DecryptInit(pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params), a.handle); err != nil {
			return nil, err
		}
		return s.Decrypt(opts.Data)
	})
}
