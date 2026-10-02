// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/pkcs11v3"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

// newMLDSA constructs a new mldsaKey.
func newMLDSA(pool *session.PoolRef, public, private object, mech *uint) (kms.Key, error) {
	var m uint
	if mech == nil {
		m = pkcs11v3.CKM_ML_DSA
	} else {
		m = *mech
	}

	switch m {
	case pkcs11v3.CKM_ML_DSA:
	default:
		return nil, fmt.Errorf("unsupported ML-DSA key mechanism: %x", m)
	}

	exportPublic := onceOrCancel(func(ctx context.Context) (*mldsa.PublicKey, error) {
		temp := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11v3.CKA_PARAMETER_SET, 0),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, 0),
		}
		attr, err := session.Scope(ctx, pool, func(s *session.Handle) ([]*pkcs11.Attribute, error) {
			return s.GetAttributeValue(public.handle, temp)
		})
		if err != nil {
			return nil, fmt.Errorf("export public key attributes: %w", err)
		}
		ckp, err := bytesToUint(attr[0].Value)
		if err != nil {
			return nil, fmt.Errorf("export public key: parse CKA_PARAMETER_SET: %w", err)
		}
		var params mldsa.Parameters
		switch ckp {
		case pkcs11v3.CKP_ML_DSA_44:
			params = mldsa.MLDSA44()
		case pkcs11v3.CKP_ML_DSA_65:
			params = mldsa.MLDSA65()
		case pkcs11v3.CKP_ML_DSA_87:
			params = mldsa.MLDSA87()
		default:
			return nil, fmt.Errorf("export public key: unknown CKA_PARAMETER_SET: %x", ckp)
		}
		return mldsa.NewPublicKey(params, attr[1].Value)
	})

	return &mldsaKey{
		pool:   pool,
		handle: private.handle,
		public: exportPublic,
	}, nil
}

type mldsaKey struct {
	kms.UnimplementedKey

	pool   *session.PoolRef
	handle pkcs11.ObjectHandle

	// Exported public key.
	public func(ctx context.Context) (*mldsa.PublicKey, error)
}

func (m *mldsaKey) Sign(ctx context.Context, opts *kms.SignOptions) ([]byte, error) {
	switch opts.HashFunc() {
	case crypto.Hash(0):
	case crypto.MLDSAMu:
		return nil, errors.New("external ML-DSA Mu is not supported")
	default:
		return nil, errors.New("HashML-DSA is not supported")
	}

	if o, ok := opts.SignerOpts.(*mldsa.Options); ok && o.Context != "" {
		return nil, errors.New("ML-DSA with context parameter is not supported")
	}

	mech := pkcs11.NewMechanism(pkcs11v3.CKM_ML_DSA, nil)
	return session.Scope(ctx, m.pool, func(s *session.Handle) ([]byte, error) {
		if err := s.SignInit(mech, m.handle); err != nil {
			return nil, err
		}
		return s.Sign(opts.Data)
	})
}

func (m *mldsaKey) Verify(ctx context.Context, opts *kms.VerifyOptions) error {
	switch opts.HashFunc() {
	case crypto.Hash(0):
	case crypto.MLDSAMu:
		return errors.New("external ML-DSA Mu is not supported")
	default:
		return errors.New("HashML-DSA is not supported")
	}

	pub, err := m.public(ctx)
	if err != nil {
		return err
	}

	if err := mldsa.Verify(pub, opts.Data, opts.Signature, nil); err != nil {
		return fmt.Errorf("%w: %w", kms.ErrInvalidSignature, err)
	}

	return nil
}

func (m *mldsaKey) ExportPublic(ctx context.Context) (crypto.PublicKey, error) {
	return m.public(ctx)
}
