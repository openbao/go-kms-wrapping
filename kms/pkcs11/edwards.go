// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/keybuilder"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/pkcs11v3"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

// newEdwards constructs a new edwardsKey.
func newEdwards(pool *session.PoolRef, public, private object, mech *uint) (kms.Key, error) {
	var m uint
	if mech == nil {
		m = pkcs11v3.CKM_EDDSA
	} else {
		m = *mech
	}

	switch m {
	case pkcs11v3.CKM_EDDSA:
	default:
		return nil, fmt.Errorf("unsupported edwards key mechanism: %x", m)
	}

	exportPublic := onceOrCancel(func(ctx context.Context) (ed25519.PublicKey, error) {
		temp := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, 0),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, 0),
		}
		attr, err := session.Scope(ctx, pool, func(s *session.Handle) ([]*pkcs11.Attribute, error) {
			return s.GetAttributeValue(public.handle, temp)
		})
		if err != nil {
			return nil, fmt.Errorf("export public key attributes: %w", err)
		}

		// Ensure this is an Ed25519 key, not Ed448. The standard library only
		// supports the former, so there's little gain in supporting an export
		// of the latter.
		if !isEd25519(attr[0].Value) {
			return nil, errors.New("export public key: supports only Ed25519")
		}

		// CKA_EC_POINT may either be the raw public key (32 bytes), or
		// DER-encoded. If sizes match, assume it is raw and finish here.
		if len(attr[1].Value) == ed25519.PublicKeySize {
			return ed25519.PublicKey(attr[1].Value), nil
		}

		var raw []byte
		rest, err := asn1.Unmarshal(attr[1].Value, &raw)
		switch {
		case err != nil:
			return nil, fmt.Errorf("unexpected public key encoding: neither a %d-byte raw key nor DER-encoded", ed25519.PublicKeySize)
		case len(rest) != 0:
			return nil, fmt.Errorf("unexpected public key size: got %d trailing bytes", len(rest))
		case len(raw) != ed25519.PublicKeySize:
			return nil, fmt.Errorf("unexpected public key size: want %d, got %d",
				ed25519.PublicKeySize, len(raw))
		}

		return ed25519.PublicKey(raw), nil
	})

	return &edwardsKey{
		pool:   pool,
		handle: private.handle,
		public: exportPublic,
	}, nil
}

type edwardsKey struct {
	kms.UnimplementedKey

	pool   *session.PoolRef
	handle pkcs11.ObjectHandle

	// Exported public key.
	public func(ctx context.Context) (ed25519.PublicKey, error)
}

func (e *edwardsKey) Sign(ctx context.Context, opts *kms.SignOptions) ([]byte, error) {
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("pre-hashed EdDSA is not supported")
	}

	if o, ok := opts.SignerOpts.(*ed25519.Options); ok && o.Context != "" {
		return nil, errors.New("Ed25519ctx is not supported")
	}

	mech := pkcs11.NewMechanism(pkcs11v3.CKM_EDDSA, nil)
	return session.Scope(ctx, e.pool, func(s *session.Handle) ([]byte, error) {
		if err := s.SignInit(mech, e.handle); err != nil {
			return nil, err
		}
		return s.Sign(opts.Data)
	})
}

func (e *edwardsKey) Verify(ctx context.Context, opts *kms.VerifyOptions) error {
	if opts.HashFunc() != crypto.Hash(0) || opts.Prehashed {
		return errors.New("pre-hashed EdDSA is not supported")
	}

	pub, err := e.public(ctx)
	if err != nil {
		return err
	}

	if ed25519.Verify(pub, opts.Data, opts.Signature) {
		return nil
	}

	return kms.ErrInvalidSignature
}

func (e *edwardsKey) ExportPublic(ctx context.Context) (crypto.PublicKey, error) {
	return e.public(ctx)
}

// isEd25519 inspects a CKA_EC_PARAMS returns true if it matches a well-known
// encoding for Ed25519.
func isEd25519(params []byte) bool {
	if bytes.Equal(params, []byte("edwards25519")) {
		return true
	}
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(params, &oid)
	if err != nil || len(rest) != 0 {
		return false
	}
	return oid.Equal(keybuilder.OIDEd25519)
}
