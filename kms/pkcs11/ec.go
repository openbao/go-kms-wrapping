// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/keybuilder"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

// newEC constructs a new ecKey.
func (p *pkcs11KMS) newEC(public, private object, mech *uint) (kms.Key, error) {
	var m uint
	if mech == nil {
		m = pkcs11.CKM_ECDSA
	} else {
		m = *mech
	}

	switch m {
	// pkcs11.CKM_ECDSA_SHA{X} variants can be added in the future if there is
	// desire for remote message hashing.
	case pkcs11.CKM_ECDSA:
	default:
		return nil, fmt.Errorf("unsupported EC key mechanism: %x", m)
	}

	exportPublic := onceOrCancel(func(ctx context.Context) (*ecdsa.PublicKey, error) {
		temp := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, 0),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, 0),
		}
		attr, err := session.Scope(ctx, p.pool, func(s *session.Handle) ([]*pkcs11.Attribute, error) {
			// NOTE: For CKK_EC keys, the public key can only be exported from
			// the public key handle, unlike RSA keys where attributes are
			// available on either object.
			return s.GetAttributeValue(public.handle, temp)
		})
		if err != nil {
			return nil, fmt.Errorf("export public key: %w", err)
		}
		curve, err := curveFromOID(attr[0].Value)
		if err != nil {
			// Give this one more try as a literal.
			curve, err = curveFromLiteral(attr[0].Value)
			if err != nil {
				return nil, fmt.Errorf("export public key: %w", err)
			}
		}
		var point []byte
		rest, err := asn1.Unmarshal(attr[1].Value, &point)
		switch {
		case err != nil:
			return nil, err
		case len(rest) != 0:
			return nil, errors.New("export public key: unexpected data remaining unmarshaling CKA_EC_POINT")
		}
		return ecdsa.ParseUncompressedPublicKey(curve, point)
	})

	return &ecKey{
		kms:       p,
		pubHandle: public.handle,
		prvHandle: private.handle,
		public:    exportPublic,
	}, nil
}

// ecKey wraps keys of type CKK_EC.
type ecKey struct {
	kms.UnimplementedKey

	kms       *pkcs11KMS
	pubHandle pkcs11.ObjectHandle
	prvHandle pkcs11.ObjectHandle

	// Exported public key.
	public func(ctx context.Context) (*ecdsa.PublicKey, error)
}

func (e *ecKey) Sign(ctx context.Context, opts *kms.SignOptions) ([]byte, error) {
	hash := opts.HashFunc()
	if hash == crypto.Hash(0) {
		return nil, errors.New("need hash function")
	}

	data := opts.Data
	if !opts.Prehashed {
		h := opts.HashFunc().New()
		_, _ = h.Write(data)
		data = h.Sum(nil)
	}

	mech := pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
	raw, err := session.Scope(ctx, e.kms.pool, func(s *session.Handle) ([]byte, error) {
		if err := s.SignInit(mech, e.prvHandle); err != nil {
			return nil, err
		}
		return s.Sign(data)
	})
	switch {
	case err != nil:
		return nil, err
	case len(raw) == 0, len(raw)%2 != 0:
		return nil, fmt.Errorf("invalid ECDSA signature length: %d", len(raw))
	}

	mid := len(raw) / 2
	return asn1.Marshal(struct{ R, S *big.Int }{
		R: new(big.Int).SetBytes(raw[:mid]),
		S: new(big.Int).SetBytes(raw[mid:]),
	})
}

func (e *ecKey) Verify(ctx context.Context, opts *kms.VerifyOptions) error {
	hash := opts.HashFunc()
	if hash == crypto.Hash(0) {
		return errors.New("need hash function")
	}

	data := opts.Data
	if !opts.Prehashed {
		h := opts.HashFunc().New()
		_, _ = h.Write(data)
		data = h.Sum(nil)
	}

	pub, err := e.public(ctx)
	if err != nil {
		return err
	}

	// Verifying via PKCS#11 is significant implementation overhead and likely
	// overkill. It would also require querying key parameters to apply the
	// correct padding, which gets us halfway to exporting the public key
	// anyway. For now, this'll do P-224, P-256, P-384 and P-521 via the
	// standard library - a `disable_software_verification` toggle can be added
	// in the future if desired.
	if ecdsa.VerifyASN1(pub, data, opts.Signature) {
		return nil
	}

	return kms.ErrInvalidSignature
}

func (e *ecKey) ExportPublic(ctx context.Context) (crypto.PublicKey, error) {
	return e.public(ctx)
}

// curveFromOID returns an elliptic curve by ASN.1 marshaled OID.
func curveFromOID(v []byte) (elliptic.Curve, error) {
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(v, &oid)
	switch {
	case err != nil:
		return nil, err
	case len(rest) != 0:
		return nil, errors.New("unexpected data remaining unmarshaling CKA_EC_PARAMS")
	}
	switch {
	case oid.Equal(keybuilder.CurveP224):
		return elliptic.P224(), nil
	case oid.Equal(keybuilder.CurveP256):
		return elliptic.P256(), nil
	case oid.Equal(keybuilder.CurveP384):
		return elliptic.P384(), nil
	case oid.Equal(keybuilder.CurveP521):
		return elliptic.P521(), nil
	}
	return nil, errors.New("unknown elliptic curve")
}

// curveFromLiteral returns an elliptic curve by name.
func curveFromLiteral(v []byte) (elliptic.Curve, error) {
	switch {
	case bytes.Equal(v, []byte("secp224r1")):
		return elliptic.P224(), nil
	case bytes.Equal(v, []byte("secp256r1")):
		return elliptic.P256(), nil
	case bytes.Equal(v, []byte("secp384r1")):
		return elliptic.P384(), nil
	case bytes.Equal(v, []byte("secp521r1")):
		return elliptic.P521(), nil
	}
	return nil, errors.New("unknown elliptic curve")
}
