// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

const (
	// IdAttr is CKA_ID. This attribute may be passed to GetKeyByAttrs as
	// []byte or string. It is always present as []byte in ProviderSpecific key
	// attributes.
	IdAttr = "id"

	// UniqueIdAttr is CKA_UNIQUE_ID. This attribute may be passed to
	// GetKeyByAttrs as []byte or string. It is always present as []byte in
	// ProviderSpecific key attributes.
	UniqueIdAttr = "unique-id"

	// LabelAttr is CKA_LABEL. This attribute may be passed to GetKeyByAttrs as
	// []byte or string. String values that start with "0x" are decoded as Hex.
	// It is always present as []byte in ProviderSpecific key attributes.
	LabelAttr = "label"

	// ClassAttr is CKA_CLASS. This attribute always available as uint in
	// ProviderSpecific attributes.
	ClassAttr = "class"

	// TypeAttr is CKA_KEY_TYPE. This attribute is always available as uint in
	// ProviderSpecific attributes.
	TypeAttr = "type"
)

// key is the base key type shared by all kms.Key implementations.
type key struct {
	pool *session.PoolRef

	// As-is CKA_ID, CKA_UNIQUE_ID and CKA_LABEL values.
	CKA_ID, CKA_UNIQUE_ID, CKA_LABEL []byte
	// As-is CKA_KEY_TYPE and CKA_CLASS values.
	CKA_KEY_TYPE, CKA_CLASS uint

	// Usage flags as booleans.
	CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY bool
	// Other flags as booleans.
	CKA_TOKEN, CKA_SENSITIVE, CKA_EXTRACTABLE bool

	// length is set per key type based on CKA_VALUE_LEN, CKA_EC_PARAMS or
	// CKA_MODULUS.
	length uint32

	// curve is set via CKA_EC_PARAMS for EC keys.
	curve kms.Curve
}

func (k *key) Resolved() bool                           { return true }
func (k *key) Resolve(context.Context) (kms.Key, error) { return k, nil }

func (k *key) GetId() string {
	switch {
	case len(k.CKA_UNIQUE_ID) != 0:
		return string(k.CKA_UNIQUE_ID)
	case len(k.CKA_LABEL) != 0 || len(k.CKA_ID) != 0:
		return fmt.Sprintf("%s:%s", k.CKA_LABEL, k.CKA_ID)
	default:
		return ""
	}
}

func (k *key) GetName() string    { return string(k.CKA_LABEL) }
func (k *key) GetGroupId() string { return string(k.CKA_ID) }

func (k *key) IsSensitive() bool  { return k.CKA_SENSITIVE }
func (k *key) IsPersistent() bool { return k.CKA_TOKEN }

func (k *key) GetLength() uint32 { return k.length }

func (k *key) GetType() kms.KeyType {
	switch k.CKA_CLASS {
	case pkcs11.CKO_SECRET_KEY:
		switch k.CKA_KEY_TYPE {
		case pkcs11.CKK_AES:
			return kms.KeyType_AES
		default:
			return kms.KeyType_Generic_Secret
		}

	case pkcs11.CKO_PUBLIC_KEY:
		switch k.CKA_KEY_TYPE {
		case pkcs11.CKK_EC:
			return kms.KeyType_EC_Public
		case pkcs11.CKK_RSA:
			return kms.KeyType_RSA_Public
		}

	case pkcs11.CKO_PRIVATE_KEY:
		switch k.CKA_KEY_TYPE {
		case pkcs11.CKK_EC:
			return kms.KeyType_EC_Private
		case pkcs11.CKK_RSA:
			return kms.KeyType_RSA_Private
		}
	}

	return kms.KeyType(0)
}

func (k *key) GetKeyAttributes() *kms.KeyAttributes {
	return &kms.KeyAttributes{
		KeyId:        k.GetId(),
		Name:         k.GetName(),
		GroupId:      k.GetGroupId(),
		KeyType:      k.GetType(),
		Curve:        k.curve,
		BitKeyLen:    k.length,
		CanEncrypt:   k.CKA_ENCRYPT,
		CanDecrypt:   k.CKA_DECRYPT,
		CanSign:      k.CKA_SIGN,
		CanVerify:    k.CKA_VERIFY,
		IsSensitive:  k.CKA_SENSITIVE,
		IsExportable: k.CKA_EXTRACTABLE,
		IsPersistent: k.CKA_TOKEN,
		ProviderSpecific: map[string]any{
			IdAttr:       k.CKA_ID,
			UniqueIdAttr: k.CKA_UNIQUE_ID,
			LabelAttr:    k.CKA_LABEL,
			ClassAttr:    k.CKA_CLASS,
			TypeAttr:     k.CKA_KEY_TYPE,
		},
	}
}

func (k *key) GetProtectedKeyAttributes() *kms.ProtectedKeyAttributes {
	return &kms.ProtectedKeyAttributes{}
}

func (k *key) IsAsymmetric() bool {
	// This is overridden by public/private/pair types.
	return false
}

func (k *key) Close(ctx context.Context) error {
	return nil
}

func (k *key) Login(ctx context.Context, creds *kms.Credentials) error {
	// This would likely map to CKA_ALWAYS_AUTHENTICATE + CKU_CONTEXT_SPECIFIC.
	// This is a niche feature that is difficult to implement in terms of
	// session handling, so it is omitted for the time being.
	return errors.New("unimplemented")
}

// secret is a secret key (Supported types: AES).
type secret struct {
	*key
	obj pkcs11.ObjectHandle
}

// pair is a key pair (Supported types: RSA, EC).
type pair struct {
	*key
	pub, prv pkcs11.ObjectHandle
}

// public is a public key (Supported types: RSA, EC)
type public struct {
	*key
	obj pkcs11.ObjectHandle
}

// private is a private key (Supported types: RSA, EC).
type private struct {
	*key
	obj pkcs11.ObjectHandle
}

func (*secret) IsAsymmetric() bool  { return false }
func (*pair) IsAsymmetric() bool    { return true }
func (*public) IsAsymmetric() bool  { return true }
func (*private) IsAsymmetric() bool { return true }

// toPair merges key halves into one key pair.
func toPair(pub *public, prv *private) (*pair, error) {
	if pub.CKA_KEY_TYPE != prv.CKA_KEY_TYPE {
		return nil, fmt.Errorf("cannot construct key pair: got %s public key and %s private key",
			pub.GetType(), prv.GetType())
	}

	prv.CKA_VERIFY = pub.CKA_VERIFY
	prv.CKA_ENCRYPT = pub.CKA_ENCRYPT

	return &pair{
		key: prv.key,
		pub: pub.obj, prv: prv.obj,
	}, nil
}

// NOTE: These cannot be generically implemented on key only as that would
// return the embedded type only.
func (s *secret) Resolve(ctx context.Context) (kms.Key, error)  { return s, nil }
func (p *pair) Resolve(ctx context.Context) (kms.Key, error)    { return p, nil }
func (p *public) Resolve(ctx context.Context) (kms.Key, error)  { return p, nil }
func (p *private) Resolve(ctx context.Context) (kms.Key, error) { return p, nil }

// miekg/pkcs11 only has PKCS#11 v2.x functions and constants. CKA_UNIQUE_ID
// is v3.0+ but easily queryable from a v2 "client", so declare it as a local
// constant here.
const _CKA_UNIQUE_ID = 0x00000004

// fromObject constructs a key from an object handle by querying various
// attributes.
func fromObject(s *session.Handle, p *session.PoolRef, obj pkcs11.ObjectHandle) (kms.Key, error) {
	base := key{pool: p}

	// These are generic attributes that can always be queried. Specialized
	// attributes are retrieved in follow-up queries below.
	temp := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, 0),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, 0),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, 0),
	}

	version := p.Module().Info().CryptokiVersion
	if version.Major >= 3 {
		temp = append(temp, pkcs11.NewAttribute(_CKA_UNIQUE_ID, 0))
	}

	attrs, err := s.GetAttributeValue(obj, temp)
	if err != nil {
		return nil, err
	}

	for _, attr := range attrs {
		switch attr.Type {
		case pkcs11.CKA_ID:
			base.CKA_ID = attr.Value
		case pkcs11.CKA_LABEL:
			base.CKA_LABEL = attr.Value
		case pkcs11.CKA_CLASS:
			base.CKA_CLASS, err = bytesToUint(attr.Value)
		case _CKA_UNIQUE_ID:
			base.CKA_UNIQUE_ID = attr.Value
		}
		if err != nil {
			return nil, err
		}
	}

	// Next, query boolean flags based on object class.
	temp = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_TOKEN, 0)}

	switch base.CKA_CLASS {
	case pkcs11.CKO_SECRET_KEY:
		temp = append(temp,
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, 0),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, 0),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, 0),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, 0),
		)
	case pkcs11.CKO_PRIVATE_KEY:
		temp = append(temp,
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, 0),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, 0),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, 0),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, 0),
		)
	case pkcs11.CKO_PUBLIC_KEY:
		temp = append(temp,
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, 0),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, 0),
		)
	default:
		// A generic object that we don't specially handle yet.
		return &base, nil
	}

	attrs, err = s.GetAttributeValue(obj, temp)
	if err != nil {
		return nil, err
	}

	for _, attr := range attrs {
		val, err := bytesToUint(attr.Value)
		if err != nil {
			return nil, err
		}
		if val != 1 {
			continue
		}
		switch attr.Type {
		case pkcs11.CKA_SIGN:
			base.CKA_SIGN = true
		case pkcs11.CKA_VERIFY:
			base.CKA_VERIFY = true
		case pkcs11.CKA_ENCRYPT:
			base.CKA_ENCRYPT = true
		case pkcs11.CKA_DECRYPT:
			base.CKA_DECRYPT = true
		case pkcs11.CKA_TOKEN:
			base.CKA_TOKEN = true
		case pkcs11.CKA_SENSITIVE:
			base.CKA_SENSITIVE = true
		case pkcs11.CKA_EXTRACTABLE:
			base.CKA_EXTRACTABLE = true
		}
	}

	// Next, query the key type. This cannot be part of the initial query
	// alongside CKA_CLASS as non-key objects (e.g., certificates) do not
	// support this attribute.
	temp = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0)}
	attrs, err = s.GetAttributeValue(obj, temp)
	if err != nil {
		return nil, err
	}
	base.CKA_KEY_TYPE, err = bytesToUint(attrs[0].Value)
	if err != nil {
		return nil, err
	}

	switch base.CKA_KEY_TYPE {
	case pkcs11.CKK_AES:
		return newAES(s, &base, obj)
	case pkcs11.CKK_RSA:
		return newRSA(s, &base, obj)
	case pkcs11.CKK_EC:
		return newEC(s, &base, obj)
	default:
		// A key object that we don't specially handle yet.
		return &base, nil
	}
}

// newAES constructs an AES kms.Key.
func newAES(s *session.Handle, base *key, obj pkcs11.ObjectHandle) (kms.Key, error) {
	temp := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil)}
	attrs, err := s.GetAttributeValue(obj, temp)
	if err != nil {
		return nil, err
	}

	val, err := bytesToUint(attrs[0].Value)
	if err != nil {
		return nil, err
	}
	if val != pkcs11.CK_UNAVAILABLE_INFORMATION {
		// CKA_VALUE_LEN is byte size, not bit size.
		base.length = uint32(val) * 8
	}

	switch base.CKA_CLASS {
	case pkcs11.CKO_SECRET_KEY:
		return &secret{key: base, obj: obj}, nil
	default:
		return nil, fmt.Errorf("expected secret key class, got class %d", base.CKA_CLASS)
	}
}

// newRSA constructs an RSA kms.Key.
func newRSA(s *session.Handle, base *key, obj pkcs11.ObjectHandle) (kms.Key, error) {
	temp := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil)}
	attrs, err := s.GetAttributeValue(obj, temp)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(attrs[0].Value)
	base.length = uint32(n.BitLen())

	switch base.CKA_CLASS {
	case pkcs11.CKO_PUBLIC_KEY:
		return &public{key: base, obj: obj}, nil
	case pkcs11.CKO_PRIVATE_KEY:
		return &private{key: base, obj: obj}, nil
	default:
		return nil, fmt.Errorf("expected public or private key class, got class %d", base.CKA_CLASS)
	}
}

// newEC constructs an EC kms.Key.
func newEC(s *session.Handle, base *key, obj pkcs11.ObjectHandle) (kms.Key, error) {
	temp := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil)}
	attrs, err := s.GetAttributeValue(obj, temp)
	if err != nil {
		return nil, err
	}

	curve, err := curveFromOID(attrs[0].Value)
	if err != nil {
		// Give this one more try as a string.
		curve = curveFromLiteral(attrs[0].Value)
		if curve == kms.Curve_None {
			return nil, err
		}
	}

	base.curve = curve
	base.length = curve.Len()

	switch base.CKA_CLASS {
	case pkcs11.CKO_PUBLIC_KEY:
		return &public{key: base, obj: obj}, nil
	case pkcs11.CKO_PRIVATE_KEY:
		return &private{key: base, obj: obj}, nil
	default:
		return nil, fmt.Errorf("expected public or private key class, got class %d", base.CKA_CLASS)
	}
}

// pairFromObjects creates a key pair from two object handles. This is primarily
// useful in tests that generate the key pair itself and want the respective
// combined key representation.
func pairFromObjects(s *session.Handle, p *session.PoolRef, pub, prv pkcs11.ObjectHandle) (*pair, error) {
	k, err := fromObject(s, p, pub)
	if err != nil {
		return nil, err
	}
	pubkey, ok := k.(*public)
	if !ok {
		return nil, fmt.Errorf("expected *public key, got %T", k)
	}

	k, err = fromObject(s, p, prv)
	if err != nil {
		return nil, err
	}
	prvkey, ok := k.(*private)
	if !ok {
		return nil, fmt.Errorf("expected *private key, got %T", k)
	}

	return toPair(pubkey, prvkey)
}

// bytesToUint converts a byte slice to uint.
func bytesToUint(value []byte) (uint, error) {
	switch len(value) {
	case 1:
		return uint(value[0]), nil
	case 2:
		return uint(binary.NativeEndian.Uint16(value)), nil
	case 4:
		return uint(binary.NativeEndian.Uint32(value)), nil
	case 8:
		u64 := binary.NativeEndian.Uint64(value)
		if u64 > math.MaxUint {
			return 0, errors.New("value exceeds max uint")
		}
		return uint(u64), nil
	default:
		return 0, fmt.Errorf("cannot convert byte slice of length %d to uint", len(value))
	}
}

// curveFromOID determines a kms.Curve by interpreting bytes as an ASN.1 encoded OID.
func curveFromOID(val []byte) (kms.Curve, error) {
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(val, &oid)
	switch {
	case err != nil:
		return kms.Curve_None, err
	case len(rest) != 0:
		return kms.Curve_None, errors.New("unexpected data remaining after asn1 unmarshal")
	}

	for _, curve := range []kms.Curve{kms.Curve_P256, kms.Curve_P384, kms.Curve_P521} {
		if oid.Equal(curve.OID()) {
			return curve, nil
		}
	}

	return kms.Curve_None, errors.New("unsupported/unknown curve")
}

// curveFromLiteral determines a kms.Curve by interpreting bytes as a string.
// Some vendors store named curves as ASCII strings instead of OIDs.
func curveFromLiteral(val []byte) kms.Curve {
	switch {
	case bytes.Equal(val, []byte("secp256r1")):
		return kms.Curve_P256
	case bytes.Equal(val, []byte("secp384r1")):
		return kms.Curve_P384
	case bytes.Equal(val, []byte("secp521r1")):
		return kms.Curve_P521
	default:
		return kms.Curve_None
	}
}
