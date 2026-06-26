// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// package keybuilder provides builders to create PKCS#11 key templates.
package keybuilder

import (
	"encoding/asn1"
	"fmt"

	"github.com/miekg/pkcs11"
)

// SecretBuilder is a builder for secret keys.
type SecretBuilder struct {
	mech *pkcs11.Mechanism
	temp map[uint]any
}

// PairBuilder is a builder for key pairs.
type PairBuilder struct {
	mech            *pkcs11.Mechanism
	public, private map[uint]any
}

// Secret initializes a SecretBuilder.
func Secret(mech uint) *SecretBuilder {
	return &SecretBuilder{
		mech: pkcs11.NewMechanism(mech, nil),
		temp: map[uint]any{
			pkcs11.CKA_TOKEN:     true,
			pkcs11.CKA_SENSITIVE: true,
		},
	}
}

// Pair initializes a PairBuilder.
func Pair(mech uint) *PairBuilder {
	return &PairBuilder{
		mech: pkcs11.NewMechanism(mech, nil),
		public: map[uint]any{
			pkcs11.CKA_TOKEN: true,
		},
		private: map[uint]any{
			pkcs11.CKA_TOKEN:     true,
			pkcs11.CKA_SENSITIVE: true,
		},
	}
}

// Attribute adds an attribute (or overwrites an existing one).
func (b *SecretBuilder) Attribute(typ uint, x any) *SecretBuilder {
	b.temp[typ] = x
	return b
}

// PublicAttribute adds an attribute to the public key half.
func (b *PairBuilder) PublicAttribute(typ uint, x any) *PairBuilder {
	b.public[typ] = x
	return b
}

// PrivateAttribute adds an attribute to the private key half.
func (b *PairBuilder) PrivateAttribute(typ uint, x any) *PairBuilder {
	b.private[typ] = x
	return b
}

// ID sets CKA_ID.
func (b *SecretBuilder) ID(id string) *SecretBuilder {
	b.temp[pkcs11.CKA_ID] = id
	return b
}

// Label sets CKA_LABEL.
func (b *SecretBuilder) Label(label string) *SecretBuilder {
	b.temp[pkcs11.CKA_LABEL] = label
	return b
}

// ID sets CKA_ID on both key halves.
func (b *PairBuilder) ID(id string) *PairBuilder {
	b.public[pkcs11.CKA_ID] = id
	b.private[pkcs11.CKA_ID] = id
	return b
}

// Label sets CKA_LABEL on both key halves.
func (b *PairBuilder) Label(label string) *PairBuilder {
	b.public[pkcs11.CKA_LABEL] = label
	b.private[pkcs11.CKA_LABEL] = label
	return b
}

// AES initializes a SecretBuilder for an AES key with the given byte size.
func AES(bytes int) *SecretBuilder {
	return Secret(pkcs11.CKM_AES_KEY_GEN).
		Attribute(pkcs11.CKA_VALUE_LEN, bytes).
		Attribute(pkcs11.CKA_ENCRYPT, true).
		Attribute(pkcs11.CKA_DECRYPT, true).
		Attribute(pkcs11.CKA_SENSITIVE, true)
}

// RSA initializes a PairBuilder for an RSA key pair with the given bit size.
func RSA(bits int) *PairBuilder {
	return Pair(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN).
		PublicAttribute(pkcs11.CKA_MODULUS_BITS, bits).
		PublicAttribute(pkcs11.CKA_VERIFY, true).
		PublicAttribute(pkcs11.CKA_ENCRYPT, true).
		PrivateAttribute(pkcs11.CKA_SIGN, true).
		PrivateAttribute(pkcs11.CKA_DECRYPT, true).
		PrivateAttribute(pkcs11.CKA_SENSITIVE, true)
}

// These are pre-defined OIDs that can be passed to [EC].
var (
	CurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	CurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	CurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	CurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

// EC initializes a PairBuilder for an EC key pair with the given curve.
func EC(curve asn1.ObjectIdentifier) *PairBuilder {
	b, err := asn1.Marshal(curve)
	if err != nil {
		panic(fmt.Errorf("OID should marshal: %w", err))
	}
	return Pair(pkcs11.CKM_EC_KEY_PAIR_GEN).
		PublicAttribute(pkcs11.CKA_EC_PARAMS, b).
		PublicAttribute(pkcs11.CKA_VERIFY, true).
		PublicAttribute(pkcs11.CKA_ENCRYPT, true).
		PrivateAttribute(pkcs11.CKA_SIGN, true).
		PrivateAttribute(pkcs11.CKA_DECRYPT, true).
		PrivateAttribute(pkcs11.CKA_SENSITIVE, true)
}

// Build returns the final mechanism and key template.
func (b *SecretBuilder) Build() (*pkcs11.Mechanism, []*pkcs11.Attribute) {
	var temp []*pkcs11.Attribute
	for typ, x := range b.temp {
		temp = append(temp, pkcs11.NewAttribute(typ, x))
	}
	return b.mech, temp
}

// Build returns the final mechanism and (public, private) key templates.
func (b *PairBuilder) Build() (*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) {
	var public, private []*pkcs11.Attribute
	for typ, x := range b.public {
		public = append(public, pkcs11.NewAttribute(typ, x))
	}
	for typ, x := range b.private {
		private = append(private, pkcs11.NewAttribute(typ, x))
	}
	return b.mech, public, private
}
