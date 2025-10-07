// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
)

// KeyType represents the type of cryptographic key. Public keys are reported
// differently than private keys as they may not have the same key usage.
// Systems with key pairs (where both are present or can be derived) are to
// report the corresponding private type, with key attributes satisfying both
// operations (can encrypt + can decrypt for instance with RSA-OAEP keys).
type KeyType int

const (
	KeyType_Generic_Secret KeyType = iota + 1
	KeyType_AES
	KeyType_RSA_Public
	KeyType_RSA_Private
	KeyType_EC_Public
	KeyType_EC_Private
	KeyType_ED_Public
	KeyType_ED_Private
)

func (k KeyType) String() string {
	switch k {
	case KeyType_Generic_Secret:
		return "generic"
	case KeyType_AES:
		return "aes"
	case KeyType_RSA_Public, KeyType_RSA_Private:
		return "rsa"
	case KeyType_EC_Public, KeyType_EC_Private:
		return "ec"
	case KeyType_ED_Public, KeyType_ED_Private:
		return "ed"
	}

	return fmt.Sprintf("(unknown %d)", k)
}

// Symmetric reports whether the KeyType is a symmetric key or an asymmetric
// key.
func (k KeyType) Symmetric() bool {
	switch k {
	case KeyType_Generic_Secret, KeyType_AES:
		return true
	}

	return false
}

// Curve represents an elliptic curve.
type Curve int

const (
	Curve_None Curve = iota
	Curve_P256
	Curve_P384
	Curve_P521
)

func (c Curve) String() string {
	switch c {
	case Curve_P256:
		return "p-256"
	case Curve_P384:
		return "p-384"
	case Curve_P521:
		return "p-521"
	}

	return fmt.Sprintf("(unknown %d)", c)
}

func (c Curve) OID() asn1.ObjectIdentifier {
	switch c {
	case Curve_P256:
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	case Curve_P384:
		return asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	case Curve_P521:
		return asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	}

	return nil
}

func (c Curve) Len() uint32 {
	switch c {
	case Curve_P256:
		return 256
	case Curve_P384:
		return 384
	case Curve_P521:
		return 521
	}

	return 0
}

// KeyAttributes represents basic key attributes and key usages (allowed operations).
//
// All attributes are expected to be non-sensitive, though may not
// necessarily be public.
type KeyAttributes struct {
	KeyId   string
	Name    string
	Version string

	// Group id should be the same when referring to the corresponding public
	// and private keys in a key pair, but different otherwise.
	GroupId string

	KeyType   KeyType
	Curve     Curve
	BitKeyLen uint32

	// Key usages
	CanEncrypt bool
	CanDecrypt bool
	CanWrap    bool
	CanUnwrap  bool
	CanSign    bool
	CanVerify  bool
	CanDerive  bool

	// Key material availability
	IsPersistent                bool
	IsRemovable                 bool
	IsSensitive                 bool
	IsDerivable                 bool
	IsExportable                bool
	IsExportableWithTrustedOnly bool
	IsTrusted                   bool

	// Provider-specific attributes.
	ProviderSpecific map[string]interface{}
}

// ProtectedKeyAttributes are attributes which are sensitive and should not
// be disclosed in normal operation.
type ProtectedKeyAttributes struct {
	// Provider-specific sensitive attributes.
	ProviderSpecific map[string]interface{}
}

// Globally defined provider-specific protected key attributes
const (
	// Password for protecting this key. Expected to be of type string.
	KeyAttributePassword string = "password"

	// Credential for protecting this key. Expected to be of type Credentials.
	KeyAttributeCredential string = "credential"
)

var ErrNoPublicKey error = errors.New("no corresponding public key")

// Key interface represents a cryptographic key
type Key interface {
	// Resolved - whether this key is shown to exist and has all attributes resolved.
	Resolved() bool

	// Resolve returns the resolved version of the key.
	Resolve(ctx context.Context) (Key, error)

	// Close terminates the key
	Close(ctx context.Context) error

	// Login logs in a user (application) to this specific key
	Login(ctx context.Context, credentials *Credentials) error

	// GetType returns the type of the given key.
	GetType() KeyType

	// GetId returns the Id of the given key
	GetId() string

	// GetName returns the name of the given key
	GetName() string

	// GetGroupId returns the Group Id of the given key
	GetGroupId() string

	// isPersistence returns the persistence of the given key
	IsPersistent() bool

	// IsSensitivity returns the sensitivity of the given key
	IsSensitive() bool

	// IsAsymmetric returns true if the given key satisfies also the
	// AsymmetricKey interface.
	IsAsymmetric() bool

	// GetLength returns the length in bits of the specified key
	// For a secret key, the length in bits of its value
	// For an RSA key, the length in bits of the modulus
	GetLength() uint32

	// GetKeyAttributes returns the non-sensitive key attributes. Returns nil
	// if the attributes are not resolved.
	GetKeyAttributes() *KeyAttributes

	// GetProtectedKeyAttributes returns the sensitive attributes. Returns nil
	// if the attributes are not resolved.
	GetProtectedKeyAttributes() *ProtectedKeyAttributes
}

type AsymmetricKey interface {
	// GetPublic returns the corresponding public key from an asymmetric
	// private key or key pair. When called on an invalid key, returns an
	// error that satisfies errors.Is(err, ErrNoPublicKey).
	GetPublic(ctx context.Context) (Key, error)

	// ExportPublic returns the ASN.1 form of the key, if available.
	ExportPublic(ctx context.Context) ([]byte, error)

	// ExportComponentPublic exports the component form of the key, if available.
	//
	// When Go's standard library implements a given type, we expect that to
	// be returned instead of a custom type.
	ExportComponentPublic(ctx context.Context) (interface{}, error)
}
