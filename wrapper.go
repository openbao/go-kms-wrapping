// Copyright The OpenBao Contributors
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package wrapping

import (
	"context"
	"crypto"
)

type HmacComputer interface {
	// HmacKeyID is the ID of the key currently used for HMACing (if any)
	HmacKeyId(context.Context) (string, error)
}

type InitFinalizer interface {
	// Init allows performing any necessary setup calls before using a
	// Wrapper or Hub.
	Init(ctx context.Context, options ...Option) error

	// Finalize can be called when all usage of a Wrapper or Hub
	// is done if any cleanup or finalization is required.
	Finalize(ctx context.Context, options ...Option) error
}

// Wrapper is an an interface where supporting implementations allow for
// encrypting and decrypting data.
type Wrapper interface {
	// Type is the type of Wrapper
	Type(context.Context) (WrapperType, error)

	// KeyId is the ID of the key currently used for encryption
	KeyId(context.Context) (string, error)

	// SetConfig applies the given options to a Wrapper and returns
	// configuration information. WithConfigMap will almost certainly be
	// required to be passed in to provide wrapper-specific configuration.
	SetConfig(ctx context.Context, options ...Option) (*WrapperConfig, error)

	// Encrypt encrypts the given byte slice and stores the resulting
	// information in the returned blob info. Which options are used
	// depends on the underlying wrapper.
	Encrypt(ctx context.Context, plaintext []byte, options ...Option) (*BlobInfo, error)
	// Decrypt decrypts the given byte slice and stores the resulting
	// information in the returned byte slice. Which options are used
	// depends on the underlying wrapper.
	Decrypt(ctx context.Context, ciphertext *BlobInfo, options ...Option) ([]byte, error)
}

// KeyExporter defines an optional interface for wrappers to implement that returns
// the "current" key bytes. This will be implementation-specific.
type KeyExporter interface {
	// KeyBytes returns the "current" key bytes
	KeyBytes(context.Context) ([]byte, error)
}

// Hub is a hub for keys within a certain pool, e.g. a
// PKCS#11 token slot. Specific keys with varying capabilities can
// be accessed using GetKey.
type Hub interface {
	// SetConfig applies the given options to a Hub.
	// WithConfigMap will almost certainly be required to be passed in to
	// provide wrapper-specific configuration. Supported options will be
	// ones for general client configuration. Key-level configuration is
	// passed to GetKey.
	SetConfig(ctx context.Context, options ...Option) error
	// GetKey gets an opaque ExternalKey.
	// Supported options will let you bind to a specific key in the KMS.
	// Generic client-level configuration is passed in SetConfig.
	GetKey(ctx context.Context, options ...Option) (ExternalKey, error)
}

// ExternalKey is an opaque key that may support the following interfaces:
//   - crypto.Signer
//   - crypto.Decrypter
//
// You may type-assert an ExternalKey into either of these interfaces,
// however you should prefer the explicit Signer and Decrypter methods
// to retain support for type assertions over gRPC connections with go-plugin.
type ExternalKey interface {
	Signer() (crypto.Signer, bool)
	Decrypter() (crypto.Decrypter, bool)
}
