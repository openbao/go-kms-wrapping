// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
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
	// Wrapper or ExternalKey.
	Init(ctx context.Context, options ...Option) error

	// Finalize can be called when all usage of a Wrapper or ExternalKey
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

// ExternalKey is an interface where supporting implementations enable access
// to cryptographic operations via the standard library's crypto.Signer and
// crypto.Decrypter interfaces.
type ExternalKey interface {
	// SetConfig applies the given options to an ExternalKey.
	// WithConfigMap will almost certainly be required to be passed in to
	// provide wrapper-specific configuration. Supported options will be
	// ones for general client configuration and not bound to a specific
	// key. To access keys after setting the configuration, see GetKey.
	SetConfig(ctx context.Context, options ...Option) error
	// Signer retrieves a crypto.Signer.
	// Supported options will let you bind to a specific key in the KMS,
	// generic client-level configuration is passed in SetConfig.
	Signer(ctx context.Context, options ...Option) (crypto.Signer, error)
	// Decrypter retrieves a crypto.Decrypter.
	// Supported options will let you bind to a specific key in the KMS,
	// generic client-level configuration is passed in SetConfig.
	Decrypter(ctx context.Context, options ...Option) (crypto.Decrypter, error)
}
