// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package wrapping

import (
	"context"
)

// Wrapper is an interface for encrypting and decrypting data using a set of one
// or more opaque encryption keys.
type Wrapper interface {
	// Type returns the constant named type of the Wrapper, e.g., "pkcs11".
	Type(ctx context.Context) (WrapperType, error)

	// SetConfig applies the given configuration options to the Wrapper
	// and returns resulting configuration metadata.
	//
	// This method takes the following generic options:
	// 	- WithKeyId
	// 	- WithConfigMap
	//
	// Not all wrappers will support all available options. Additionally,
	// provider-specific options defined by specific wrapper packages may be
	// passed. Note that this does not work if the wrapper is consumed via the
	// plugin mechanism.
	//
	// Implementations should expect that SetConfig is called at most once and
	// do not need to handle re-configuration beyond an initial configuration
	// call, though may choose to provide support for this nevertheless.
	// Implementations can also expect that SetConfig is called before any other
	// method besides Type is called.
	SetConfig(ctx context.Context, options ...Option) (*WrapperConfig, error)

	// Encrypt encrypts the given byte slice and stores the result in the
	// returned BlobInfo.
	//
	// This method takes the following generic options:
	// 	- WithAad
	// 	- WithKeyId
	//
	// If no specific key ID is passed, the Wrapper should use the latest
	// available or "default" key to perform the operation.
	//
	// Not all wrappers will support all available options. Additionally,
	// provider-specific options defined by specific wrapper packages may be
	// passed. Note that this does not work if the wrapper is consumed via the
	// plugin mechanism.
	Encrypt(ctx context.Context, plaintext []byte, options ...Option) (*BlobInfo, error)

	// Decrypt decrypts the given BlobInfo and returns the resulting plaintext.
	//
	// This method takes the following generic options:
	// 	- WithAad
	// 	- WithKeyId
	//
	// If no specific key ID is passed, the Wrapper should use the latest
	// available or "default" key to perform the operation.
	//
	// Not all wrappers will support all available options. Additionally,
	// provider-specific options defined by specific wrapper packages may be
	// passed. Note that this does not work if the wrapper is consumed via the
	// plugin mechanism.
	Decrypt(ctx context.Context, ciphertext *BlobInfo, options ...Option) ([]byte, error)

	// KeyId returns an identifier for the encryption key currently in use.
	//
	// This can be used to compare the current key ID against a key ID
	// previously included in the result of a call to Encrypt to detect that a
	// different key is now in use.
	KeyId(ctx context.Context) (string, error)
}

// InitFinalizer is optionally implemented by a Wrapper. It exposes resource
// initialization and finalization hooks that should be called by users of the
// Wrapper if this interface is implemented.
type InitFinalizer interface {
	// Init is called once after a successful call to SetConfig but before any
	// of Encrypt, Decrypt, KeyId or KeyBytes are called.
	//
	// This can be used to perform expensive initialization operations, though
	// most implementations choose to initialize their resources in SetConfig.
	//
	// Init does not take any generic options.
	Init(ctx context.Context, options ...Option) error

	// Finalize is called once after a Wrapper is no longer in use. This should
	// be used to clean up any remaining resources owned by the Wrapper.
	//
	// Finalize does not take any generic options.
	Finalize(ctx context.Context, options ...Option) error
}

// KeyExporter is optionally implemented by a Wrapper. It returns the key
// bytes of the key currently in use. The encoding of the returned key will be
// implementation-specific.
//
// This interface is largely reserved for wrappers that use local crypto, such
// as the AEAD wrapper. When implementing a Wrapper around a particular KMS API,
// you should not (be able to) implement this.
type KeyExporter interface {
	// KeyBytes returns the "current" key bytes.
	KeyBytes(ctx context.Context) ([]byte, error)
}
