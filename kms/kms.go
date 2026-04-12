// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// package kms provides minimal, shared KMS interfaces for providers to
// implement to integrate with OpenBao. The interfaces defined here power the
// External Keys feature in OpenBao and can be used as a foundation to build
// Auto Unseal mechanisms via go-kms-wrapping's Wrapper type.
package kms

import (
	"context"
	"crypto"
	"errors"
	"io"

	"github.com/hashicorp/go-hclog"
)

var (
	// ErrNotImplemented is returned when a provider has not implemented or
	// generally does not support the called API.
	ErrNotImplemented = errors.New("not implemented")

	// ErrInvalidSignature is returned by Verify when signature verification
	// fails. If the underlying KMS provides an additional error message, it
	// should be wrapped in this error. This allows callers to differentiate
	// between a cryptographic error and other failures.
	ErrInvalidSignature = errors.New("invalid signature")
)

// KMS provides access to KMS-backed keys.
//
// KMS implementations are not expected to implement all methods, though Open
// and GetKey are required for a minimally viable implementation. Also see
// [UnimplementedKMS] which provides default implementations to cover for
// omitted APIs.
type KMS interface {
	// Open configures this KMS and acquires any necessary resources to perform
	// key operations. Open is to be called exactly once, before other APIs are
	// called.
	//
	// Open effectively behaves like a constructor, but is pushed into the
	// interface itself to ease integration with go-plugin.
	//
	// Also see [OpenOptions].
	Open(context.Context, *OpenOptions) error

	// GetKey returns an opaque Key using the passed options.
	//
	// Implementations should avoid fetching key information at this stage if
	// possible and assume the key without dispatching a call to the KMS. This
	// allows for one-shot key operations specifically with REST-like KMS APIs.
	// Other protocols such as PKCS#11 will require fetching a minimal amount
	// of key information at this stage as subsequent key operations are not
	// possible without first retrieving a live handle to it.
	//
	// Also see [KeyOptions].
	GetKey(context.Context, *KeyOptions) (Key, error)

	// Close terminates this KMS, rendering further use of it a semantic error.
	//
	// Implementations should use this hook to clean up any resources acquired
	// by Open. Close should return a nil error if not implemented to signify
	// a no-op. Close does not need to and should not be called if the call to
	// Open failed.
	Close(context.Context) error
}

// Key provides cryptographic functionality over an opaque, KMS-backed key.
//
// Key implementations are not expected to implement all methods. Also see
// [UnimplementedKey] which provides default implementations to cover for
// omitted APIs.
type Key interface {
	// Encrypt encrypts data according to the passed options and returns
	// ciphertext.
	//
	// Also see [CipherOptions].
	Encrypt(context.Context, *CipherOptions) ([]byte, error)

	// Decrypt decrypts data according to the passed options and returns
	// plaintext.
	//
	// Also see [CipherOptions].
	Decrypt(context.Context, *CipherOptions) ([]byte, error)

	// Sign creates a digital signature.
	//
	// The returned signature is expected to follow the encoding used by the
	// standard library if defined:
	//  - ASN.1 encoding for RSA and ECDSA signatures.
	//  - Raw encoding for EdDSA signatures.
	//
	// Also see [SignOptions].
	Sign(context.Context, *SignOptions) ([]byte, error)

	// Verify verifies a digital signature created by Sign.
	//
	// Also see [VerifyOptions].
	Verify(context.Context, *VerifyOptions) error

	// ExportPublic exports a key's associated public key if applicable, and
	// errors otherwise. The returned public key should follow the standard
	// library encoding for public keys if defined, that is:
	//  - *rsa.PublicKey for RSA keys
	//  - *ecdsa.PublicKey for EC keys
	//  - ed25519.PublicKey for Ed25519 keys
	ExportPublic(context.Context) (crypto.PublicKey, error)

	// Close terminates this key, rendering further use of it a semantic error.
	//
	// KMS providers likely will not need to directly implement this. Rather,
	// this is useful for plugin clients to free key references on a remote
	// plugin server.
	//
	// Close should return a nil error if not implemented to signify a no-op.
	Close(context.Context) error
}

// ConfigMap represents user-defined data that is used to configure APIs in this
// package via provider-specific parameters.
//
// A ConfigMap MUST use JSON-serializable types only. Providers are expected
// to decode ConfigMaps using mapstructure.WeakDecode. For a reference
// implementation, see the github.com/openbao/go-kms-wrapping/v2/kms/transit
// package.
type ConfigMap map[string]any

// OpenOptions is passed to [KMS.Open].
type OpenOptions struct {
	// Logger is a logger made available to the KMS.
	//
	// This field will be ignored if passed over a go-plugin boundary, and the
	// plugin server will provide its own logger instead.
	Logger hclog.Logger

	// AllowEnvironment allows the KMS to configure itself based on environment
	// variables or well-known configuration files as available if set to true.
	// Implementing such auto-configuration behavior is entirely optional.
	// HOWEVER, note that this field is false by default to ensure safe,
	// encapsulated usage of the KMS, and implementations MUST ensure that no
	// environment variables or configuration files are read by default.
	AllowEnvironment bool

	// ConfigMap is the ConfigMap that will configure the KMS. This is
	// provider-level configuration that should include information such as:
	//  - Endpoints
	//  - Provider-specific buckets, e.g. a key namespace.
	//  - Provider-level authentication (not key-level authentication).
	//  - Other top-level configuration knobs.
	ConfigMap ConfigMap
}

// KeyOptions is passed to [KMS.GetKey].
type KeyOptions struct {
	// ConfigMap is the ConfigMap that will configure the Key. Configuration is
	// provider-specific, but common categories of information passed here are:
	//  - A Key name or ID to uniquely identify a key to use.
	//  - Per-key authentication parameters.
	//  - An algorithm that this key must be enforced to use.
	//  - The key type to avoid +1 key type lookup calls if required to set up
	//    calls for key operations.
	ConfigMap ConfigMap
}

// CipherOptions is passed to [Key.Encrypt] and [Key.Decrypt].
type CipherOptions struct {
	// Data is the raw plaintext or ciphertext to operate on, depending on the
	// operation. This may hold a provider-specific encoding if most practical.
	Data []byte

	// AAD is Additional Authenticated Data to pass to an encrypt or decrypt
	// operation. Not all providers or cipher modes will honor this field, but
	// should respect it if applicable to the underlying cipher mode used.
	AAD []byte

	// Nonce holds the (optional) nonce value either produced by a Encrypt
	// operation or taken by a Decrypt operation. That is, Nonce is never
	// manually passed to Encrypt, but Encrypt generates a secure nonce itself
	// using the KMS and writes it back to this field.
	//
	// If the nonce cannot trivially be split from the ciphertext, e.g., because
	// it would require additional API calls to determine the used cipher mode
	// parameters or key type, it is allowed not to split it and bundle it with
	// the ciphertext in provider-specific encoding.
	Nonce []byte

	// KeyVersion is a provider-specific reference to the key version used to
	// create a ciphertext. This may optionally be required by certain providers
	// (e.g., OpenBao Transit) to target the correct key for decryption. This
	// value is produced and written back by Encrypt calls and read by Decrypt
	// calls, much like the Nonce field. Human-readable encodings are preferred.
	KeyVersion string
}

// SignOptions is passed to [Key.Sign].
type SignOptions struct {
	// Data is the data to be signed. This is either a pre-hashed digest or a
	// raw message, indicated by the value of Prehashed.
	Data []byte

	// Prehashed indicates whether Data is a pre-hashed digest or a raw message.
	// If pre-hashing is not applicable to an algorithm, e.g., with pure
	// Ed25519, this field MUST be ignored and may take any value.
	//
	// If applicable, providers may choose to implement a configuration
	// parameter in KeyOptions to enforce that a given Key is
	// never used with pre-hashed data such that the payload to
	// be signed can be inspected in plaintext on the KMS. See the
	// github.com/openbao/go-kms-wrapping/v2/kms/transit package as a reference
	// implementation on how to do so.
	Prehashed bool

	// SignOptions are signing parameters specific to signature schemes
	// that indicate (at minimum) a hash function or the absence of one via
	// crypto.Hash(0).
	crypto.SignerOpts

	// KeyVersion is a provider-specific reference to the key version used
	// to create a signature. This may optionally be required by certain
	// providers (e.g., OpenBao Transit) to target the correct key for signature
	// verification. This value is written back to this field by Sign calls.
	// Human-readable encodings are preferred.
	KeyVersion string
}

// VerifyOptions is passed to [Key.Verify].
type VerifyOptions struct {
	// Signature is the signature to be verified, created by a Sign operation.
	Signature []byte

	// Data is the data accompanying the signature to be verified. This is
	// either a pre-hashed digest or a raw message, indicated by the value of
	// Digest.
	Data []byte

	// Prehashed indicates whether Data is a pre-hashed digest or a raw message.
	// If pre-hashing is not applicable to an algorithm, e.g., with pure
	// Ed25519, this field MUST be ignored and may take any value.
	Prehashed bool

	// SignOptions are signing parameters specific to signature schemes
	// that indicate (at minimum) a hash function or the absence of one via
	// crypto.Hash(0).
	crypto.SignerOpts

	// KeyVersion is a provider-specific reference to the key version used
	// to create a signature. This may optionally be required by certain
	// providers (e.g., OpenBao Transit) to target the correct key for signature
	// verification. If required by the provider, this field should be populated
	// when calling Verify and be set to the KeyVersion produced by a Sign call.
	// Human-readable encodings are preferred.
	KeyVersion string
}

// UnimplementedKMS should be embedded in all implementations of [KMS] to ensure
// automatic forward-compatibility when new methods are added to the interface.
// It provides default implementations for all [KMS] methods, returning
// [ErrNotImplemented] or nil values as appropriate.
type UnimplementedKMS struct{}

var _ KMS = UnimplementedKMS{}

func (UnimplementedKMS) Open(context.Context, *OpenOptions) error {
	return ErrNotImplemented
}
func (UnimplementedKMS) GetKey(context.Context, *KeyOptions) (Key, error) {
	return nil, ErrNotImplemented
}
func (UnimplementedKMS) Close(context.Context) error {
	return nil
}

// UnimplementedKey should be embedded in all implementations of [Key] to
// ensure automatic forward-compatibility when new methods are added to the
// interface. It provides default implementations for all Key methods, returning
// [ErrNotImplemented] or nil values as appropriate.
type UnimplementedKey struct{}

var _ Key = UnimplementedKey{}

func (UnimplementedKey) Encrypt(context.Context, *CipherOptions) ([]byte, error) {
	return nil, ErrNotImplemented
}
func (UnimplementedKey) Decrypt(context.Context, *CipherOptions) ([]byte, error) {
	return nil, ErrNotImplemented
}
func (UnimplementedKey) Sign(context.Context, *SignOptions) ([]byte, error) {
	return nil, ErrNotImplemented
}
func (UnimplementedKey) Verify(context.Context, *VerifyOptions) error {
	return ErrNotImplemented
}
func (UnimplementedKey) ExportPublic(context.Context) (crypto.PublicKey, error) {
	return nil, ErrNotImplemented
}
func (UnimplementedKey) Close(context.Context) error {
	return nil
}

// NewSigner returns a [crypto.Signer]/[crypto.MessageSigner] built on a [Key]
// for compatibility with crypto/x509 and the likes.
func NewSigner(ctx context.Context, key Key) (crypto.Signer, error) {
	pub, err := key.ExportPublic(ctx)
	if err != nil {
		return nil, err
	}
	return &signer{key: key, pub: pub, ctx: ctx}, nil
}

type signer struct {
	key Key
	pub crypto.PublicKey
	ctx context.Context
}

// Public implements crypto.Signer.
func (s *signer) Public() crypto.PublicKey {
	return s.pub
}

// Sign implements crypto.Signer.
func (s *signer) Sign(_ io.Reader, data []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(s.ctx, &SignOptions{
		Data:       data,
		Prehashed:  true,
		SignerOpts: opts,
	})
}

// SignMessage implements crypto.MessageSigner.
func (s *signer) SignMessage(_ io.Reader, data []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(s.ctx, &SignOptions{
		Data:       data,
		SignerOpts: opts,
	})
}
