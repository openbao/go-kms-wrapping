// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"crypto"
	"fmt"
	"io"

	"github.com/miekg/pkcs11"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// ExternalKey is a wrapping.ExternalKey that uses PKCS#11.
type ExternalKey struct {
	client *Client
}

var (
	// Ensure that we implement both ExternalKey and InitFinalizer correctly
	_ wrapping.ExternalKey   = (*ExternalKey)(nil)
	_ wrapping.InitFinalizer = (*ExternalKey)(nil)
)

// NewExternalKey returns a new uninitialized and unconfigured ExternalKey.
func NewExternalKey() *ExternalKey {
	return &ExternalKey{}
}

// Init initializes the ExternalKey. It is currently a no-op.
func (k *ExternalKey) Init(_ context.Context, _ ...wrapping.Option) error {
	return nil
}

// Finalize finalizes the ExternalKey and closes its client.
func (k *ExternalKey) Finalize(_ context.Context, _ ...wrapping.Option) error {
	return k.client.Close()
}

// SetConfig configures the client used by the ExternalKey.
func (k *ExternalKey) SetConfig(_ context.Context, options ...wrapping.Option) error {
	opts, err := getExternalKeyOpts(options)
	if err != nil {
		return err
	}
	client, err := NewClient(opts.lib, opts.slotNumber, opts.tokenLabel, opts.pin, opts.maxSessions)
	if err != nil {
		return err
	}
	k.client = client
	return nil
}

func (k *ExternalKey) Signer(ctx context.Context, options ...wrapping.Option) (crypto.Signer, error) {
	opts, err := getSignerDecrypterOpts(options)
	if err != nil {
		return nil, err
	}
	key, err := NewKey(opts.keyId, opts.keyLabel, opts.keyType, opts.mechanism, opts.hash)
	if err != nil {
		return nil, err
	}

	var obj pkcs11.ObjectHandle
	var keytype int

	if err := k.client.WithSession(ctx, func(session *Session) error {
		var err error
		obj, keytype, err = session.FindSigningKey(key)
		return err
	}); err != nil {
		return nil, err
	}

	base := baseSignerDecrypter{ctx: ctx, client: k.client, obj: obj}
	switch keytype {
	case pkcs11.CKK_RSA:
		return &rsaSignerDecrypter{baseSignerDecrypter: base}, nil
	case pkcs11.CKK_EC:
		return &ecdsaSigner{baseSignerDecrypter: base}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %d", keytype)
	}
}

func (k *ExternalKey) Decrypter(ctx context.Context, options ...wrapping.Option) (crypto.Decrypter, error) {
	opts, err := getSignerDecrypterOpts(options)
	if err != nil {
		return nil, err
	}
	key, err := NewKey(opts.keyId, opts.keyLabel, opts.keyType, opts.mechanism, opts.hash)
	if err != nil {
		return nil, err
	}

	var obj pkcs11.ObjectHandle
	var keytype int

	if err := k.client.WithSession(ctx, func(session *Session) error {
		var err error
		obj, keytype, err = session.FindDecryptionKey(key)
		return err
	}); err != nil {
		return nil, err
	}

	base := baseSignerDecrypter{ctx: ctx, client: k.client, obj: obj}
	switch keytype {
	case pkcs11.CKK_RSA:
		return &rsaSignerDecrypter{baseSignerDecrypter: base}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %d", keytype)
	}
}

var (
	// Ensure that all signers implement crypto.Signer
	_ crypto.Signer = (*ecdsaSigner)(nil)
	_ crypto.Signer = (*rsaSignerDecrypter)(nil)
	// Ensure that rsaSignerDecrypter is additionally a crypto.Decrypter
	_ crypto.Decrypter = (*rsaSignerDecrypter)(nil)
)

// baseSignerDecrypter is common to all crypto.Signer and crypto.Decrypter implementations.
type baseSignerDecrypter struct {
	// Context for session cancellation
	ctx context.Context
	// Client to perform operations
	client *Client
	// Internal handle to the backing private key
	obj pkcs11.ObjectHandle
	// Resolved public key
	public crypto.PublicKey
}

func (b *baseSignerDecrypter) Public() crypto.PublicKey {
	return b.public
}

type ecdsaSigner struct {
	baseSignerDecrypter
}

type rsaSignerDecrypter struct {
	baseSignerDecrypter
}

func (e *ecdsaSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) (signature []byte, err error) {
	err = e.client.WithSession(e.ctx, func(session *Session) error {
		signature, err = session.SignEcdsa(e.obj, digest)
		return err
	})
	return signature, err
}

func (r *rsaSignerDecrypter) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, fmt.Errorf("unimplemented")
}

func (r *rsaSignerDecrypter) Decrypt(_ io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return nil, fmt.Errorf("unimplemented")
}
