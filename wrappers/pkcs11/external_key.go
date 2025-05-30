// Copyright The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
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

	var signer crypto.Signer
	err = k.client.WithSession(ctx, func(session *Session) error {
		priv, pub, keytype, err := session.FindSigningKeyPair(key)
		if err != nil {
			return err
		}

		base := baseSignerDecrypter{ctx: ctx, client: k.client, obj: priv}
		switch keytype {
		case pkcs11.CKK_EC:
			public, err := session.ExportEcdsaPublicKey(pub)
			if err != nil {
				return fmt.Errorf("failed to export ECDSA public key: %w", err)
			}
			signer = &ecdsaSigner{baseSignerDecrypter: base, public: public}
		case pkcs11.CKK_RSA:
			public, err := session.ExportRsaPublicKey(pub)
			if err != nil {
				return fmt.Errorf("failed to export RSA public key: %w", err)
			}
			signer = &rsaSignerDecrypter{baseSignerDecrypter: base, public: public}
		default:
			return fmt.Errorf("unsupported key type: %d", keytype)
		}

		return nil
	})

	return signer, err
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

	var decrypter crypto.Decrypter
	err = k.client.WithSession(ctx, func(session *Session) error {
		priv, pub, keytype, err := session.FindDecryptionKeyPair(key)
		if err != nil {
			return err

		}

		base := baseSignerDecrypter{ctx: ctx, client: k.client, obj: priv}
		switch keytype {
		case pkcs11.CKK_RSA:
			public, err := session.ExportRsaPublicKey(pub)
			if err != nil {
				return fmt.Errorf("failed to export RSA public key: %w", err)
			}
			decrypter = &rsaSignerDecrypter{baseSignerDecrypter: base, public: public}
		default:
			return fmt.Errorf("unsupported key type: %d", keytype)
		}

		return nil
	})

	return decrypter, err
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
}

type ecdsaSigner struct {
	baseSignerDecrypter
	public *ecdsa.PublicKey
}

func (e *ecdsaSigner) Public() crypto.PublicKey {
	return e.public
}

func (e *ecdsaSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) (signature []byte, err error) {
	err = e.client.WithSession(e.ctx, func(session *Session) error {
		signature, err = session.SignEcdsa(e.obj, digest)
		return err
	})
	return signature, err
}

type rsaSignerDecrypter struct {
	baseSignerDecrypter
	public *rsa.PublicKey
}

func (e *rsaSignerDecrypter) Public() crypto.PublicKey {
	return e.public
}

func (r *rsaSignerDecrypter) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, fmt.Errorf("unimplemented")
}

func (r *rsaSignerDecrypter) Decrypt(_ io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	switch o := opts.(type) {
	case *rsa.OAEPOptions:
		hash, err := HashMechanismFromCrypto(o.Hash)
		if err != nil {
			return nil, err
		}
		err = r.client.WithSession(r.ctx, func(s *Session) error {
			var err error
			plaintext, err = s.DecryptRsaOaep(r.obj, msg, hash)
			return err
		})
	default:
		// TODO: Do we want to support PKCS#1 v1.5 here, given the use is general-purpose and not scoped to sealing?
		err = fmt.Errorf("unsupported RSA options")
	}
	return plaintext, err
}
