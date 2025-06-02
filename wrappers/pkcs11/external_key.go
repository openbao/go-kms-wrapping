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
	key, err := NewKey(opts.keyId, opts.keyLabel, opts.mechanism)
	if err != nil {
		return nil, err
	}

	var signer crypto.Signer
	err = k.client.WithSession(ctx, func(session *Session) error {
		priv, pub, err := session.FindSigningKeyPair(key)
		if err != nil {
			return err
		}

		base := baseSignerDecrypter{ctx: ctx, client: k.client, obj: priv}
		switch key.mechanism {
		case pkcs11.CKM_ECDSA:
			public, err := session.ExportECDSAPublicKey(pub)
			if err != nil {
				return fmt.Errorf("failed to export ECDSA public key: %w", err)
			}
			signer = &ecdsaSigner{baseSignerDecrypter: base, public: public}
		case pkcs11.CKM_RSA_PKCS_PSS, pkcs11.CKM_RSA_PKCS:
			public, err := session.ExportRSAPublicKey(pub)
			if err != nil {
				return fmt.Errorf("failed to export RSA public key: %w", err)
			}
			signer = &rsaSignerDecrypter{
				baseSignerDecrypter: base,
				public:              public,
				mechanism:           key.mechanism,
			}
		default:
			return fmt.Errorf("unsupported mechanism: %s", MechanismToString(key.mechanism))
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
	key, err := NewKey(opts.keyId, opts.keyLabel, opts.mechanism)
	if err != nil {
		return nil, err
	}

	var decrypter crypto.Decrypter
	err = k.client.WithSession(ctx, func(session *Session) error {
		priv, pub, err := session.FindDecryptionKeyPair(key)
		if err != nil {
			return err

		}
		base := baseSignerDecrypter{ctx: ctx, client: k.client, obj: priv}
		switch key.mechanism {
		case pkcs11.CKM_RSA_PKCS_OAEP:
			public, err := session.ExportRSAPublicKey(pub)
			if err != nil {
				return fmt.Errorf("failed to export RSA public key: %w", err)
			}
			decrypter = &rsaSignerDecrypter{
				baseSignerDecrypter: base,
				public:              public,
				mechanism:           key.mechanism,
			}
		default:
			return fmt.Errorf("unsupported mechanism: %s", MechanismToString(key.mechanism))
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
		signature, err = session.SignECDSA(e.obj, digest)
		return err
	})
	return signature, err
}

type rsaSignerDecrypter struct {
	baseSignerDecrypter
	public    *rsa.PublicKey
	mechanism uint
}

func (e *rsaSignerDecrypter) Public() crypto.PublicKey {
	return e.public
}

func (r *rsaSignerDecrypter) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	switch o := opts.(type) {
	case *rsa.PSSOptions:
		if r.mechanism != pkcs11.CKM_RSA_PKCS_PSS {
			return nil, fmt.Errorf("forbidden mechanism, this signer is meant for: %s",
				MechanismToString(r.mechanism))
		}
		var hash uint
		hash, err = HashMechanismFromCrypto(o.Hash)
		if err != nil {
			return nil, err
		}
		saltLength := o.SaltLength
		if o.SaltLength == rsa.PSSSaltLengthAuto || o.SaltLength == rsa.PSSSaltLengthEqualsHash {
			saltLength = o.Hash.Size()
		}
		if saltLength < 0 {
			return nil, fmt.Errorf("invalid salt length: %d", saltLength)
		}
		err = r.client.WithSession(r.ctx, func(s *Session) error {
			signature, err = s.SignRSAPSS(r.obj, digest, hash, uint(saltLength))
			return err
		})
	default:
		if r.mechanism != pkcs11.CKM_RSA_PKCS {
			return nil, fmt.Errorf("forbidden mechanism, this signer is meant for: %s",
				MechanismToString(r.mechanism))
		}
		err = r.client.WithSession(r.ctx, func(s *Session) error {
			signature, err = s.SignRSAPKCS1v15(r.obj, digest)
			return err
		})
	}
	return signature, err
}

func (r *rsaSignerDecrypter) Decrypt(_ io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	switch o := opts.(type) {
	case *rsa.OAEPOptions:
		if r.mechanism != pkcs11.CKM_RSA_PKCS_OAEP {
			return nil, fmt.Errorf("forbidden mechanism, this decrypter is meant for: %s",
				MechanismToString(r.mechanism))
		}
		var hash uint
		hash, err = HashMechanismFromCrypto(o.Hash)
		if err != nil {
			return nil, err
		}
		err = r.client.WithSession(r.ctx, func(s *Session) error {
			plaintext, err = s.DecryptRSAOAEP(r.obj, msg, hash)
			return err
		})
	default:
		// Do we want to support PKCS#1 v1.5 decryption here, given the use is general-purpose and
		// not scoped to sealing? FWIW we also don't support PKCS#1 v1.5 encryption anywhere, so...
		err = fmt.Errorf("unsupported RSA options")
	}
	return plaintext, err
}
