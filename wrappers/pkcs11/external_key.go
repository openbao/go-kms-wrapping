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

// Signer gets a crypto.Signer backed by a private key via PKCS#11.
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

// Decrypter gets a crypto.Decrypter backed by a private key via PKCS#11.
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

// ecdsaSigner implements crypto.Signer for ECDSA keys.
type ecdsaSigner struct {
	baseSignerDecrypter
	public *ecdsa.PublicKey
}

// Public is the crypto.Signer Public() implementation for ecdsaSigner.
func (e *ecdsaSigner) Public() crypto.PublicKey {
	return e.public
}

// Sign is the crypto.Signer Sign(...) implementation for ecdsaSigner.
func (e *ecdsaSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) (signature []byte, err error) {
	err = e.client.WithSession(e.ctx, func(session *Session) error {
		signature, err = session.SignECDSA(e.obj, digest)
		return err
	})
	return signature, err
}

// ecdsaSigner implements crypto.Signer/Decrypter for RSA keys.
type rsaSignerDecrypter struct {
	baseSignerDecrypter
	public    *rsa.PublicKey
	mechanism uint
}

// Public is the crypto.Signer/Decrypter Public() implementation for rsaSignerDecrypter.
func (e *rsaSignerDecrypter) Public() crypto.PublicKey {
	return e.public
}

// Adapted from crypto/internal/fips140/rsa:
// TODO: Do we really need all of these?
var hashPKCS1v15Prefixes = map[crypto.Hash][]byte{
	crypto.MD5:        {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:       {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:     {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:     {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:     {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:     {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.SHA512_224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05, 0x00, 0x04, 0x1C},
	crypto.SHA512_256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA3_224:   {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x05, 0x00, 0x04, 0x1C},
	crypto.SHA3_256:   {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA3_384:   {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA3_512:   {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:    {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160:  {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

// Sign is the crypto.Signer Sign(...) implementation for rsaSignerDecrypter.
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
		// PSSSaltLengthAuto: "When signing in FIPS 140-3 mode, the salt length
		// is capped at the length of the hash function used in the signature."
		// Let's just do the same as FIPS 140-3 here then.
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
		hashPrefix, ok := hashPKCS1v15Prefixes[o.HashFunc()]
		if !ok {
			return nil, fmt.Errorf("unknown hash function")
		}
		err = r.client.WithSession(r.ctx, func(s *Session) error {
			signature, err = s.SignRSAPKCS1v15(r.obj, digest, hashPrefix)
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
	case *rsa.PKCS1v15DecryptOptions:
		if o.SessionKeyLen != 0 {
			// We cannot match the constant-time guarantee required by a non-zero SessionKeyLen.
			return nil, fmt.Errorf("RSA PKCS#1 v1.5 decryption with session key is not supported")
		}
		err = r.client.WithSession(r.ctx, func(s *Session) error {
			plaintext, err = s.DecryptRSAPKCS1v15(r.obj, msg)
			return err
		})
	default:
		err = fmt.Errorf("unsupported RSA options")
	}
	return plaintext, err
}
