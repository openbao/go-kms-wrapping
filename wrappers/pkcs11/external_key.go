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

type baseExternalKey struct {
	ctx    context.Context
	client *client
	key    *key
}

var _ wrapping.ExternalKey = (*baseExternalKey)(nil)

func (b *baseExternalKey) Signer() (crypto.Signer, bool)       { return nil, false }
func (b *baseExternalKey) Decrypter() (crypto.Decrypter, bool) { return nil, false }

type ecdsaKey struct {
	baseExternalKey
	public *ecdsa.PublicKey
}

type rsaKey struct {
	baseExternalKey
	public *rsa.PublicKey
}

func (e *ecdsaKey) Public() crypto.PublicKey { return e.public }
func (r *rsaKey) Public() crypto.PublicKey   { return r.public }

type ecdsaSigner struct{ ecdsaKey }

var _ crypto.Signer = (*ecdsaSigner)(nil)

func (e *ecdsaSigner) Signer() (crypto.Signer, bool) { return e, true }
func (e *ecdsaSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return signECDSA(&e.ecdsaKey, digest)
}

type rsaSigner struct{ rsaKey }

var _ crypto.Signer = (*rsaSigner)(nil)

func (r *rsaSigner) Signer() (crypto.Signer, bool) { return r, true }
func (r *rsaSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return signRSA(&r.rsaKey, digest, opts)
}

type rsaDecrypter struct{ rsaKey }

var _ crypto.Decrypter = (*rsaDecrypter)(nil)

func (r *rsaDecrypter) Decrypter() (crypto.Decrypter, bool) { return r, true }
func (r *rsaDecrypter) Decrypt(_ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return decryptRSA(&r.rsaKey, ciphertext, opts)
}

type rsaSignerDecrypter struct{ rsaKey }

var _ crypto.Signer = (*rsaSignerDecrypter)(nil)

func (r *rsaSignerDecrypter) Signer() (crypto.Signer, bool) { return r, true }
func (r *rsaSignerDecrypter) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return signRSA(&r.rsaKey, digest, opts)
}

var _ crypto.Decrypter = (*rsaSignerDecrypter)(nil)

func (r *rsaSignerDecrypter) Decrypter() (crypto.Decrypter, bool) { return r, true }
func (r *rsaSignerDecrypter) Decrypt(_ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return decryptRSA(&r.rsaKey, ciphertext, opts)
}

func newExternalKey(ctx context.Context, c *client, s *session, k *key) (wrapping.ExternalKey, error) {
	base := baseExternalKey{ctx: ctx, client: c, key: k}
	switch k.keytype {
	case pkcs11.CKK_EC:
		return newECDSAExternalKey(base, s)
	case pkcs11.CKK_RSA:
		return newRSAExternalKey(base, s)
	default:
		return nil, fmt.Errorf("unsupported key type: %d", k.keytype)
	}
}

func newECDSAExternalKey(base baseExternalKey, s *session) (wrapping.ExternalKey, error) {
	public, err := s.exportECDSAPublicKey(base.key.public)
	if err != nil {
		return nil, fmt.Errorf("failed to export ECDSA public key: %w", err)
	}
	ekey := ecdsaKey{baseExternalKey: base, public: public}
	switch {
	case base.key.sign:
		return &ecdsaSigner{ecdsaKey: ekey}, nil
	default:
		return &ekey, nil
	}
}

func newRSAExternalKey(base baseExternalKey, s *session) (wrapping.ExternalKey, error) {
	public, err := s.exportRSAPublicKey(base.key.public)
	if err != nil {
		return nil, fmt.Errorf("failed to export RSA public key: %w", err)
	}
	rkey := rsaKey{baseExternalKey: base, public: public}
	switch {
	case base.key.sign && base.key.decrypt:
		return &rsaSignerDecrypter{rsaKey: rkey}, nil
	case base.key.sign:
		return &rsaSigner{rsaKey: rkey}, nil
	case base.key.decrypt:
		return &rsaDecrypter{rsaKey: rkey}, nil
	default:
		return &rkey, nil
	}
}

// Adapted from crypto/internal/fips140/rsa.
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

func signECDSA(e *ecdsaKey, digest []byte) (signature []byte, err error) {
	err = e.client.do(e.ctx, func(s *session) error {
		signature, err = s.signECDSA(e.key, digest)
		return err
	})
	return signature, err
}

func signRSA(r *rsaKey, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	switch o := opts.(type) {
	case *rsa.PSSOptions:
		var hash uint
		hash, err = hashMechanismFromCrypto(o.Hash)
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
		err = r.client.do(r.ctx, func(s *session) error {
			signature, err = s.signRSAPSS(r.key, digest, hash, uint(saltLength))
			return err
		})
	default:
		hashPrefix, ok := hashPKCS1v15Prefixes[o.HashFunc()]
		if !ok {
			return nil, fmt.Errorf("unknown hash function")
		}
		err = r.client.do(r.ctx, func(s *session) error {
			signature, err = s.signRSAPKCS1v15(r.key, digest, hashPrefix)
			return err
		})
	}
	return signature, err
}

func decryptRSA(r *rsaKey, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	switch o := opts.(type) {
	case *rsa.OAEPOptions:
		var hash uint
		hash, err = hashMechanismFromCrypto(o.Hash)
		if err != nil {
			return nil, err
		}
		err = r.client.do(r.ctx, func(s *session) error {
			plaintext, err = s.decryptRSAOAEP(r.key, msg, hash)
			return err
		})
	case *rsa.PKCS1v15DecryptOptions:
		if o.SessionKeyLen != 0 {
			// We cannot match the constant-time guarantee required by a non-zero SessionKeyLen.
			return nil, fmt.Errorf("RSA PKCS#1 v1.5 decryption with session key is not supported")
		}
		err = r.client.do(r.ctx, func(s *session) error {
			plaintext, err = s.decryptRSAPKCS1v15(r.key, msg)
			return err
		})
	default:
		err = fmt.Errorf("unsupported RSA options")
	}
	return plaintext, err
}
