// Copyright The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/miekg/pkcs11"
)

const (
	CryptoAesGcmNonceSize = 12
	CryptoAesGcmOverhead  = 16
)

// client operates on a certain PKCS#11 slot.
type client struct {
	ctx    *pkcs11.Ctx
	pool   *sessionPool
	module *module
}

// session provides access to cryptographic operations.
// Acquire a session via [client.do].
type session struct {
	ctx    *pkcs11.Ctx
	handle pkcs11.SessionHandle
}

// key is found via [session.find] and passed to other methods
// of [session] for cryptographic operations.
type key struct {
	// Session-scoped handle
	handle pkcs11.ObjectHandle
	// Only present for class == CKO_PRIVATE_KEY
	public *key
	// Attributes
	class   uint // CKA_CLASS
	keytype uint // CKA_KEY_TYPE
	encrypt bool // CKA_ENCRYPT
	decrypt bool // CKA_DECRYPT
	sign    bool // CKA_SIGN
}

func newClient(opts *clientOptions) (*client, error) {
	mod, info, err := acquireSlot(opts.lib, opts.slotNumber, opts.tokenLabel)
	if err != nil {
		return nil, err
	}
	pool, err := newSessionPool(mod.ctx, info, opts.pin, opts.maxParallel)
	if err != nil {
		return nil, errors.Join(err, mod.releaseSlot(info.ID))
	}
	return &client{ctx: mod.ctx, module: mod, pool: pool}, nil
}

func (c *client) close() error {
	return errors.Join(c.pool.close(), c.module.releaseSlot(c.pool.slot))
}

func (c *client) do(ctx context.Context, f func(*session) error) error {
	handle, err := c.pool.create(ctx)
	if err != nil {
		return err
	}
	session := &session{ctx: c.ctx, handle: handle}
	return errors.Join(f(session), c.pool.done(handle))
}

func (s *session) find(id, label []byte) (*key, error) {
	var template []*pkcs11.Attribute
	if id != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}
	if label != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))
	}

	// Start out by finding all objects that match our ID + label.
	if err := s.ctx.FindObjectsInit(s.handle, template); err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 FindObjectsInit: %w", err)
	}
	objs, _, err := s.ctx.FindObjects(s.handle, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 FindObjects: %w", err)
	}
	if err := s.ctx.FindObjectsFinal(s.handle); err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 FindObjectsFinal: %w", err)
	}

	switch len(objs) {
	case 1, 2: // Either one secret key or a private key + public key.
	case 0:
		return nil, fmt.Errorf("no key found")
	default:
		return nil, fmt.Errorf("could not find unique secret key or key pair")
	}

	var keys []*key
	for _, obj := range objs {
		key, err := s.resolveKeyAttrs(obj)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}

	// A single secret key:
	if len(keys) == 1 {
		if keys[0].class != pkcs11.CKO_SECRET_KEY {
			return nil, fmt.Errorf("found a single object, expected a secret key (class %d) but got class %d",
				pkcs11.CKO_SECRET_KEY, keys[0].keytype)
		}
		return keys[0], nil
	}

	var privateKey *key
	switch {
	case keys[0].class == pkcs11.CKO_PRIVATE_KEY && keys[1].class == pkcs11.CKO_PUBLIC_KEY:
		privateKey = keys[0]
		privateKey.public = keys[1]
	case keys[0].class == pkcs11.CKO_PUBLIC_KEY && keys[1].class == pkcs11.CKO_PRIVATE_KEY:
		privateKey = keys[1]
		privateKey.public = keys[0]
	default:
		return nil, fmt.Errorf("found two objects, expected public/private key pair (class %d and %d) but got class %d and %d",
			pkcs11.CKO_PUBLIC_KEY, pkcs11.CKO_PRIVATE_KEY, keys[0].keytype, keys[1].keytype)
	}

	if privateKey.keytype != privateKey.public.keytype {
		return nil, fmt.Errorf("private key type does not match public key type (%d vs %d)",
			privateKey.keytype, privateKey.public.keytype)
	}

	return privateKey, nil
}

func (s *session) resolveKeyAttrs(obj pkcs11.ObjectHandle) (*key, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, 0),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
	}

	attrs, err := s.ctx.GetAttributeValue(s.handle, obj, template)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 GetAttributeValue: %w", err)
	}

	class, err := bytesToUint(attrs[0].Value)
	if err != nil {
		return nil, err
	}
	keytype, err := bytesToUint(attrs[1].Value)
	if err != nil {
		return nil, err
	}

	// PKCS#11 is nasty and doesn't let just query for _any_ attribute, instead
	// we must query only for the select attributes that can be supported by the
	// object's class.
	switch class {
	case pkcs11.CKO_SECRET_KEY:
		template = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, 0),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, 0),
		}
	case pkcs11.CKO_PRIVATE_KEY:
		template = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, 0),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, 0),
		}
	case pkcs11.CKO_PUBLIC_KEY:
		template = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, 0),
		}
	default:
		return nil, fmt.Errorf("found unsupported object of class %d", class)
	}

	attrs, err = s.ctx.GetAttributeValue(s.handle, obj, template)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 GetAttributeValue: %w", err)
	}

	var encrypt, decrypt, sign uint
	for _, attr := range attrs {
		val, err := bytesToUint(attr.Value)
		if err != nil {
			return nil, err
		}
		switch attr.Type {
		case pkcs11.CKA_ENCRYPT:
			encrypt = val
		case pkcs11.CKA_DECRYPT:
			decrypt = val
		case pkcs11.CKA_SIGN:
			sign = val
		}
	}

	return &key{
		handle:  obj,
		class:   class,
		keytype: keytype,
		encrypt: encrypt == 1,
		decrypt: decrypt == 1,
		sign:    sign == 1,
	}, nil
}

func (s *session) encrypt(k *key, mech []*pkcs11.Mechanism, plaintext []byte) ([]byte, error) {
	if err := s.ctx.EncryptInit(s.handle, mech, k.handle); err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 EncryptInit: %w", err)
	}
	ciphertext, err := s.ctx.Encrypt(s.handle, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 Encrypt: %w", err)
	}
	return ciphertext, nil
}

func (s *session) encryptRSAOAEP(k *key, plaintext []byte, hash uint) ([]byte, error) {
	mgf := hashMechanismToMgf(hash)
	params := pkcs11.NewOAEPParams(hash, mgf, pkcs11.CKZ_DATA_SPECIFIED, nil)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, params)}
	return s.encrypt(k, mech, plaintext)
}

func (s *session) encryptAESGCM(k *key, plaintext []byte) ([]byte, []byte, error) {
	nonce, err := s.ctx.GenerateRandom(s.handle, CryptoAesGcmNonceSize)
	if err != nil {
		return nil, nil, err
	}
	params := pkcs11.NewGCMParams(nonce, nil, CryptoAesGcmOverhead*8)
	defer params.Free()
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}
	ciphertext, err := s.encrypt(k, mech, plaintext)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, params.IV(), nil
}

func (s *session) decrypt(k *key, mech []*pkcs11.Mechanism, ciphertext []byte) ([]byte, error) {
	if err := s.ctx.DecryptInit(s.handle, mech, k.handle); err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 DecryptInit: %w", err)
	}
	plaintext, err := s.ctx.Decrypt(s.handle, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 Decrypt: %w", err)
	}
	return plaintext, nil
}

func (s *session) decryptRSAOAEP(k *key, ciphertext []byte, hash uint) ([]byte, error) {
	mgf := hashMechanismToMgf(hash)
	params := pkcs11.NewOAEPParams(hash, mgf, pkcs11.CKZ_DATA_SPECIFIED, nil)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, params)}
	return s.decrypt(k, mech, ciphertext)
}

func (s *session) decryptRSAPKCS1v15(k *key, ciphertext []byte) ([]byte, error) {
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	return s.decrypt(k, mech, ciphertext)
}

func (s *session) decryptAESGCM(k *key, ciphertext, nonce []byte) ([]byte, error) {
	params := pkcs11.NewGCMParams(nonce, nil, CryptoAesGcmOverhead*8)
	defer params.Free()
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}
	return s.decrypt(k, mech, ciphertext)
}

func (s *session) sign(k *key, mech []*pkcs11.Mechanism, digest []byte) ([]byte, error) {
	if err := s.ctx.SignInit(s.handle, mech, k.handle); err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 SignInit: %w", err)
	}
	signature, err := s.ctx.Sign(s.handle, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 Sign: %w", err)
	}
	return signature, nil
}

func (s *session) signECDSA(k *key, digest []byte) ([]byte, error) {
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}
	signature, err := s.sign(k, mech, digest)
	if err != nil {
		return nil, err
	}
	if len(signature) == 0 || len(signature)%2 != 0 {
		return nil, fmt.Errorf("ECDSA signature length is invalid: length is %d", len(signature))
	}
	mid := len(signature) / 2
	R := &big.Int{}
	S := &big.Int{}
	return asn1.Marshal(struct {
		R, S *big.Int
	}{
		R: R.SetBytes(signature[:mid]),
		S: S.SetBytes(signature[mid:]),
	})
}

func (s *session) signRSAPSS(k *key, digest []byte, hash, saltLength uint) ([]byte, error) {
	mgf := hashMechanismToMgf(hash)
	params := pkcs11.NewPSSParams(hash, mgf, saltLength)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, params)}
	return s.sign(k, mech, digest)
}

func (s *session) signRSAPKCS1v15(k *key, digest []byte, hashPrefix []byte) ([]byte, error) {
	digest = append(hashPrefix, digest...)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	return s.sign(k, mech, digest)
}

// Inlined from crypto/x509:
var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

// Adapted from crypto/x509:
func namedCurveFromOID(val []byte) (elliptic.Curve, error) {
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(val, &oid)
	if err != nil {
		return nil, nil
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("unexpected data remaining unmarshaling elliptic curve parameter bytes")
	}

	switch {
	case oid.Equal(oidNamedCurveP224):
		return elliptic.P224(), nil
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256(), nil
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384(), nil
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521(), nil
	}
	return nil, nil
}

// Some vendors (e.g. Utimaco, CryptoServer 5) store ASCII strings rather than
// OIDs in EC_PARAMS. Not part of the standard, but not hard to support.
func namedCurveFromLiteral(val []byte) elliptic.Curve {
	switch {
	case slices.Equal(val, []byte("secp224r1")):
		return elliptic.P224()
	case slices.Equal(val, []byte("secp256r1")):
		return elliptic.P256()
	case slices.Equal(val, []byte("secp384r1")):
		return elliptic.P384()
	case slices.Equal(val, []byte("secp521r1")):
		return elliptic.P521()
	}
	return nil
}

func (s *session) exportECDSAPublicKey(k *key) (*ecdsa.PublicKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}
	attrs, err := s.ctx.GetAttributeValue(s.handle, k.handle, template)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 GetAttributeValue: %w", err)
	}

	curve, err := namedCurveFromOID(attrs[0].Value)
	if err != nil {
		return nil, err
	}
	if curve == nil {
		curve = namedCurveFromLiteral(attrs[0].Value)
	}
	if curve == nil {
		return nil, fmt.Errorf("unknown/unsupported elliptic curve")
	}

	var point []byte
	rest, err := asn1.Unmarshal(attrs[1].Value, &point)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal elliptic curve point bytes: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("unexpected data remaining unmarshaling elliptic curve point bytes")
	}

	// Deprecated function, but realistically waiting on Go 1.25 to reasonably
	// replace. For more information, see https://github.com/golang/go/issues/63963.
	// Below should work with Go 1.25:
	// return ecdsa.ParseUncompressedPublicKey(curve, point)
	x, y := elliptic.Unmarshal(curve, point)
	if x == nil || y == nil {
		return nil, fmt.Errorf("failed to unmarshal elliptic curve point")
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func (s *session) exportRSAPublicKey(k *key) (*rsa.PublicKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}
	attrs, err := s.ctx.GetAttributeValue(s.handle, k.handle, template)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 GetAttributeValue: %w", err)
	}

	var n = new(big.Int)
	n.SetBytes(attrs[0].Value)
	var e = new(big.Int)
	e.SetBytes(attrs[1].Value)

	// Sanity checks
	one := big.NewInt(1)
	if n.Cmp(one) != 1 {
		return nil, fmt.Errorf("malformed rsa public key: modulus is less than one")
	}
	if e.Cmp(one) != 1 {
		return nil, fmt.Errorf("malformed rsa public key: exponent is less than one")
	}
	if n.Cmp(e) != 1 {
		return nil, fmt.Errorf("malformed rsa public key: modulus must be greater than exponent")
	}
	if e.BitLen() > 32 {
		return nil, fmt.Errorf("malformed rsa public key: exponent is longer than 32 bits")
	}

	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}
