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
	"math"
	"math/big"

	"github.com/miekg/pkcs11"
)

const (
	CryptoAesGcmNonceSize = 12
	CryptoAesGcmOverhead  = 16
)

// Client is a high-level PKCS#11 client wrapping a specific token slot.
type Client struct {
	ctx  *pkcs11.Ctx
	mod  *module
	pool *sessionPool
}

// Session is a session that is lent out by the client via WithSession.
type Session struct {
	ctx    *pkcs11.Ctx
	handle pkcs11.SessionHandle
}

// NewClient creates a new client and initializes the underlying PKCS#11 module.
func NewClient(
	modulePath string, slotNumber *uint, tokenLabel, pin string, maxParallel uint,
) (*Client, error) {
	mod, info, err := acquireSlot(modulePath, slotNumber, tokenLabel)
	if err != nil {
		return nil, err
	}

	pool, err := newSessionPool(mod.ctx, info, pin, maxParallel)
	if err != nil {
		return nil, errors.Join(err, mod.releaseSlot(info.ID))
	}

	return &Client{ctx: mod.ctx, mod: mod, pool: pool}, nil
}

// Close discards the client's resources.
func (c *Client) Close() error {
	return errors.Join(c.pool.close(), c.mod.releaseSlot(c.pool.slot))
}

// Module returns the module path the client initialized on.
func (c *Client) Module() string {
	return c.mod.path
}

// Slot returns the token slot number the client initialized on.
func (c *Client) Slot() uint {
	return c.pool.slot
}

// WithSession takes a function f that is passed a session.
func (c *Client) WithSession(ctx context.Context, f func(*Session) error) error {
	handle, err := c.pool.get(ctx)
	if err != nil {
		return err
	}
	session := &Session{ctx: c.ctx, handle: handle}
	return errors.Join(f(session), c.pool.put(handle))
}

// FindKey finds a key based on key ID, label and other template attributes.
func (s *Session) FindKey(
	id, label []byte, template []*pkcs11.Attribute,
) (pkcs11.ObjectHandle, error) {
	if id != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}
	if label != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))
	}

	if err := s.ctx.FindObjectsInit(s.handle, template); err != nil {
		return 0, err
	}
	objs, _, err := s.ctx.FindObjects(s.handle, 2)
	if err != nil {
		return 0, err
	}
	if err := s.ctx.FindObjectsFinal(s.handle); err != nil {
		return 0, err
	}

	if len(objs) == 0 {
		return 0, fmt.Errorf("no key found")
	}
	if len(objs) != 1 {
		return 0, fmt.Errorf("found more than one key")
	}

	return objs[0], nil
}

// FindDecryptionKey finds a key that is capable of encryption.
func (s *Session) FindEncryptionKey(
	id, label []byte, keytype *uint,
) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true)}
	if keytype != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, *keytype))
		if isAsymmetricKeyType(*keytype) {
			// We can narrow our search down to public keys only.
			template = append(template, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY))
		}
	}
	return s.FindKey(id, label, template)
}

// FindDecryptionKey finds a key that is capable of decryption.
func (s *Session) FindDecryptionKey(
	id, label []byte, keytype *uint,
) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true)}
	if keytype != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, *keytype))
		if isAsymmetricKeyType(*keytype) {
			// We can narrow our search down to private keys only.
			template = append(template, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY))
		}
	}
	return s.FindKey(id, label, template)
}

// FindKeyPair finds a public/private key pair.
func (s *Session) FindKeyPair(
	id, label []byte,
) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY)}
	priv, err := s.FindKey(id, label, template)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to find private key: %w", err)
	}
	template = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY)}
	pub, err := s.FindKey(id, label, template)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to find public key: %w", err)
	}
	return priv, pub, nil
}

// GetKeyType gets the key type (CKK_*) of the key referenced by obj.
func (s *Session) GetKeyType(obj pkcs11.ObjectHandle) (uint, error) {
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0)}
	attrs, err := s.ctx.GetAttributeValue(s.handle, obj, template)
	if err != nil {
		return 0, fmt.Errorf("failed to pkcs11 GetAttributeValue: %w", err)
	}
	keytype, err := bytesToUint(attrs[0].Value)
	if err != nil {
		return 0, fmt.Errorf("failed to read pkcs11 GetAttributeValue response: %w", err)
	}
	if keytype == uint64(pkcs11.CK_UNAVAILABLE_INFORMATION) {
		return 0, fmt.Errorf("key type is unavailable information")
	}
	if keytype > math.MaxUint {
		return 0, fmt.Errorf("got key type that exceeds max uint")
	}
	return uint(keytype), nil
}

// encrypt performs the generic EncryptInit -> Encrypt flow.
func (s *Session) encrypt(
	obj pkcs11.ObjectHandle, mech []*pkcs11.Mechanism, plaintext []byte,
) ([]byte, error) {
	if err := s.ctx.EncryptInit(s.handle, mech, obj); err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 EncryptInit: %w", err)
	}
	ciphertext, err := s.ctx.Encrypt(s.handle, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 Encrypt: %w", err)
	}
	return ciphertext, nil
}

// EncryptRSAOAEP encrypts plaintext via CKM_RSA_PKCS_OAEP with the CKK_RSA
// public key referenced by obj.
func (s *Session) EncryptRSAOAEP(
	obj pkcs11.ObjectHandle, plaintext []byte, hash uint,
) ([]byte, error) {
	mgf := hashMechanismToMgf(hash)
	params := pkcs11.NewOAEPParams(hash, mgf, pkcs11.CKZ_DATA_SPECIFIED, nil)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, params)}
	return s.encrypt(obj, mech, plaintext)
}

// EncryptAESGCM encrypts plaintext via CKM_AES_GCM with the CKK_AES key
// referenced by obj.
func (s *Session) EncryptAESGCM(
	obj pkcs11.ObjectHandle, plaintext []byte,
) ([]byte, []byte, error) {
	nonce, err := s.ctx.GenerateRandom(s.handle, CryptoAesGcmNonceSize)
	if err != nil {
		return nil, nil, err
	}

	params := pkcs11.NewGCMParams(nonce, nil, CryptoAesGcmOverhead*8)
	defer params.Free()

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}
	ciphertext, err := s.encrypt(obj, mech, plaintext)
	if err != nil {
		return nil, nil, err
	}

	return ciphertext, params.IV(), nil
}

// decrypt performs the generic DecryptInit -> Decrypt flow.
func (s *Session) decrypt(
	obj pkcs11.ObjectHandle, mech []*pkcs11.Mechanism, ciphertext []byte,
) ([]byte, error) {
	if err := s.ctx.DecryptInit(s.handle, mech, obj); err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 DecryptInit: %w", err)
	}
	plaintext, err := s.ctx.Decrypt(s.handle, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 Decrypt: %w", err)
	}
	return plaintext, nil
}

// DecryptRSAOAEP decrypts ciphertext via CKM_RSA_PKCS_OAEP with the CKK_RSA
// private key referenced by obj.
func (s *Session) DecryptRSAOAEP(
	obj pkcs11.ObjectHandle, ciphertext []byte, hash uint,
) ([]byte, error) {
	mgf := hashMechanismToMgf(hash)
	params := pkcs11.NewOAEPParams(hash, mgf, pkcs11.CKZ_DATA_SPECIFIED, nil)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, params)}
	return s.decrypt(obj, mech, ciphertext)
}

// DecryptRSAPKCS1v15 decrypts ciphertext VIA CKM_RSA_PKCS with the CKK_RSA
// private key referenced by obj.
func (s *Session) DecryptRSAPKCS1v15(
	obj pkcs11.ObjectHandle, ciphertext []byte,
) ([]byte, error) {
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	return s.decrypt(obj, mech, ciphertext)
}

// DecryptAESGcm decrypts ciphertext via CKM_AES_GCM with the CKK_AES key
// referenced by obj.
func (s *Session) DecryptAESGCM(
	obj pkcs11.ObjectHandle, ciphertext, nonce []byte,
) ([]byte, error) {
	params := pkcs11.NewGCMParams(nonce, nil, CryptoAesGcmOverhead*8)
	defer params.Free()
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}
	return s.decrypt(obj, mech, ciphertext)
}

// sign performs the generic SignInit -> Sign flow.
func (s *Session) sign(
	obj pkcs11.ObjectHandle, mech []*pkcs11.Mechanism, digest []byte,
) ([]byte, error) {
	if err := s.ctx.SignInit(s.handle, mech, obj); err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 SignInit: %w", err)
	}
	signature, err := s.ctx.Sign(s.handle, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 Sign: %w", err)
	}
	return signature, nil
}

// SignECDSA signs a digest via CKM_ECDSA with the CKK_EC key referenced by obj.
func (s *Session) SignECDSA(obj pkcs11.ObjectHandle, digest []byte) ([]byte, error) {
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}
	signature, err := s.sign(obj, mech, digest)
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

// SignRSAPSS signs a digest via CKM_RSA_PKCS_PSS with the CKK_RSA key
// referenced by obj.
func (s *Session) SignRSAPSS(
	obj pkcs11.ObjectHandle, digest []byte, hash, saltLength uint,
) ([]byte, error) {
	mgf := hashMechanismToMgf(hash)
	params := pkcs11.NewPSSParams(hash, mgf, saltLength)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, params)}
	return s.sign(obj, mech, digest)
}

// SignRSAPKCS1v15 signs a digest via CKM_RSA_PKCS with the CKK_RSA key
// referenced by obj.
func (s *Session) SignRSAPKCS1v15(
	obj pkcs11.ObjectHandle, digest []byte, hashPrefix []byte,
) ([]byte, error) {
	digest = append(hashPrefix, digest...)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	return s.sign(obj, mech, digest)
}

// Inlined from crypto/x509:
var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

// Inlined from crypto/x509:
func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521()
	}
	return nil
}

// ExportECDSAPublicKey exports an ECDSA public key (provided the curve is known
// by Go's standard library) from a CKK_EC public key handle.
func (s *Session) ExportECDSAPublicKey(obj pkcs11.ObjectHandle) (*ecdsa.PublicKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}
	attrs, err := s.ctx.GetAttributeValue(s.handle, obj, template)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs11 GetAttributeValue: %w", err)
	}

	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(attrs[0].Value, &oid)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("unexpected data remaining unmarshaling elliptic curve parameter bytes")
	}

	var point []byte
	rest, err = asn1.Unmarshal(attrs[1].Value, &point)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("unexpected data remaining unmarshaling elliptic curve point bytes")
	}

	curve := namedCurveFromOID(oid)
	if curve == nil {
		return nil, fmt.Errorf("unknown/unsupported elliptic curve")
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

// ExportRSAPublicKey exports an RSA public key from a CKK_RSA public key
// handle.
func (s *Session) ExportRSAPublicKey(obj pkcs11.ObjectHandle) (*rsa.PublicKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}
	attrs, err := s.ctx.GetAttributeValue(s.handle, obj, template)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs11 GetAttributeValue: %w", err)
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
