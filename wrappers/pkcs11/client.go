// Copyright The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math"
	"math/big"
	"sync"

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

// slotGuard is used to ensure that at most one client can operate on a
// certain module's slot. This is important for multi-tenancy as login
// state in PKCS#11 is per-application, not per-session.
// We try our best to resolve and deduplicate the module path, but
// ultimately it is up to the administrator that configures module paths
// to ensure security.
type slotGuard struct {
	// Path of the module file
	module string
	// Slot number to use
	slot uint
}

var (
	// slotGuards tracks all in-use slots.
	slotGuards = make(map[slotGuard]bool)
	// slotGuardsLock guards slotGuards.
	slotGuardsLock = sync.Mutex{}
)

// NewClient creates a new client and initializes the underlying PKCS#11 module.
func NewClient(
	modulePath string, slotNumber *uint, tokenLabel, pin string, maxSessions int,
) (*Client, error) {
	mod, err := openModule(modulePath)
	if err != nil {
		return nil, err
	}

	slot, err := mod.FindSlot(slotNumber, tokenLabel)
	if err != nil {
		mod.Close()
		return nil, err
	}

	slotGuardsLock.Lock()
	defer slotGuardsLock.Unlock()

	guard := slotGuard{module: mod.path, slot: slot.id}
	if _, ok := slotGuards[guard]; ok {
		mod.Close()
		return nil, fmt.Errorf("slot %d of module %q is already in use by another client",
			slot.id, modulePath)
	}
	slotGuards[guard] = true

	pool, err := newSessionPool(slot, pin, maxSessions)
	if err != nil {
		mod.Close()
		return nil, err
	}

	return &Client{ctx: mod.ctx, mod: mod, pool: pool}, nil
}

// Close discards the client's resources.
func (c *Client) Close(ctx context.Context) error {
	err := c.pool.Close(ctx)

	// We always want to free up the slot, regardless of errors.
	slotGuardsLock.Lock()
	guard := slotGuard{module: c.mod.path, slot: c.pool.slot}
	delete(slotGuards, guard)
	slotGuardsLock.Unlock()

	if err != nil {
		return err
	}
	// Closing the module is only safe if the pool exited successfully.
	// Otherwise, we cannot guarantee that potentially freeing the module won't cause
	// nil pointer dereferences.
	c.mod.Close()

	return nil
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
	handle, err := c.pool.Get(ctx)
	if err != nil {
		return nil
	}
	defer c.pool.Put(handle)

	session := &Session{ctx: c.ctx, handle: handle}
	return f(session)
}

// FindKey finds a key based on key ID, label and other template attributes.
func (s *Session) FindKey(id, label []byte, template []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
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
func (s *Session) FindEncryptionKey(id, label []byte, keytype *uint) (pkcs11.ObjectHandle, error) {
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
func (s *Session) FindDecryptionKey(id, label []byte, keytype *uint) (pkcs11.ObjectHandle, error) {
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
func (s *Session) FindKeyPair(id, label []byte) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
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

// EncryptRSAOAEP encrypts plaintext via CKM_RSA_PKCS_OAEP with the
// CKK_RSA public key referenced by obj.
func (s *Session) EncryptRSAOAEP(
	obj pkcs11.ObjectHandle, plaintext []byte, hash uint,
) ([]byte, error) {
	mgf := hashMechanismToMgf(hash)
	params := pkcs11.NewOAEPParams(hash, mgf, pkcs11.CKZ_DATA_SPECIFIED, nil)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, params)}

	if err := s.ctx.EncryptInit(s.handle, mech, obj); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 EncryptInit: %w", err)
	}
	ciphertext, err := s.ctx.Encrypt(s.handle, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs11 Encrypt: %w", err)
	}
	return ciphertext, nil
}

// EncryptAESGCM encrypts plaintext via CKM_AES_GCM with the CKK_AES key referenced by obj.
func (s *Session) EncryptAESGCM(obj pkcs11.ObjectHandle, plaintext []byte) ([]byte, []byte, error) {
	nonce, err := s.ctx.GenerateRandom(s.handle, CryptoAesGcmNonceSize)
	if err != nil {
		return nil, nil, err
	}

	// Some HSM will ignore the given nonce and generate their own.
	// That's why we need to free manually the GCM parameters.
	params := pkcs11.NewGCMParams(nonce, nil, CryptoAesGcmOverhead*8)
	defer params.Free()

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}

	if err = s.ctx.EncryptInit(s.handle, mech, obj); err != nil {
		return nil, nil, fmt.Errorf("failed to pkcs11 EncryptInit: %w", err)
	}
	var ciphertext []byte
	if ciphertext, err = s.ctx.Encrypt(s.handle, plaintext); err != nil {
		return nil, nil, fmt.Errorf("failed to pkcs11 Encrypt: %w", err)
	}

	// Some HSMs (CloudHSM) do not read the nonce/IV and generate their own.
	// Since it's appended, we need to extract it.
	if len(ciphertext) == CryptoAesGcmNonceSize+len(plaintext)+CryptoAesGcmOverhead {
		nonce = ciphertext[len(ciphertext)-CryptoAesGcmNonceSize:]
		ciphertext = ciphertext[:len(ciphertext)-CryptoAesGcmNonceSize]
	}

	return ciphertext, nonce, nil
}

// DecryptRSAOAEP decrypts ciphertext via CKM_RSA_PKCS_OAEP with the CKK_RSA
// private key referenced by obj.
func (s *Session) DecryptRSAOAEP(
	obj pkcs11.ObjectHandle, ciphertext []byte, hash uint,
) ([]byte, error) {
	mgf := hashMechanismToMgf(hash)
	params := pkcs11.NewOAEPParams(hash, mgf, pkcs11.CKZ_DATA_SPECIFIED, nil)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, params)}

	if err := s.ctx.DecryptInit(s.handle, mech, obj); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 DecryptInit: %w", err)
	}
	plaintext, err := s.ctx.Decrypt(s.handle, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs11 Decrypt: %w", err)
	}
	return plaintext, nil
}

// DecryptRSAPKCS1v15 decrypts ciphertext VIA CKM_RSA_PKCS with the
// CKK_RSA private key referenced by obj.
func (s *Session) DecryptRSAPKCS1v15(obj pkcs11.ObjectHandle, ciphertext []byte) ([]byte, error) {
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	if err := s.ctx.DecryptInit(s.handle, mech, obj); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 DecryptInit: %w", err)
	}
	plaintext, err := s.ctx.Decrypt(s.handle, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs11 Decrypt: %w", err)
	}
	return plaintext, nil
}

// DecryptAESGcm decrypts ciphertext via CKM_AES_GCM with the CKK_AES key referenced by obj.
func (s *Session) DecryptAESGCM(obj pkcs11.ObjectHandle, ciphertext, nonce []byte) ([]byte, error) {
	params := pkcs11.NewGCMParams(nonce, nil, CryptoAesGcmOverhead*8)
	defer params.Free()
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}

	var err error
	if err = s.ctx.DecryptInit(s.handle, mech, obj); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 DecryptInit: %s", err)
	}
	var decrypted []byte
	if decrypted, err = s.ctx.Decrypt(s.handle, ciphertext); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 Decrypt: %s", err)
	}
	return decrypted, nil
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

// ExportECDSAPublicKey exports an ECDSA public key (provided the curve is known by Go's
// standard library) from a CKK_EC public key handle.
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
	// Deprecated function, but realistically waiting on https://github.com/golang/go/issues/63963
	// (i.e., likely Go 1.25) to reasonably replace.
	x, y := elliptic.Unmarshal(curve, point)
	if x == nil || y == nil {
		return nil, fmt.Errorf("failed to unmarshal elliptic curve point")
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// ExportRSAPublicKey exports an RSA public key from a CKK_RSA public key handle.
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

// SignECDSA signs a digest via CKM_ECDSA with the CKK_EC key referenced by obj.
func (s *Session) SignECDSA(obj pkcs11.ObjectHandle, digest []byte) ([]byte, error) {
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}

	if err := s.ctx.SignInit(s.handle, mech, obj); err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 SignInit: %w", err)
	}
	signature, err := s.ctx.Sign(s.handle, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 Sign: %w", err)
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

// SignRSAPSS signs a digest via CKM_RSA_PKCS_PSS with the CKK_RSA key referenced by obj.
func (s *Session) SignRSAPSS(obj pkcs11.ObjectHandle, digest []byte, hash, saltLength uint) ([]byte, error) {
	mgf := hashMechanismToMgf(hash)
	params := pkcs11.NewPSSParams(hash, mgf, saltLength)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, params)}

	if err := s.ctx.SignInit(s.handle, mech, obj); err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 SignInit: %w", err)
	}
	signature, err := s.ctx.Sign(s.handle, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 Sign: %w", err)
	}

	return signature, nil
}

// SignRSAPKCS1v15 signs a digest via CKM_RSA_PKCS with the CKK_RSA key referenced by obj.
func (s *Session) SignRSAPKCS1v15(obj pkcs11.ObjectHandle, digest []byte, hashPrefix []byte) ([]byte, error) {
	digest = append(hashPrefix, digest...)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	if err := s.ctx.SignInit(s.handle, mech, obj); err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 SignInit: %w", err)
	}
	signature, err := s.ctx.Sign(s.handle, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 Sign: %w", err)
	}
	return signature, nil
}
