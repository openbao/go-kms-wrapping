// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"sync"

	"github.com/miekg/pkcs11"
)

const (
	CryptoAesGcmNonceSize = 12
	CryptoAesGcmOverhead  = 16

	DefaultRsaOaepHash = pkcs11.CKM_SHA256
)

// Client is a high-level PKCS#11 client wrapping a specific token slot.
type Client struct {
	ctx    *pkcs11.Ctx
	module *Module
	pool   *Pool
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
	module, err := OpenModule(modulePath)
	if err != nil {
		return nil, err
	}

	slot, err := module.FindSlot(slotNumber, tokenLabel)
	if err != nil {
		module.Close()
		return nil, err
	}

	slotGuardsLock.Lock()
	defer slotGuardsLock.Unlock()

	guard := slotGuard{module: module.path, slot: slot.id}
	if _, ok := slotGuards[guard]; ok {
		module.Close()
		return nil, fmt.Errorf("slot %d of module %q is already in use by another client",
			slot.id, modulePath)
	}
	slotGuards[guard] = true

	pool, err := NewPool(slot, pin, maxSessions)
	if err != nil {
		module.Close()
		return nil, err
	}

	return &Client{ctx: module.ctx, module: module, pool: pool}, nil
}

// Close discards the client's resources.
func (c *Client) Close() error {
	if err := c.pool.Close(); err != nil {
		return err
	}

	// Important: Close the module _after_ closing the pool.
	c.module.Close()

	slotGuardsLock.Lock()
	defer slotGuardsLock.Unlock()

	guard := slotGuard{module: c.module.path, slot: c.pool.slot}
	delete(slotGuards, guard)

	return nil
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

// FindEncryptionKey finds a key capable of encryption (CKA_ENCRYPT).
func (s *Session) FindEncryptionKey(key *Key) (pkcs11.ObjectHandle, int, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
	}
	return s.FindKey(key, template)
}

// FindEncryptionKey finds a key capable of decryption (CKA_DECRYPT).
func (s *Session) FindDecryptionKey(key *Key) (pkcs11.ObjectHandle, int, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	}
	return s.FindKey(key, template)
}

// FindSigningKeyPair finds a public/private key pair where the private key is capable of signing (CKA_SIGN).
func (s *Session) FindSigningKeyPair(key *Key) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, int, error) {
	return s.FindKeyPair(key, pkcs11.CKA_SIGN)
}

// FindDecryptionKeyPair finds a public/private key pair where the private key is capable of decryption (CKA_DECRYPT).
func (s *Session) FindDecryptionKeyPair(key *Key) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, int, error) {
	return s.FindKeyPair(key, pkcs11.CKA_DECRYPT)
}

// FindKeyPair finds a public/private key pair where the private key is capable of <purpose>.
func (s *Session) FindKeyPair(key *Key, purpose uint) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, int, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(purpose, true),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}
	priv, privtype, err := s.FindKey(key, template)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to find private key: %w", err)
	}

	template = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	}
	pub, pubtype, err := s.FindKey(key, template)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to find public key: %w", err)
	}

	// Sanity check!
	if privtype != pubtype {
		return 0, 0, 0, fmt.Errorf("public and private key type do not match: %d vs %d", pubtype, privtype)
	}

	return priv, pub, privtype, nil
}

// FindKey finds a key, based on key ID, key label, key type and other template attributes.
// If the type of the passed key is unset, FindKey attempts to find a unique key regardless of key type
// and returns the resolved type of the key.
func (s *Session) FindKey(key *Key, template []*pkcs11.Attribute) (pkcs11.ObjectHandle, int, error) {
	if key.keytype > -1 {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, key.keytype))
	}

	if id, err := hex.DecodeString(key.id); err == nil && len(id) != 0 {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}
	if key.label != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(key.label)))
	}

	if err := s.ctx.FindObjectsInit(s.handle, template); err != nil {
		return 0, 0, err
	}
	objs, _, err := s.ctx.FindObjects(s.handle, 2)
	if err != nil {
		return 0, 0, err
	}
	if err := s.ctx.FindObjectsFinal(s.handle); err != nil {
		return 0, 0, err
	}

	if len(objs) == 0 {
		return 0, 0, fmt.Errorf("no key found for id %q and label %q", key.id, key.label)
	}
	if len(objs) != 1 {
		return 0, 0, fmt.Errorf("found more than one key for id %q and label %q", key.id, key.label)
	}

	if key.keytype > -1 {
		return objs[0], key.keytype, nil
	}

	// If we weren't looking for a specific key type, try to find out what type we got.
	// Integer casting here gets a bit ugly. We want to return an int because that's what
	// pkcs11.CKK_* values are typed as, we need a uint to compare to CK_UNAVAILABLE_INFORMATION,
	// and we need to account for reading a full uint64 from the GetAttributeValue result.
	template = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
	}
	attrs, err := s.ctx.GetAttributeValue(s.handle, objs[0], template)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to pkcs11 GetAttributeValue: %w", err)
	}
	keytype, err := BytesToUint(attrs[0].Value)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read pkcs11 GetAttributeValue response: %w", err)
	}
	if keytype == uint64(pkcs11.CK_UNAVAILABLE_INFORMATION) {
		return 0, 0, fmt.Errorf("failed to automatically determine key type for id %q and label %q", key.id, key.label)
	}
	if keytype > math.MaxInt {
		return 0, 0, fmt.Errorf("got key type that exceeds max int: %d", keytype)
	}

	return objs[0], int(keytype), nil
}

// EncryptRsaOaep encrypts plaintext with the key referenced by obj using the RSA-OAEP mechanism.
func (s *Session) EncryptRsaOaep(obj pkcs11.ObjectHandle, plaintext []byte, hash int) ([]byte, error) {
	if hash < 0 {
		hash = DefaultRsaOaepHash
	}
	mgf, err := HashMechanismToMgf(hash)
	if err != nil {
		return nil, err
	}

	params := pkcs11.NewOAEPParams(uint(hash), uint(mgf), pkcs11.CKZ_DATA_SPECIFIED, nil)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, params)}

	if err = s.ctx.EncryptInit(s.handle, mech, obj); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 EncryptInit: %w", err)
	}
	var ciphertext []byte
	if ciphertext, err = s.ctx.Encrypt(s.handle, plaintext); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 Encrypt: %w", err)
	}
	return ciphertext, nil
}

// EncryptAesGcm encrypts plaintext with the key referenced by obj using the AES-GCM mechanism.
func (s *Session) EncryptAesGcm(obj pkcs11.ObjectHandle, plaintext []byte) ([]byte, []byte, error) {
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

// DecryptRsaOaep decrypts ciphertext with the key referenced by obj using the RSA-OAEP mechanism.
func (s *Session) DecryptRsaOaep(obj pkcs11.ObjectHandle, ciphertext []byte, hash int) ([]byte, error) {
	if hash < 0 {
		hash = DefaultRsaOaepHash
	}
	mgf, err := HashMechanismToMgf(hash)
	if err != nil {
		return nil, err
	}

	params := pkcs11.NewOAEPParams(uint(hash), uint(mgf), pkcs11.CKZ_DATA_SPECIFIED, nil)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, params)}

	if err = s.ctx.DecryptInit(s.handle, mech, obj); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 DecryptInit: %w", err)
	}
	var plaintext []byte
	if plaintext, err = s.ctx.Decrypt(s.handle, ciphertext); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 Decrypt: %w", err)
	}
	return plaintext, nil
}

// DecryptAesGcm decrypts ciphertext with the key referenced by obj using the AES-GCM mechanism.
func (s *Session) DecryptAesGcm(obj pkcs11.ObjectHandle, ciphertext, nonce []byte) ([]byte, error) {
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

// ExportEcdsaPublicKey exports an ECDSA public key (provided the curve is known by Go's
// standard library) from a public key handle.
func (s *Session) ExportEcdsaPublicKey(obj pkcs11.ObjectHandle) (*ecdsa.PublicKey, error) {
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
	x, y := elliptic.Unmarshal(curve, point)
	if x == nil || y == nil {
		return nil, fmt.Errorf("failed to unmarshal elliptic curve point")
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// ExportRsaPublicKey exports an RSA public key from a public key handle.
func (s *Session) ExportRsaPublicKey(obj pkcs11.ObjectHandle) (*rsa.PublicKey, error) {
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

// SignEcdsa signs a digest with the CKK_EC key referenced by obj via ECDSA.
func (s *Session) SignEcdsa(obj pkcs11.ObjectHandle, digest []byte) ([]byte, error) {
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}

	if err := s.ctx.SignInit(s.handle, mech, obj); err != nil {
		return nil, err
	}
	signature, err := s.ctx.Sign(s.handle, digest)
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

// SignRsa signs a digest with the CKK_RSA key referenced by obj.
func (s *Session) SignRsa(obj pkcs11.ObjectHandle, digest []byte) ([]byte, error) {
	return nil, nil
}
