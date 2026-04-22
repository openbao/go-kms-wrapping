// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/go-viper/mapstructure/v2"
	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/module"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

// New returns a new KMS that uses PKCS#11 libraries.
func New() kms.KMS {
	return &pkcs11KMS{}
}

// pkcs11KMS implements kms.KMS.
type pkcs11KMS struct {
	kms.UnimplementedKMS

	mod   *module.Ref
	token *module.Token
	pool  *session.PoolRef

	// Disable preferring local public key encryption over performing public key
	// encryption via PKCS#11.
	disableSoftwareEncryption bool
}

func (p *pkcs11KMS) Open(ctx context.Context, opts *kms.OpenOptions) error {
	var cfg struct {
		// PKCS#11 library path.
		Lib string `mapstructure:"lib"`

		// Token slot selectors.
		Slot   *uint  `mapstructure:"slot"`
		Serial string `mapstructure:"serial"`
		Token  string `mapstructure:"token"`

		// PIN to authenticate against the chosen token.
		PIN string `mapstructure:"pin"`

		// Other tweaks.
		DisableSoftwareEncryption bool `mapstructure:"disable_software_encryption"`
	}
	if err := mapstructure.WeakDecode(opts.ConfigMap, &cfg); err != nil {
		return err
	}
	if cfg.Lib == "" {
		return errors.New("missing required parameter 'lib'")
	}

	// Build a list of selectors to find the correct token to use:
	var selectors []module.TokenSelector
	if cfg.Slot != nil {
		selectors = append(selectors, module.SelectID(*cfg.Slot))
	}
	if cfg.Serial != "" {
		selectors = append(selectors, module.SelectSerial(cfg.Serial))
	}
	if cfg.Token != "" {
		selectors = append(selectors, module.SelectLabel(cfg.Token))
	}
	if len(selectors) == 0 {
		return errors.New("at least one of 'slot', 'serial', 'token' is required")
	}

	// Open the library:
	mod, err := module.Open(cfg.Lib)
	if err != nil {
		return err
	}
	// Find the token:
	token, err := mod.GetToken(selectors...)
	if err != nil {
		return errors.Join(err, mod.Drop())
	}
	// Log into the token:
	pool, err := session.Login(ctx, mod, token, cfg.PIN)
	if err != nil {
		return errors.Join(err, mod.Drop())
	}

	// Good to go.
	p.mod, p.token, p.pool = mod, token, pool
	p.disableSoftwareEncryption = cfg.DisableSoftwareEncryption

	return nil
}

func (p *pkcs11KMS) Close(ctx context.Context) error {
	if err := p.pool.Drop(ctx); err != nil {
		// Prefer leaking mod if the pool fails to close (via timeout) to avoid
		// any dangling references to library code from pool.
		return err
	}
	return p.mod.Drop()
}

func (p *pkcs11KMS) GetKey(ctx context.Context, opts *kms.KeyOptions) (kms.Key, error) {
	var cfg struct {
		ID          string `mapstructure:"id"`
		Label       string `mapstructure:"label"`
		Mechanism   string `mapstructure:"mechanism"`
		RSAOAEPHash string `mapstructure:"rsa_oaep_hash"`
	}
	if err := mapstructure.WeakDecode(opts.ConfigMap, &cfg); err != nil {
		return nil, err
	}

	// Parse and optionally pin the mechanism:
	mech, err := parseMechanism(cfg.Mechanism)
	if err != nil {
		return nil, fmt.Errorf("parse 'mechanism': %w", err)
	}

	// Parse the OAEP hash:
	oaepHash, err := parseOAEPHash(cfg.RSAOAEPHash)
	if err != nil {
		return nil, fmt.Errorf("parse 'rsa_oaep_hash': %w", err)
	}

	// Build a template to perform the initial key lookup:
	var temp []*pkcs11.Attribute
	if cfg.ID != "" {
		id, err := parseKeyID(cfg.ID)
		if err != nil {
			return nil, fmt.Errorf("parse 'id': %w", err)
		}
		temp = append(temp, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}
	if cfg.Label != "" {
		temp = append(temp, pkcs11.NewAttribute(pkcs11.CKA_LABEL, cfg.Label))
	}
	if len(temp) == 0 {
		return nil, errors.New("one of 'id', 'label' must be set")
	}

	return session.Scope(ctx, p.pool, func(s *session.Handle) (kms.Key, error) {
		objs, err := find(s, temp, 2)
		if err != nil {
			return nil, err
		}

		if len(objs) == 1 {
			switch objs[0].class {
			// A single secret key:
			case pkcs11.CKO_SECRET_KEY:
				return p.newSymmetric(objs[0], mech)

			// A single private key: the matching public key may have a different
			// label so search for the public key.
			case pkcs11.CKO_PRIVATE_KEY:
				attr, err := s.GetAttributeValue(objs[0].handle, []*pkcs11.Attribute{
					pkcs11.NewAttribute(pkcs11.CKA_ID, 0),
				})
				switch {
				case err != nil:
					return nil, err
				case len(attr[0].Value) == 0:
					return nil, errors.New("private key has no CKA_ID, cannot find matching public key")
				}
				pubs, err := find(s, []*pkcs11.Attribute{
					pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
					pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, objs[0].keytype),
					pkcs11.NewAttribute(pkcs11.CKA_ID, attr[0].Value),
				}, 1)
				if err != nil {
					return nil, err
				}
				return p.newAsymmetric(pubs[0], objs[0], mech, oaepHash)

			default:
				return nil, fmt.Errorf("expected CKO_SECRET_KEY or CKO_PRIVATE_KEY but got %s", classToString(objs[0].class))
			}
		}

		var public, private object
		switch {
		case objs[0].class == pkcs11.CKO_PUBLIC_KEY && objs[1].class == pkcs11.CKO_PRIVATE_KEY:
			public, private = objs[0], objs[1]
		case objs[0].class == pkcs11.CKO_PRIVATE_KEY && objs[1].class == pkcs11.CKO_PUBLIC_KEY:
			public, private = objs[1], objs[0]
		default:
			return nil, fmt.Errorf("expected CKO_PRIVATE_KEY and CKO_PUBLIC_KEY pair but got %s and %s",
				classToString(objs[0].class), classToString(objs[1].class))
		}
		if public.keytype != private.keytype {
			return nil, fmt.Errorf("private key of type %s does not match public key of type %s",
				keyTypeToString(private.keytype), keyTypeToString(public.keytype))
		}
		return p.newAsymmetric(public, private, mech, oaepHash)
	})
}

// object is a pkcs11.ObjectHandle with CKA_CLASS and CKA_KEY_TYPE resolved.
type object struct {
	handle  pkcs11.ObjectHandle
	class   uint // CKA_CLASS
	keytype uint // CKA_KEY_TYPE
}

// find resolves up to limit objects for a given object search template.
func find(s *session.Handle, temp []*pkcs11.Attribute, limit int) ([]object, error) {
	init := s.FindObjectsInit(temp)
	handles, err := s.FindObjects(limit)
	errs := errors.Join(init, err, s.FindObjectsFinal())
	switch {
	case errs != nil:
		return nil, errs
	case len(handles) == 0:
		return nil, errors.New("no objects found")
	}

	objs := make([]object, 0, len(handles))
	for _, handle := range handles {
		attrs, err := s.GetAttributeValue(handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, 0),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
		})
		if err != nil {
			return nil, err
		}
		class, err := bytesToUint(attrs[0].Value)
		if err != nil {
			return nil, fmt.Errorf("parse CKA_CLASS: %w", err)
		}
		keytype, err := bytesToUint(attrs[1].Value)
		if err != nil {
			return nil, fmt.Errorf("parse CKA_KEY_TYPE: %w", err)
		}
		objs = append(objs, object{
			handle:  handle,
			class:   class,
			keytype: keytype,
		})
	}
	return objs, nil
}

// newSymmetric constructs a symmetric key implementation from an object.
func (p *pkcs11KMS) newSymmetric(o object, mech *uint) (kms.Key, error) {
	switch o.keytype {
	case pkcs11.CKK_AES:
		return p.newAES(o, mech)
	}
	return nil, fmt.Errorf("unsupported symmetric key type: %s", keyTypeToString(o.keytype))
}

// newAsymmetric constructs an asymmetric key implementation from two objects.
func (p *pkcs11KMS) newAsymmetric(public, private object, mech *uint, oaepHash crypto.Hash) (kms.Key, error) {
	switch public.keytype {
	case pkcs11.CKK_EC:
		return p.newEC(public, private, mech)
	case pkcs11.CKK_RSA:
		return p.newRSA(public, private, mech, oaepHash)
	}
	return nil, fmt.Errorf("unsupported asymmetric key type: %s", keyTypeToString(public.keytype))
}

// bytesToUint converts a byte slice to uint.
func bytesToUint(value []byte) (uint, error) {
	switch len(value) {
	case 1:
		return uint(value[0]), nil
	case 2:
		return uint(binary.NativeEndian.Uint16(value)), nil
	case 4:
		return uint(binary.NativeEndian.Uint32(value)), nil
	case 8:
		u64 := binary.NativeEndian.Uint64(value)
		if u64 > math.MaxUint {
			return 0, errors.New("value exceeds max uint")
		}
		return uint(u64), nil
	default:
		return 0, fmt.Errorf("cannot convert byte slice of length %d to uint", len(value))
	}
}

// parseKeyID parses a key ID string to bytes either by interpreting it as hex
// or by casting the string to bytes directly.
func parseKeyID(s string) (b []byte, err error) {
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		return hex.DecodeString(s[2:])
	} else {
		return []byte(s), nil
	}
}

// parseMechanism parses a mechanism either from a literal or falls back to
// interpreting it as a number mapping to a PKCS#11 constant definition.
func parseMechanism(s string) (*uint, error) {
	if s == "" {
		return nil, nil
	}
	var ret uint
	// Normalize casing, normalize '-' and '_', normalize 'CKM_' prefix.
	switch strings.TrimPrefix(strings.ReplaceAll(strings.ToLower(s), "_", "-"), "ckm-") {
	case "aes-gcm":
		ret = pkcs11.CKM_AES_GCM
	case "ecdsa":
		ret = pkcs11.CKM_ECDSA
	case "rsa-pkcs-pss":
		ret = pkcs11.CKM_RSA_PKCS_PSS
	case "rsa-pkcs-oaep":
		ret = pkcs11.CKM_RSA_PKCS_OAEP
	default:
		mech, err := strconv.ParseUint(s, 0, 32)
		if err != nil {
			return nil, err
		}
		ret = uint(mech)
	}
	return &ret, nil
}

// parseOAEPHash parses the hash to use with RSA-OAEP from a literal.
// An empty input is defaulted to SHA-256.
func parseOAEPHash(s string) (crypto.Hash, error) {
	switch strings.ToLower(s) {
	case "":
		return crypto.SHA256, nil
	case "sha1":
		return crypto.SHA1, nil
	case "sha224":
		return crypto.SHA224, nil
	case "sha256":
		return crypto.SHA256, nil
	case "sha384":
		return crypto.SHA384, nil
	case "sha512":
		return crypto.SHA512, nil
	}
	return crypto.Hash(0), fmt.Errorf("unsupported mechanism: %q", s)
}

// classToString stringifies known CKA_CLASS values for better error messages.
func classToString(class uint) string {
	switch class {
	case pkcs11.CKO_PRIVATE_KEY:
		return "CKO_PRIVATE_KEY"
	case pkcs11.CKO_PUBLIC_KEY:
		return "CKO_PUBLIC_KEY"
	case pkcs11.CKO_SECRET_KEY:
		return "CKO_SECRET_KEY"
	default:
		return fmt.Sprintf("unknown (%x)", class)
	}
}

// keyTypeToString stringifies known CKA_KEY_TYPE values for better error
// messages.
func keyTypeToString(keytype uint) string {
	switch keytype {
	case pkcs11.CKK_RSA:
		return "CKK_RSA"
	case pkcs11.CKK_AES:
		return "CKK_AES"
	case pkcs11.CKK_EC:
		return "CKK_EC"
	default:
		return fmt.Sprintf("unknown (%x)", keytype)
	}
}

// onceOrCancel is similar to sync.Once or sync.OnceValue, but the callback
// takes a context and won't store a value if the context was canceled, allowing
// reattempts.
//
// This doesn't handle panics like the standard library versions do, which is
// likely fine given the local use case.
func onceOrCancel[T any](f func(context.Context) (T, error)) func(context.Context) (T, error) {
	o := struct {
		done atomic.Bool
		mu   sync.Mutex
		ret  T
		err  error
	}{}
	return func(ctx context.Context) (T, error) {
		// Fast path:
		if o.done.Load() {
			return o.ret, o.err
		}
		o.mu.Lock()
		defer o.mu.Unlock()
		// Check again:
		if o.done.Load() {
			return o.ret, o.err
		}
		o.ret, o.err = f(ctx)
		// Don't set done if the context was canceled.
		o.done.Store(!errors.Is(o.err, context.Canceled))
		return o.ret, o.err
	}
}
