// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"sync/atomic"

	uuid "github.com/hashicorp/go-uuid"
	pkcs11 "github.com/miekg/pkcs11"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// These constants contain the accepted env vars; the Vault one is for backwards compat
const (
	EnvPkcs11WrapperKeyId   = "PKCS11_WRAPPER_KEY_ID"
	EnvVaultPkcs11SealKeyId = "VAULT_PKCS11_SEAL_KEY_ID"
)

// Wrapper is a Wrapper that uses PKCS11
type Wrapper struct {
	client       *pkcs11KMS
	keyId        string
	currentKeyId *atomic.Value
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new PKCS11 Wrapper
func NewWrapper() *Wrapper {
	k := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	k.currentKeyId.Store("")
	return k
}

// SetConfig sets the fields on the Pkcs11Wrapper object based on
// values from the config parameter.
//
// Order of precedence Pkcs11 values:
// * Environment variable
// * Value from Vault configuration file
// * Instance metadata role (access key and secret key)
func (k *Wrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	// Check and set KeyId
	switch {
	case os.Getenv(EnvPkcs11WrapperKeyId) != "" && !opts.Options.WithDisallowEnvVars:
		k.keyId = os.Getenv(EnvPkcs11WrapperKeyId)
	case os.Getenv(EnvVaultPkcs11SealKeyId) != "" && !opts.Options.WithDisallowEnvVars:
		k.keyId = os.Getenv(EnvVaultPkcs11SealKeyId)
	case opts.WithKeyId != "":
		k.keyId = opts.WithKeyId
	default:
		return nil, fmt.Errorf("key id not found (env or config) for pkcs11 wrapper configuration")
	}

	// Set and check k.client
	if k.client == nil {
		k.client = &pkcs11KMS{}

		if !opts.Options.WithDisallowEnvVars && os.Getenv("PKCS11_SLOT") != "" {
			var err error
			var slot uint64
			slot, err = strconv.ParseUint(os.Getenv("PKCS11_SLOT"), 10, 64)
			if err != nil {
				return nil, err
			}
			opts.withSlot = uint(slot)
		}
		if k.client.slot == 0 {
			k.client.slot = opts.withSlot
		}

		if !opts.Options.WithDisallowEnvVars {
			k.client.pin = os.Getenv("PKCS11_PIN")
		}
		if k.client.pin == "" {
			k.client.pin = opts.withPin
		}

		if !opts.Options.WithDisallowEnvVars {
			k.client.module = os.Getenv("PKCS11_MODULE")
		}
		if k.client.module == "" {
			k.client.module = opts.withModule
		}

		if !opts.Options.WithDisallowEnvVars {
			k.client.label = os.Getenv("PKCS11_LABEL")
		}
		if k.client.label == "" {
			k.client.label = opts.withLabel
		}

		if !opts.Options.WithDisallowEnvVars {
			mechanismName := os.Getenv("PKCS11_MECHANISM")
			if mechanismName != "" {
				k.client.mechanism, err = MechanisFromString(mechanismName)
				if err != nil {
					return nil, err
				}
			}
		}
		if k.client.mechanism == 0 {
			if opts.withMechanism != "" {
				k.client.mechanism, err = MechanisFromString(opts.withMechanism)
				if err != nil {
					return nil, err
				}
			}
		}

		k.client.keyId = k.keyId

		p := pkcs11.New(k.client.module)
		err := p.Initialize()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize PKCS11: %w", err)
		}
		defer p.Destroy()
		defer p.Finalize()

		session, err := p.OpenSession(k.client.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			return nil, fmt.Errorf("failed to open session: %w", err)
		}
		defer p.CloseSession(session)

		err = p.Login(session, pkcs11.CKU_USER, k.client.pin)
		if err != nil {
			return nil, fmt.Errorf("failed to login: %w", err)
		}
		defer p.Logout(session)

	}
	// Store the current key id. If using a key alias, this will point to the actual
	// unique key that that was used for this encrypt operation.
	k.currentKeyId.Store(k.keyId)

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["kms_key_id"] = k.keyId
	wrapConfig.Metadata["slot"] = strconv.Itoa(int(k.client.slot))
	if k.client.label != "" {
		wrapConfig.Metadata["label"] = k.client.label
	}
	if k.client.mechanism != 0 {
		wrapConfig.Metadata["mechanism"] = MechanisString(k.client.mechanism)
	}

	return wrapConfig, nil
}

// Type returns the type for this particular wrapper implementation
func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypePkcs11, nil
}

// KeyId returns the last known key id
func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.currentKeyId.Load().(string), nil
}

// Encrypt is used to encrypt the master key using the the PKCS11.
// This returns the ciphertext, and/or any errors from this
// call. This should be called after the KMS client has been instantiated.
func (k *Wrapper) Encrypt(_ context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	WrappedKey, err := k.client.EncryptDEK(context.Background(), env.Key)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	// Store the current key id.
	k.currentKeyId.Store(k.keyId)

	ret := &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			KeyId:      k.keyId,
			WrappedKey: WrappedKey,
		},
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext. This should be called after Init.
func (k *Wrapper) Decrypt(_ context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, fmt.Errorf("given input for decryption is nil")
	}

	keyBytes, err := k.client.DecryptDEK(context.Background(), in.KeyInfo.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data encryption key: %w", err)
	}

	envInfo := &wrapping.EnvelopeInfo{
		Key:        keyBytes,
		Iv:         in.Iv,
		Ciphertext: in.Ciphertext,
	}
	plaintext, err := wrapping.EnvelopeDecrypt(envInfo, opt...)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return plaintext, nil
}

func GetKeyTypeFromMech(mech uint) (uint, error) {
	switch mech {
	case pkcs11.CKM_RSA_PKCS:
		return pkcs11.CKK_RSA, nil
	case pkcs11.CKM_AES_CBC_PAD:
		return pkcs11.CKK_AES, nil
	default:
		return 0, fmt.Errorf("unsupported mechanism: %d", mech)
	}
}

func MechanisString(mech uint) string {
	switch mech {
	case pkcs11.CKM_RSA_PKCS:
		return "CKM_RSA_PKCS"
	case pkcs11.CKM_AES_CBC_PAD:
		return "CKM_AES_CBC_PAD"
	default:
		return "Unknown"
	}
}

func IsIvNeeded(mech uint) bool {
	switch mech {
	case pkcs11.CKM_AES_CBC_PAD:
		return true
	default:
		return false
	}
}

func MechanisFromString(mech string) (uint, error) {
	switch mech {
	case "CKM_RSA_PKCS":
		return pkcs11.CKM_RSA_PKCS, nil
	case "CKM_AES_CBC_PAD":
		return pkcs11.CKM_AES_CBC_PAD, nil
	default:
		return 0, fmt.Errorf("unsupported mechanism: %s", mech)
	}
}

type pkcs11KMS struct {
	// standard PKCS11 configuration options
	slot      uint
	pin       string
	module    string
	keyId     string
	label     string
	mechanism uint
}

// EncryptDEK uses the PKCS11 encrypt operation to encrypt the DEK.
func (kms *pkcs11KMS) EncryptDEK(ctx context.Context, plainDEK []byte) ([]byte, error) {
	p := pkcs11.New(kms.module)
	err := p.Initialize()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS11: %w", err)
	}

	defer p.Destroy()
	defer p.Finalize()

	session, err := p.OpenSession(kms.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session: %w", err)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, kms.pin)
	if err != nil {
		return nil, fmt.Errorf("failed to login: %w", err)
	}
	defer p.Logout(session)

	keyIdBytes, err := hex.DecodeString(kms.keyId)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key id: %w", err)
	}
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyIdBytes),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
	}
	if kms.label != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, kms.label))
	}
	if kms.mechanism != 0 {
		keyTypeString, err := GetKeyTypeFromMech(kms.mechanism)
		if err != nil {
			return nil, fmt.Errorf("failed to get key type from mechanism: %s", err)
		}
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyTypeString))
	}
	if err := p.FindObjectsInit(session, template); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 FindObjectsInit: %s", err)
	}
	obj, _, err := p.FindObjects(session, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs11 FindObjects: %s", err)
	}
	if err := p.FindObjectsFinal(session); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 FindObjectsFinal: %s", err)
	}

	if len(obj) != 1 {
		return nil, fmt.Errorf("expected 1 object, got %d", len(obj))
	}
	key := obj[0]

	template = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	}
	attr, err := p.GetAttributeValue(session, pkcs11.ObjectHandle(key), template)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs11 GetAttributeValue: %s", err)
	}

	attrMap := GetAttributesMap(attr)
	keyType := GetValueAsInt(attrMap[pkcs11.CKA_KEY_TYPE])

	mechanism := uint(0)
	switch keyType {
	case pkcs11.CKK_AES:
		if kms.mechanism != 0 {
			mechanism = kms.mechanism
		} else {
			mechanism = pkcs11.CKM_AES_CBC_PAD
		}
	case pkcs11.CKK_RSA:
		if kms.mechanism != 0 {
			mechanism = kms.mechanism
		} else {
			mechanism = pkcs11.CKM_RSA_PKCS
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %d", keyType)
	}

	var iv []byte
	if IsIvNeeded(mechanism) {
		template = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil),
		}
		attr, err := p.GetAttributeValue(session, pkcs11.ObjectHandle(key), template)
		if err != nil {
			return nil, fmt.Errorf("failed to pkcs11 GetAttributeValue: %s", err)
		}
		attrMap := GetAttributesMap(attr)

		ivLength := 0
		ivLength = int(GetValueAsInt(attrMap[pkcs11.CKA_VALUE_LEN]))

		iv, err = uuid.GenerateRandomBytes(ivLength)
		if err != nil {
			return nil, err
		}
	}

	if err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, iv)}, key); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 EncryptInit: %s", err)
	}
	var ciphertext []byte
	if ciphertext, err = p.Encrypt(session, plainDEK); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 Encrypt: %s", err)
	}

	if iv != nil {
		return append(iv, ciphertext...), nil
	} else {
		return ciphertext, nil
	}
}

// DecryptDEK uses the PKCS11 decrypt operation to decrypt the DEK.
func (kms *pkcs11KMS) DecryptDEK(ctx context.Context, encryptedDEK []byte) ([]byte, error) {
	p := pkcs11.New(kms.module)
	err := p.Initialize()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS11: %w", err)
	}

	defer p.Destroy()
	defer p.Finalize()

	session, err := p.OpenSession(kms.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session: %w", err)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, kms.pin)
	if err != nil {
		return nil, fmt.Errorf("failed to login: %w", err)
	}
	defer p.Logout(session)

	keyIdBytes, err := hex.DecodeString(kms.keyId)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key id: %w", err)
	}
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyIdBytes),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	}
	if kms.label != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(kms.label)))
	}
	if kms.mechanism != 0 {
		keyTypeString, err := GetKeyTypeFromMech(kms.mechanism)
		if err != nil {
			return nil, fmt.Errorf("failed to get key type from mechanism: %s", err)
		}
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyTypeString))
	}
	if err := p.FindObjectsInit(session, template); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 FindObjectsInit: %s", err)
	}

	obj, _, err := p.FindObjects(session, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs11 FindObjects: %s", err)
	}
	if err := p.FindObjectsFinal(session); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 FindObjectsFinal: %s", err)
	}

	if len(obj) != 1 {
		return nil, fmt.Errorf("expected 1 object, got %d", len(obj))
	}
	key := obj[0]

	template = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	}
	attr, err := p.GetAttributeValue(session, pkcs11.ObjectHandle(key), template)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs11 GetAttributeValue: %s", err)
	}

	attrMap := GetAttributesMap(attr)
	keyType := GetValueAsInt(attrMap[pkcs11.CKA_KEY_TYPE])

	mechanism := uint(0)
	switch keyType {
	case pkcs11.CKK_AES:
		if kms.mechanism != 0 {
			mechanism = kms.mechanism
		} else {
			mechanism = pkcs11.CKM_AES_CBC_PAD
		}
	case pkcs11.CKK_RSA:
		if kms.mechanism != 0 {
			mechanism = kms.mechanism
		} else {
			mechanism = pkcs11.CKM_RSA_PKCS
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %d", keyType)
	}

	var iv []byte
	if IsIvNeeded(mechanism) {
		template = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil),
		}
		attr, err := p.GetAttributeValue(session, pkcs11.ObjectHandle(key), template)
		if err != nil {
			return nil, fmt.Errorf("failed to pkcs11 GetAttributeValue: %s", err)
		}
		attrMap := GetAttributesMap(attr)

		ivLength := 0
		ivLength = int(GetValueAsInt(attrMap[pkcs11.CKA_VALUE_LEN]))

		if len(encryptedDEK) < ivLength {
			return nil, fmt.Errorf("encrypted DEK is too short")
		}

		iv = encryptedDEK[:ivLength]
		encryptedDEK = encryptedDEK[ivLength:]
	}

	if err = p.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, iv)}, key); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 DecryptInit: %s", err)
	}

	var decrypted []byte
	if decrypted, err = p.Decrypt(session, encryptedDEK); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 Decrypt: %s", err)
	}
	return decrypted, nil
}

func GetAttributesMap(attrs []*pkcs11.Attribute) map[uint][]byte {
	m := make(map[uint][]byte, len(attrs))
	for _, a := range attrs {
		m[a.Type] = a.Value
	}
	return m
}

func GetValueAsInt(value []byte) int64 {
	if value == nil {
		return 0
	}
	switch len(value) {
	case 1:
		return int64(value[0])
	case 2:
		return int64(binary.NativeEndian.Uint16(value))
	case 4:
		return int64(binary.NativeEndian.Uint32(value))
	case 8:
		return int64(binary.NativeEndian.Uint64(value))
	}
	return 0
}

func GetValueAsUint(value []byte) uint64 {
	if value == nil {
		return 0
	}
	switch len(value) {
	case 1:
		return uint64(value[0])
	case 2:
		return uint64(binary.NativeEndian.Uint16(value))
	case 4:
		return uint64(binary.NativeEndian.Uint32(value))
	case 8:
		return uint64(binary.NativeEndian.Uint64(value))
	}
	return 0
}
