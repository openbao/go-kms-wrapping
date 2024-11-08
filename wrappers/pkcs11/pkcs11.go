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

// Init is called during core.Initialize
func (s *Wrapper) Init(_ context.Context) error {
	return nil
}

// Finalize is called during shutdown
func (s *Wrapper) Finalize(_ context.Context) error {
	s.client.DestroyClient()
	return nil
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
			k.client.slot = uint(slot)
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
				k.client.mechanism, err = MechanismFromString(mechanismName)
				if err != nil {
					return nil, err
				}
			}
		}
		if k.client.mechanism == 0 {
			if opts.withMechanism != "" {
				k.client.mechanism, err = MechanismFromString(opts.withMechanism)
				if err != nil {
					return nil, err
				}
			}
		}

		k.client.keyId = k.keyId

		// Initialize the client
		_, err = k.client.GetClient()
		if err != nil {
			return nil, err
		}
		// Validate credentials for session establishment
		session, err := k.client.GetSession()
		if err != nil {
			return nil, err
		}
		defer k.client.CloseSession(session)
	}
	// Store the current key id. If using a key alias, this will point to the actual
	// unique key that that was used for this encrypt operation.
	k.currentKeyId.Store(k.keyId)

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["key_id"] = k.keyId
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

// Encrypt is used to encrypt data using the the PKCS11 key.
// This returns the ciphertext, and/or any errors from this
// call. This should be called after the KMS client has been instantiated.
func (k *Wrapper) Encrypt(_ context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("given plaintext for encryption is empty")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	WrappedKey, err := k.client.Encrypt(context.Background(), env.Key)
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

	keyBytes, err := k.client.Decrypt(context.Background(), in.KeyInfo.WrappedKey)
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
	case pkcs11.CKM_RSA_PKCS_OAEP:
		return pkcs11.CKK_RSA, nil
	case pkcs11.CKM_RSA_PKCS:
		return pkcs11.CKK_RSA, nil
	case pkcs11.CKM_AES_GCM:
		return pkcs11.CKK_AES, nil
	case pkcs11.CKM_AES_CBC_PAD:
		return pkcs11.CKK_AES, nil
	default:
		return 0, fmt.Errorf("unsupported mechanism: %d", mech)
	}
}

func MechanisString(mech uint) string {
	switch mech {
	case pkcs11.CKM_RSA_PKCS_OAEP:
		return "CKM_RSA_PKCS_OAEP"
	case pkcs11.CKM_RSA_PKCS:
		return "CKM_RSA_PKCS"
	case pkcs11.CKM_AES_GCM:
		return "CKM_AES_GCM"
	case pkcs11.CKM_AES_CBC_PAD:
		return "CKM_AES_CBC_PAD"
	default:
		return "Unknown"
	}
}

func IsIvNeeded(mech uint) (bool, int) {
	switch mech {
	case pkcs11.CKM_AES_GCM:
		return true, 16
	case pkcs11.CKM_AES_CBC_PAD:
		return true, 16
	default:
		return false, 0
	}
}

func MechanismFromString(mech string) (uint, error) {
	switch mech {
	case "CKM_RSA_PKCS_OAEP":
		return pkcs11.CKM_RSA_PKCS_OAEP, nil
	case "CKM_RSA_PKCS":
		return pkcs11.CKM_RSA_PKCS, nil
	case "CKM_AES_GCM":
		return pkcs11.CKM_AES_GCM, nil
	case "CKM_AES_CBC_PAD":
		return pkcs11.CKM_AES_CBC_PAD, nil
	default:
		return 0, fmt.Errorf("unsupported mechanism: %s", mech)
	}
}

type pkcs11KMS struct {
	client	  *pkcs11.Ctx
	// standard PKCS11 configuration options
	slot      uint
	pin       string
	module    string
	keyId     string
	label     string
	mechanism uint
}

// Create a PKCS11 client for the configured module.
func (kms *pkcs11KMS) GetClient() (*pkcs11.Ctx, error) {
	if kms.client != nil {
		return kms.client, nil
	}
	kms.client = pkcs11.New(kms.module)
	err := kms.client.Initialize()
	if err != nil {
		kms.client = nil
		return nil, fmt.Errorf("failed to initialize PKCS11: %w", err)
	}
	return kms.client, nil
}

// Open a session and perform the authentication process.
func (kms *pkcs11KMS) GetSession() (pkcs11.SessionHandle, error) {
	if kms.client == nil {
		return 0, fmt.Errorf("PKCS11 not initialized")
	}

	session, err := kms.client.OpenSession(kms.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return 0, fmt.Errorf("failed to open session: %w", err)
	}
	err = kms.client.Login(session, pkcs11.CKU_USER, kms.pin)
	if err != nil {
		return 0, fmt.Errorf("failed to login: %w", err)
	}
	return session, nil
}

func (kms *pkcs11KMS) CloseSession(session pkcs11.SessionHandle) {
	if kms.client == nil {
		return
	}
	kms.client.Logout(session)
	kms.client.CloseSession(session)
}

func (kms *pkcs11KMS) DestroyClient() {
	if kms.client == nil {
		return
	}
	kms.client.Finalize()
	kms.client.Destroy()
	kms.client = nil
}

//
func (kms *pkcs11KMS) FindKey(session pkcs11.SessionHandle, typ uint) ([]pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(kms.label)),
		pkcs11.NewAttribute(typ, true),
	}
	keyIdBytes, err := hex.DecodeString(kms.keyId)
	if err == nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, keyIdBytes))
	}
	if kms.mechanism != 0 {
		keyTypeString, err := GetKeyTypeFromMech(kms.mechanism)
		if err != nil {
			return nil, fmt.Errorf("failed to get key type from mechanism: %s", err)
		}
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyTypeString))
	}

	if err := kms.client.FindObjectsInit(session, template); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 FindObjectsInit: %s", err)
	}
	obj, _, err := kms.client.FindObjects(session, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs11 FindObjects: %s", err)
	}
	if err := kms.client.FindObjectsFinal(session); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 FindObjectsFinal: %s", err)
	}

	return obj, nil
}

func (kms *pkcs11KMS) GetKeyMechanism(session pkcs11.SessionHandle, key pkcs11.ObjectHandle) (uint, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	}
	attr, err := kms.client.GetAttributeValue(session, pkcs11.ObjectHandle(key), template)
	if err != nil {
		return 0, fmt.Errorf("failed to pkcs11 GetAttributeValue: %s", err)
	}

	attrMap := GetAttributesMap(attr)
	keyType := GetValueAsInt(attrMap[pkcs11.CKA_KEY_TYPE])

	mechanism := uint(0)
	switch keyType {
	case pkcs11.CKK_AES:
		if kms.mechanism != 0 {
			mechanism = kms.mechanism
		} else {
			mechanism = pkcs11.CKM_AES_GCM
		}
	case pkcs11.CKK_RSA:
		if kms.mechanism != 0 {
			mechanism = kms.mechanism
		} else {
			mechanism = pkcs11.CKM_RSA_PKCS_OAEP
		}
	default:
		return 0, fmt.Errorf("unsupported key type: %d", keyType)
	}

	return mechanism, nil
}

//
func (kms *pkcs11KMS) Encrypt(ctx context.Context, plainDEK []byte) ([]byte, error) {
	session, err := kms.GetSession()
	if err != nil {
		return nil, err
	}
	defer kms.CloseSession(session)

	obj, err := kms.FindKey(session, pkcs11.CKA_ENCRYPT)
	if err != nil {
		return nil, err
	}
	if len(obj) != 1 {
		return nil, fmt.Errorf("expected 1 object, got %d", len(obj))
	}
	key := obj[0]

	mechanism, err := kms.GetKeyMechanism(session, key)
	if err != nil {
		return nil, err
	}

	var iv []byte
	needIV, ivLength := IsIvNeeded(mechanism)
	if needIV && ivLength > 0 {
		iv, err = uuid.GenerateRandomBytes(ivLength)
		if err != nil {
			return nil, err
		}
	}

	if err = kms.client.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, iv)}, key); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 EncryptInit: %s", err)
	}
	var ciphertext []byte
	if ciphertext, err = kms.client.Encrypt(session, plainDEK); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 Encrypt: %s", err)
	}

	if iv != nil {
		return append(iv, ciphertext...), nil
	} else {
		return ciphertext, nil
	}
}

// Decrypt uses the PKCS11 decrypt operation to decrypt the DEK.
func (kms *pkcs11KMS) Decrypt(ctx context.Context, encryptedDEK []byte) ([]byte, error) {
	session, err := kms.GetSession()
	if err != nil {
		return nil, err
	}
	defer kms.CloseSession(session)

	obj, err := kms.FindKey(session, pkcs11.CKA_DECRYPT)
	if err != nil {
		return nil, err
	}

	if len(obj) != 1 {
		return nil, fmt.Errorf("expected 1 object, got %d", len(obj))
	}
	key := obj[0]

	mechanism, err := kms.GetKeyMechanism(session, key)
	if err != nil {
		return nil, err
	}

	var iv []byte
	needIV, ivLength := IsIvNeeded(mechanism)
	if needIV && ivLength > 0 {
		if len(encryptedDEK) < ivLength {
			return nil, fmt.Errorf("encrypted DEK is too short")
		}

		iv = encryptedDEK[:ivLength]
		encryptedDEK = encryptedDEK[ivLength:]
	}

	if err = kms.client.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, iv)}, key); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 DecryptInit: %s", err)
	}

	var decrypted []byte
	if decrypted, err = kms.client.Decrypt(session, encryptedDEK); err != nil {
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
