// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"fmt"
	"strconv"
	"strings"
	"encoding/binary"
	"encoding/hex"

	"github.com/openbao/openbao/api"
	uuid "github.com/hashicorp/go-uuid"
	pkcs11 "github.com/miekg/pkcs11"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

type Pkcs11Key struct {
	label		string
	id			string
}
func (k Pkcs11Key) String() string {
	return fmt.Sprintf("%s:%s", k.label, k.id)
}
func newPkcs11Key(v string) (*Pkcs11Key, error) {
	pos := strings.LastIndex(v, ":")
	if pos <= 0 {
		return nil, fmt.Errorf("Invalid key format")
	}
	k := &Pkcs11Key{
		label: v[:pos],
		id: v[pos+1:],
	}
	return k, nil
}
func (k Pkcs11Key) Set(v string) error {
	pos := strings.LastIndex(v, ":")
	if pos <= 0 {
		return fmt.Errorf("Invalid key format")
	}
	k.label = v[:pos]
	k.id = v[pos+1:]
	return nil
}

type pkcs11ClientEncryptor interface {
	Close()
	Encrypt(plaintext []byte) (ciphertext []byte, keyId *Pkcs11Key, err error)
	Decrypt(ciphertext []byte, keyId *Pkcs11Key) (plaintext []byte, err error)
}

type Pkcs11Client struct {
	client	  	*pkcs11.Ctx
	lib	    	string
	slot      	uint
	tokenLabel	string
	pin       	string
	keyLabel	string
	keyId     	string
	mechanism 	uint
}

const (
	EnvHsmWrapperLib   		= "BAO_HSM_LIB"
	EnvHsmWrapperSlot  		= "BAO_HSM_SLOT"
	EnvHsmWrapperTokenLabel = "BAO_HSM_TOKEN_LABEL"
	EnvHsmWrapperPin		= "BAO_HSM_PIN"
	EnvHsmWrapperKeyLabel	= "BAO_HSM_KEY_LABEL"
	EnvHsmWrapperKeyId		= "BAO_HSM_KEY_ID"
	EnvHsmWrapperMechanism  = "BAO_HSM_MECHANISM"
)

func newPkcs11Client(opts *options) (*Pkcs11Client, *wrapping.WrapperConfig, error) {
	var lib, slot, keyId, tokenLabel, pin, keyLabel, mechanism string
	var slotNum, mechanismNum uint64
	var err error

	switch {
	case api.ReadBaoVariable(EnvHsmWrapperLib) != "" && !opts.Options.WithDisallowEnvVars:
		lib = api.ReadBaoVariable(EnvHsmWrapperLib)
	case opts.withLib != "":
		lib = opts.withLib
	default:
		return nil, nil, fmt.Errorf("lib is required")
	}

	switch {
	case api.ReadBaoVariable(EnvHsmWrapperSlot) != "" && !opts.Options.WithDisallowEnvVars:
		slot = api.ReadBaoVariable(EnvHsmWrapperSlot)
	case opts.withSlot != "":
		slot = opts.withSlot
	default:
		slot = ""
	}

	switch {
	case api.ReadBaoVariable(EnvHsmWrapperTokenLabel) != "" && !opts.Options.WithDisallowEnvVars:
		tokenLabel = api.ReadBaoVariable(EnvHsmWrapperTokenLabel)
	case opts.withTokenLabel != "":
		tokenLabel = opts.withTokenLabel
	default:
		tokenLabel = ""
	}

	if slot == "" && tokenLabel == "" {
		return nil, nil, fmt.Errorf("slot or token label required")
	}

	switch {
	case api.ReadBaoVariable(EnvHsmWrapperKeyId) != "" && !opts.Options.WithDisallowEnvVars:
		keyId = api.ReadBaoVariable(EnvHsmWrapperKeyId)
	case opts.withKeyId != "":
		keyId = opts.withKeyId
	default:
		keyId = ""
	}

	switch {
	case api.ReadBaoVariable(EnvHsmWrapperPin) != "" && !opts.Options.WithDisallowEnvVars:
		pin = api.ReadBaoVariable(EnvHsmWrapperPin)
	case opts.withPin != "":
		pin = opts.withPin
	default:
		return nil, nil, fmt.Errorf("pin is required")
	}

	switch {
	case api.ReadBaoVariable(EnvHsmWrapperKeyLabel) != "" && !opts.Options.WithDisallowEnvVars:
		keyLabel = api.ReadBaoVariable(EnvHsmWrapperKeyLabel)
	case opts.withKeyLabel != "":
		keyLabel = opts.withKeyLabel
	default:
		return nil, nil, fmt.Errorf("key label is required")
	}

	switch {
	case api.ReadBaoVariable(EnvHsmWrapperMechanism) != "" && !opts.Options.WithDisallowEnvVars:
		mechanism = api.ReadBaoVariable(EnvHsmWrapperMechanism)
	case opts.withMechanism != "":
		mechanism = opts.withMechanism
	default:
		mechanism = ""
	}

	if slot != "" {
		if slotNum, err = numberAutoParse(slot, 32); err != nil {
			return nil, nil, fmt.Errorf("Invalid slot number")
		}
	} else {
		slotNum = 0
	}

	if mechanism != "" {
		if mechanismNum, err = MechanismFromString(mechanism); err != nil {
			return nil, nil, err
		}
	} else {
		mechanismNum = 0
	}

	client := &Pkcs11Client{
		client:    	nil,
		lib:		lib,
		slot:      	uint(slotNum),
		pin:       	pin,
		tokenLabel: tokenLabel,
		keyId:		keyId,
		keyLabel:  	keyLabel,
		mechanism: 	uint(mechanismNum),
	}
	
	// Initialize the client
	_, err = client.GetClient()
	if err != nil {
		return nil, nil, err
	}
	// Validate credentials for session establishment
	session, err := client.GetSession()
	if err != nil {
		return nil, nil, err
	}
	defer client.CloseSession(session)

	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["lib"] = lib
	wrapConfig.Metadata["key_label"] = keyLabel
	wrapConfig.Metadata["key_id"] = keyId
	if slotNum != 0 {
		wrapConfig.Metadata["slot"] = strconv.Itoa(int(slotNum))
	}
	if tokenLabel != "" {
		wrapConfig.Metadata["token_label"] = tokenLabel
	}
	if mechanismNum != 0 {
		wrapConfig.Metadata["mechanism"] = MechanismString(uint(mechanismNum))
	}

	return client, wrapConfig, nil
}


func (c *Pkcs11Client) Close() {
	if c.client == nil {
		return
	}
	c.client.Finalize()
	c.client.Destroy()
	c.client = nil
}

func (c *Pkcs11Client) Encrypt(plaintext []byte) ([]byte, *Pkcs11Key, error) {
	session, err := c.GetSession()
	if err != nil {
		return nil, nil, err
	}
	defer c.CloseSession(session)

	keyId := Pkcs11Key{ label: c.keyLabel, id: c.keyId }
	obj, err := c.FindKey(session, keyId, pkcs11.CKA_ENCRYPT)
	if err != nil {
		return nil, nil, err
	}
	if len(obj) != 1 {
		return nil, nil, fmt.Errorf("expected 1 object, got %d", len(obj))
	}
	key := obj[0]

	mechanism, err := c.GetKeyMechanism(session, key)
	if err != nil {
		return nil, nil, err
	}

	var iv []byte
	needIV, ivLength := IsIvNeeded(mechanism)
	if needIV && ivLength > 0 {
		iv, err = uuid.GenerateRandomBytes(ivLength)
		if err != nil {
			return nil, nil, err
		}
	}

	if err = c.client.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, iv)}, key); err != nil {
		return nil, nil, fmt.Errorf("failed to pkcs11 EncryptInit: %s", err)
	}
	var ciphertext []byte
	if ciphertext, err = c.client.Encrypt(session, plaintext); err != nil {
		return nil, nil, fmt.Errorf("failed to pkcs11 Encrypt: %s", err)
	}

	if iv != nil {
		return append(iv, ciphertext...), &keyId, nil
	} else {
		return ciphertext, &keyId, nil
	}
}

func (c *Pkcs11Client) Decrypt(ciphertext []byte, keyId *Pkcs11Key) ([]byte, error) {
	session, err := c.GetSession()
	if err != nil {
		return nil, err
	}
	defer c.CloseSession(session)

	if keyId == nil {
		keyId = &Pkcs11Key{ label: c.keyLabel, id: c.keyId }
	}

	obj, err := c.FindKey(session, *keyId, pkcs11.CKA_DECRYPT)
	if err != nil {
		return nil, err
	}

	if len(obj) != 1 {
		return nil, fmt.Errorf("expected 1 object, got %d", len(obj))
	}
	key := obj[0]

	mechanism, err := c.GetKeyMechanism(session, key)
	if err != nil {
		return nil, err
	}

	var iv []byte
	needIV, ivLength := IsIvNeeded(mechanism)
	if needIV && ivLength > 0 {
		if len(ciphertext) < ivLength {
			return nil, fmt.Errorf("encrypted DEK is too short")
		}

		iv = ciphertext[:ivLength]
		ciphertext = ciphertext[ivLength:]
	}

	if err = c.client.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, iv)}, key); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 DecryptInit: %s", err)
	}

	var decrypted []byte
	if decrypted, err = c.client.Decrypt(session, ciphertext); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 Decrypt: %s", err)
	}
	return decrypted, nil
}

// Create a PKCS11 client for the configured module.
func (c *Pkcs11Client) GetClient() (*pkcs11.Ctx, error) {
	if c.client != nil {
		return c.client, nil
	}
	c.client = pkcs11.New(c.lib)
	err := c.client.Initialize()
	if err != nil {
		c.client = nil
		return nil, fmt.Errorf("failed to initialize PKCS11: %w", err)
	}
	return c.client, nil
}

func (c *Pkcs11Client) GetSlotForLabel() (uint, error) {
	if c.slot != 0 {
		return c.slot, nil
	}
	if c.tokenLabel == "" {
		return 0, fmt.Errorf("not token label configured")
	}
	slots, _ := c.client.GetSlotList(true)
	for _, slot := range slots {
		tokenInfo, err := c.client.GetTokenInfo(slot)
		if err == nil && tokenInfo.Label == c.tokenLabel {
			c.slot = slot
			break
		}
	}
	if c.slot == 0 {
		return 0, fmt.Errorf("failed to find token with label: %s", c.tokenLabel)
	}
	return c.slot, nil
}

// Open a session and perform the authentication process.
func (c *Pkcs11Client) GetSession() (pkcs11.SessionHandle, error) {
	if c.client == nil {
		return 0, fmt.Errorf("PKCS11 not initialized")
	}

	if c.slot == 0 {
		_, err := c.GetSlotForLabel()
		if err != nil {
			return 0, err
		}
	}

	session, err := c.client.OpenSession(c.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return 0, fmt.Errorf("failed to open session: %w", err)
	}
	err = c.client.Login(session, pkcs11.CKU_USER, c.pin)
	if err != nil {
		return 0, fmt.Errorf("failed to login: %w", err)
	}
	return session, nil
}

func (c *Pkcs11Client) CloseSession(session pkcs11.SessionHandle) {
	if c.client == nil {
		return
	}
	c.client.Logout(session)
	c.client.CloseSession(session)
}

//
func (c *Pkcs11Client) FindKey(session pkcs11.SessionHandle, key Pkcs11Key, typ uint) ([]pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(key.label)),
		pkcs11.NewAttribute(typ, true),
	}
	if keyIdBytes, err := hex.DecodeString(key.id); err == nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, keyIdBytes))
	}
	if c.mechanism != 0 {
		keyTypeString, err := GetKeyTypeFromMech(c.mechanism)
		if err != nil {
			return nil, fmt.Errorf("failed to get key type from mechanism: %s", err)
		}
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyTypeString))
	}

	if err := c.client.FindObjectsInit(session, template); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 FindObjectsInit: %s", err)
	}
	obj, _, err := c.client.FindObjects(session, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs11 FindObjects: %s", err)
	}
	if err := c.client.FindObjectsFinal(session); err != nil {
		return nil, fmt.Errorf("failed to pkcs11 FindObjectsFinal: %s", err)
	}

	return obj, nil
}

func (c *Pkcs11Client) GetKeyMechanism(session pkcs11.SessionHandle, key pkcs11.ObjectHandle) (uint, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	}
	attr, err := c.client.GetAttributeValue(session, pkcs11.ObjectHandle(key), template)
	if err != nil {
		return 0, fmt.Errorf("failed to pkcs11 GetAttributeValue: %s", err)
	}

	attrMap := GetAttributesMap(attr)
	keyType := GetValueAsInt(attrMap[pkcs11.CKA_KEY_TYPE])

	mechanism := uint(0)
	switch keyType {
	case pkcs11.CKK_AES:
		if c.mechanism != 0 {
			mechanism = c.mechanism
		} else {
			mechanism = pkcs11.CKM_AES_GCM
		}
	case pkcs11.CKK_RSA:
		if c.mechanism != 0 {
			mechanism = c.mechanism
		} else {
			mechanism = pkcs11.CKM_RSA_PKCS_OAEP
		}
	default:
		return 0, fmt.Errorf("unsupported key type: %d", keyType)
	}

	return mechanism, nil
}

func (c *Pkcs11Client) GetCurrentKey() Pkcs11Key {
	return Pkcs11Key{
		label: c.keyLabel,
		id: c.keyId,
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

func MechanismString(mech uint) string {
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

func MechanismFromString(mech string) (uint64, error) {
	switch mech {
	case "CKM_RSA_PKCS_OAEP", "RSA_PKCS_OAEP":
		return pkcs11.CKM_RSA_PKCS_OAEP, nil
	case "CKM_RSA_PKCS", "RSA_PKCS":
		return pkcs11.CKM_RSA_PKCS, nil
	case "CKM_AES_GCM", "AES_GCM":
		return pkcs11.CKM_AES_GCM, nil
	case "CKM_AES_CBC_PAD", "AES_CBC_PAD":
		return pkcs11.CKM_AES_CBC_PAD, nil
	default:
		if mechanismNum, err := numberAutoParse(mech, 32); err == nil {
			if _, err = GetKeyTypeFromMech(uint(mechanismNum)); err == nil {
				return mechanismNum, nil
			}
		}
		return 0, fmt.Errorf("unsupported mechanism: %s", mech)
	}
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

func numberAutoParse(value string, bitSize int) (uint64, error) {
	var ret uint64
	var err error
	value = strings.ToLower(value)
	if strings.HasPrefix(value, "0x") {
		ret, err = strconv.ParseUint(value[2:], 16, bitSize)
	} else {
		ret, err = strconv.ParseUint(value, 10, bitSize)
	}
	return ret, err
}