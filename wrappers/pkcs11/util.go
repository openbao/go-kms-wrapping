// Copyright The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"crypto"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/pkcs11"
)

// Key is a helper type that is later used to perform key lookups.
// It enforces that at least one of ID, label are set.
type Key struct {
	// The key ID
	id string
	// The key label
	label string
	// Key type (CKK_*), -1 if unspecified.
	// We use -1 as "zero values" because 0 is e.g. a valid key type (RSA).
	keytype int
	// Mechanism (CKM_*), -1 if unspecified.
	mechanism int
	// Associated hash mechanism, -1 if unspecified.
	// Currently only used in conjunction with the RSA-OAEP mechanism.
	hash int
}

// NewKey creates a new Key from a ID, label, mechanism and keytype.
// All arguments are optional, but at least one of id, label must be non-empty.
func NewKey(id, label, keytype, mechanism, hash string) (*Key, error) {
	// Remove the 0x prefix.
	if strings.HasPrefix(id, "0x") {
		id = id[2:]
	}

	if id == "" && label == "" {
		return nil, fmt.Errorf("at least one one of key id, key label must be set")
	}

	key := &Key{
		id: id, label: label,
		keytype: -1, mechanism: -1, hash: -1,
	}

	var err error

	if mechanism != "" {
		key.mechanism, err = MechanismFromString(mechanism)
		if err != nil {
			return nil, err
		}
		key.keytype, err = MechanismToKeyType(key.mechanism)
		if err != nil {
			return nil, err
		}
	}

	if keytype != "" {
		tmp, err := KeyTypeFromString(keytype)
		if err != nil {
			return nil, err
		}

		// If keytype was previously set via mechanism,
		// validate that it matches the given key type.
		if key.keytype != -1 && tmp != key.keytype {
			return nil, fmt.Errorf("mechanism %q does not match key type %q", mechanism, keytype)
		}
		key.keytype = tmp
	}

	if hash != "" {
		key.hash, err = HashMechanismFromString(hash)
		if err != nil {
			return nil, err
		}
	}

	return key, nil
}

// String returns a string representation of the key.
func (k *Key) String() string {
	return fmt.Sprintf("%s:%s", k.label, k.id)
}

func (k *Key) CollectMetadata(metadata map[string]string) {
	if k.id != "" {
		metadata["key_id"] = k.id
	}
	if k.label != "" {
		metadata["key_label"] = k.label
	}
	if k.keytype != -1 {
		metadata["key_type"] = KeyTypeToString(k.keytype)
	}
	if k.mechanism != -1 {
		metadata["mechanism"] = MechanismToString(k.mechanism)
	}
	if k.hash != -1 {
		metadata["hash"] = HashMechanismToString(k.hash)
	}
}

// CertainlyAsymmetric attempts to determine whether the key is an asymmetric key
// _for certain_. If false, this does not imply that the key is symmetric!
// The key type may be unknown, and thus false will be returned.
func (k *Key) CertainlyAsymmetric() bool {
	switch k.keytype {
	case pkcs11.CKK_RSA, pkcs11.CKK_EC:
		return true
	}

	return false
}

// KeyTypeFromString parses supported key types from a string.
func KeyTypeFromString(keytype string) (int, error) {
	keytype = strings.ToUpper(keytype)
	switch keytype {
	case "CKK_RSA", "RSA":
		return pkcs11.CKK_RSA, nil
	case "CKK_EC", "CKK_ECDSA", "EC", "ECDSA":
		return pkcs11.CKK_EC, nil
	case "CKK_AES", "AES":
		return pkcs11.CKK_AES, nil
	}

	var err error
	var id uint64

	if strings.HasPrefix(keytype, "0x") {
		id, err = strconv.ParseUint(keytype[2:], 16, 32)
	} else {
		id, err = strconv.ParseUint(keytype, 10, 32)
	}

	if err != nil {
		return -1, fmt.Errorf("unsupported key type: %s", keytype)
	}

	switch int(id) {
	case pkcs11.CKK_RSA, pkcs11.CKK_AES, pkcs11.CKK_EC:
		return int(id), nil
	default:
		return -1, fmt.Errorf("unsupported key type: %s", keytype)
	}
}

// KeyTypeToString stringifies supported key types
func KeyTypeToString(keytype int) string {
	switch keytype {
	case pkcs11.CKK_RSA:
		return "CKK_RSA"
	case pkcs11.CKK_EC:
		return "CKM_EC"
	case pkcs11.CKK_AES:
		return "CKK_AES"
	default:
		return "Unknown"
	}
}

// MechanismFromString parses supported mechanisms from a string.
func MechanismFromString(mech string) (int, error) {
	mech = strings.ToUpper(mech)
	switch mech {
	case "CKM_RSA_PKCS_OAEP", "RSA_PKCS_OAEP":
		return pkcs11.CKM_RSA_PKCS_OAEP, nil
	case "CKM_AES_GCM", "AES_GCM":
		return pkcs11.CKM_AES_GCM, nil
	// Deprecated mechanisms
	case "CKM_RSA_PKCS", "RSA_PKCS", "CKM_AES_CBC_PAD", "AES_CBC_PAD":
		return -1, fmt.Errorf("deprecated mechanism: %s", mech)
	}

	var err error
	var id uint64

	if strings.HasPrefix(mech, "0x") {
		id, err = strconv.ParseUint(mech[2:], 16, 32)
	} else {
		id, err = strconv.ParseUint(mech, 10, 32)
	}

	if err != nil {
		return -1, fmt.Errorf("unsupported mechanism: %s", mech)
	}

	switch uint(id) { // Compare via uint, cannot overflow
	case pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.CKM_AES_GCM:
		return int(id), nil // Then return as int, above values are way below a max int
	// Deprecated mechanisms
	case pkcs11.CKM_RSA_PKCS, pkcs11.CKM_AES_CBC, pkcs11.CKM_AES_CBC_PAD:
		return -1, fmt.Errorf("deprecated mechanism: %s", mech)
	default:
		return -1, fmt.Errorf("unsupported mechanism: %s", mech)
	}
}

// MechanismToString stringifies supported mechanisms.
func MechanismToString(mech int) string {
	switch mech {
	case pkcs11.CKM_RSA_PKCS_OAEP:
		return "CKM_RSA_PKCS_OAEP"
	case pkcs11.CKM_AES_GCM:
		return "CKM_AES_GCM"
	// Deprecated mechanisms
	case pkcs11.CKM_RSA_PKCS:
		return "CKM_RSA_PKCS"
	case pkcs11.CKM_AES_CBC:
		return "CKM_AES_CBC"
	case pkcs11.CKM_AES_CBC_PAD:
		return "CKM_AES_CBC_PAD"
	default:
		return "Unknown"
	}
}

// MechanismToKeyType converts a supported mechanism to the respective key type.
func MechanismToKeyType(mech int) (int, error) {
	switch mech {
	case pkcs11.CKM_RSA_PKCS_OAEP:
		return pkcs11.CKK_RSA, nil
	case pkcs11.CKM_AES_GCM:
		return pkcs11.CKK_AES, nil
	default:
		return -1, fmt.Errorf("unsupported mechanism: %d", mech)
	}
}

// HashMechanismFromString parses supported hash mechanisms from a string.
func HashMechanismFromString(mech string) (int, error) {
	mech = strings.ToUpper(mech)
	switch mech {
	case "SHA1":
		return pkcs11.CKM_SHA_1, nil
	case "SHA224":
		return pkcs11.CKM_SHA224, nil
	case "SHA256":
		return pkcs11.CKM_SHA256, nil
	case "SHA384":
		return pkcs11.CKM_SHA384, nil
	case "SHA512":
		return pkcs11.CKM_SHA512, nil
	default:
		return -1, fmt.Errorf("unsupported mechanism: %s", mech)
	}
}

// HashMechanismFromCrypto converts a crypto.Hash to the PKCS#11 equivalent.
func HashMechanismFromCrypto(mech crypto.Hash) (int, error) {
	switch mech {
	case crypto.SHA1:
		return pkcs11.CKM_SHA_1, nil
	case crypto.SHA224:
		return pkcs11.CKM_SHA224, nil
	case crypto.SHA256:
		return pkcs11.CKM_SHA256, nil
	case crypto.SHA384:
		return pkcs11.CKM_SHA384, nil
	case crypto.SHA512:
		return pkcs11.CKM_SHA512, nil
	default:
		return -1, fmt.Errorf("unsupported mechanism: %s", mech)
	}
}

// HashMechanismToString stringifies supported hash mechanisms.
func HashMechanismToString(mech int) string {
	switch mech {
	case pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1:
		return "SHA1"
	case pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224:
		return "SHA224"
	case pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256:
		return "SHA256"
	case pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384:
		return "SHA384"
	case pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512:
		return "SHA512"
	default:
		return "Unknown"
	}
}

// HashMechanismToMgf gets the CKG_MGF1_SHA* for a CKM_SHA*.
func HashMechanismToMgf(mech int) (int, error) {
	switch mech {
	case pkcs11.CKM_SHA_1:
		return pkcs11.CKG_MGF1_SHA1, nil
	case pkcs11.CKM_SHA224:
		return pkcs11.CKG_MGF1_SHA224, nil
	case pkcs11.CKM_SHA256:
		return pkcs11.CKG_MGF1_SHA256, nil
	case pkcs11.CKM_SHA384:
		return pkcs11.CKG_MGF1_SHA384, nil
	case pkcs11.CKM_SHA512:
		return pkcs11.CKG_MGF1_SHA512, nil
	default:
		return -1, fmt.Errorf("unknown hash mechanism: %d", mech)
	}
}

// ParseSlotNumber parses a HSM slot number/ID from a string.
// Both Hex values (prefixed with "0x") and decimal values are supported.
// A slot number may be nil (= not specified).
func ParseSlotNumber(value string) (uint, error) {
	var slot uint64
	var err error

	value = strings.ToLower(value)
	if strings.HasPrefix(value, "0x") {
		slot, err = strconv.ParseUint(value[2:], 16, 32)
	} else {
		slot, err = strconv.ParseUint(value, 10, 32)
	}

	if err != nil {
		return 0, fmt.Errorf("failed to parse slot number: %w", err)
	}
	return uint(slot), nil
}

// BytesToUint converts a byte slice of either 1, 2, 4 or 8 bytes to a uint.
func BytesToUint(value []byte) (uint64, error) {
	switch len(value) {
	case 1:
		return uint64(value[0]), nil
	case 2:
		return uint64(binary.NativeEndian.Uint16(value)), nil
	case 4:
		return uint64(binary.NativeEndian.Uint32(value)), nil
	case 8:
		return binary.NativeEndian.Uint64(value), nil
	default:
		return 0, fmt.Errorf("cannot convert byte slice of length %d to uint", len(value))
	}
}
