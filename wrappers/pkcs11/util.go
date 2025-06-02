// Copyright The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"crypto"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/pkcs11"
)

const DefaultRSAOAEPHash = pkcs11.CKM_SHA256

// Key is a helper type that is later used to perform key lookups.
// It enforces that at least one of ID, label are set.
type Key struct {
	// The key ID
	id string
	// The key label
	label string
	// Mechanism (CKM_*)
	mechanism uint
	// Key type (CKK_*) derived from mechanism
	keytype uint
	// Associated hash mechanism for RSA-OAEP
	hash uint
}

// NewKey creates a new Key from a ID, label and mechanism.
// - One of key id, key label may be empty
// - Mechanism must be set
func NewKey(id, label, mechanism string) (*Key, error) {
	// Remove the 0x prefix.
	if strings.HasPrefix(id, "0x") {
		id = id[2:]
	}
	if id == "" && label == "" {
		return nil, fmt.Errorf("at least one one of key id, key label must be set")
	}
	if mechanism == "" {
		return nil, fmt.Errorf("key mechanism must be set")
	}

	key := &Key{id: id, label: label, hash: DefaultRSAOAEPHash}

	var err error
	key.mechanism, key.keytype, err = MechanismFromString(mechanism)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// NewKeyWithHash is like NewKey, but also parses a hash mechanism.
func NewKeyWithHash(id, label, mechanism, hash string) (*Key, error) {
	key, err := NewKey(id, label, mechanism)
	if err != nil {
		return nil, err
	}
	if hash == "" {
		return key, nil
	}
	key.hash, err = HashMechanismFromString(hash)
	return key, err
}

// String returns a string representation of the key.
func (k *Key) String() string {
	return fmt.Sprintf("%s:%s", k.label, k.id)
}

// CollectMetadata collects stringified key info into a map.
func (k *Key) CollectMetadata(metadata map[string]string) {
	if k.id != "" {
		metadata["key_id"] = k.id
	}
	if k.label != "" {
		metadata["key_label"] = k.label
	}

	metadata["mechanism"] = MechanismToString(k.mechanism)
	switch k.mechanism {
	case pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.CKM_RSA_PKCS_PSS:
		metadata["hash"] = HashMechanismToString(k.hash)
	}
}

// IsAsymmetric determines whether the key is asymmetric.
func (k *Key) IsAsymmetric() bool {
	switch k.keytype {
	case pkcs11.CKK_RSA, pkcs11.CKK_EC:
		return true
	}

	return false
}

// MechanismFromString parses supported mechanisms from a string.
func MechanismFromString(mech string) (uint, uint, error) {
	mech = strings.ToUpper(mech)
	switch mech {
	case "CKM_RSA_PKCS_OAEP", "RSA_PKCS_OAEP":
		return pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.CKK_RSA, nil
	case "CKM_RSA_PKCS_PSS", "RSA_PKCS_PSS":
		return pkcs11.CKM_RSA_PKCS_PSS, pkcs11.CKK_RSA, nil
	case "CKM_RSA_PKCS", "RSA_PKCS":
		return pkcs11.CKM_RSA_PKCS, pkcs11.CKK_RSA, nil
	case "CKM_ECDSA", "ECDSA":
		return pkcs11.CKM_ECDSA, pkcs11.CKK_EC, nil
	case "CKM_AES_GCM", "AES_GCM":
		return pkcs11.CKM_AES_GCM, pkcs11.CKK_AES, nil
	// Deprecated mechanisms
	case "CKM_AES_CBC_PAD", "AES_CBC_PAD":
		return 0, 0, fmt.Errorf("deprecated mechanism: %s", mech)
	}

	var err error
	var id uint64

	if strings.HasPrefix(mech, "0x") {
		id, err = strconv.ParseUint(mech[2:], 16, 32)
	} else {
		id, err = strconv.ParseUint(mech, 10, 32)
	}

	if err != nil {
		return 0, 0, fmt.Errorf("unsupported mechanism: %s", mech)
	}

	switch uint(id) {
	case pkcs11.CKM_RSA_PKCS_OAEP:
		return pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.CKK_RSA, nil
	case pkcs11.CKM_RSA_PKCS_PSS:
		return pkcs11.CKM_RSA_PKCS_PSS, pkcs11.CKK_RSA, nil
	case pkcs11.CKM_RSA_PKCS:
		return pkcs11.CKM_RSA_PKCS, pkcs11.CKK_RSA, nil
	case pkcs11.CKM_ECDSA:
		return pkcs11.CKM_ECDSA, pkcs11.CKK_EC, nil
	case pkcs11.CKM_AES_GCM:
		return pkcs11.CKM_AES_GCM, pkcs11.CKK_AES, nil
	case pkcs11.CKM_AES_CBC, pkcs11.CKM_AES_CBC_PAD:
		return 0, 0, fmt.Errorf("deprecated mechanism: %s", mech)
	default:
		return 0, 0, fmt.Errorf("unsupported mechanism: %s", mech)
	}
}

// MechanismToString stringifies supported mechanisms.
func MechanismToString(mech uint) string {
	switch mech {
	case pkcs11.CKM_RSA_PKCS_OAEP:
		return "CKM_RSA_PKCS_OAEP"
	case pkcs11.CKM_RSA_PKCS_PSS:
		return "CKM_RSA_PKCS_PSS"
	case pkcs11.CKM_RSA_PKCS:
		return "CKM_RSA_PKCS"
	case pkcs11.CKM_ECDSA:
		return "CKM_ECDSA"
	case pkcs11.CKM_AES_GCM:
		return "CKM_AES_GCM"
	// Deprecated mechanisms
	case pkcs11.CKM_AES_CBC:
		return "CKM_AES_CBC"
	case pkcs11.CKM_AES_CBC_PAD:
		return "CKM_AES_CBC_PAD"
	default:
		return fmt.Sprintf("Unknown (%d)", mech)
	}
}

// HashMechanismFromString parses supported hash mechanisms from a string.
func HashMechanismFromString(mech string) (uint, error) {
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
		return 0, fmt.Errorf("unsupported mechanism: %s", mech)
	}
}

// HashMechanismFromCrypto converts a crypto.Hash to the PKCS#11 equivalent.
func HashMechanismFromCrypto(mech crypto.Hash) (uint, error) {
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
		return 0, fmt.Errorf("unsupported mechanism: %s", mech)
	}
}

// HashMechanismToString stringifies supported hash mechanisms.
func HashMechanismToString(mech uint) string {
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
func HashMechanismToMgf(mech uint) (uint, error) {
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
		return 0, fmt.Errorf("unknown hash mechanism: %d", mech)
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
