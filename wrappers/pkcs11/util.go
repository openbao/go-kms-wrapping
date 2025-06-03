// Copyright The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/pkcs11"
)

// mechanismFromString parses supported mechanisms from a string.
func mechanismFromString(mech string) (uint, uint, error) {
	mech = strings.ToUpper(mech)
	switch mech {
	case "CKM_AES_GCM", "AES_GCM":
		return pkcs11.CKM_AES_GCM, pkcs11.CKK_AES, nil
	case "CKM_RSA_PKCS_OAEP", "RSA_PKCS_OAEP":
		return pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.CKK_RSA, nil
	// Deprecated mechanisms
	case "CKM_AES_CBC_PAD", "AES_CBC_PAD", "CKM_RSA_PKCS", "RSA_PKCS":
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
	case pkcs11.CKM_AES_GCM:
		return pkcs11.CKM_AES_GCM, pkcs11.CKK_AES, nil
	case pkcs11.CKM_RSA_PKCS_OAEP:
		return pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.CKK_RSA, nil
	case pkcs11.CKM_AES_CBC, pkcs11.CKM_AES_CBC_PAD, pkcs11.CKM_RSA_PKCS:
		return 0, 0, fmt.Errorf("deprecated mechanism: %s", mech)
	default:
		return 0, 0, fmt.Errorf("unsupported mechanism: %s", mech)
	}
}

// mechanismToString stringifies supported mechanisms.
func mechanismToString(mech uint) string {
	switch mech {
	case pkcs11.CKM_AES_GCM:
		return "CKM_AES_GCM"
	case pkcs11.CKM_RSA_PKCS_OAEP:
		return "CKM_RSA_PKCS_OAEP"
	default:
		// Unreachable, only called on previously resolved mechanism.
		panic("internal error: unknown mechanism")
	}
}

// bestAvailableMechanism returns the best-available
// encryption/decryption mechanism for a key type.
func bestAvailableMechanism(keytype uint) uint {
	switch keytype {
	case pkcs11.CKK_AES:
		return pkcs11.CKM_AES_GCM
	case pkcs11.CKK_RSA:
		return pkcs11.CKM_RSA_PKCS_OAEP
	default:
		// Unreachable, only called on previously validated key type.
		panic("internal error: unknown mechanism")
	}
}

// isAsymmetricKeyType returns whether a key type is asymmetric.
func isAsymmetricKeyType(keytype uint) bool {
	switch keytype {
	case pkcs11.CKK_RSA, pkcs11.CKK_EC:
		return true
	default:
		return false
	}
}

// hashMechanismFromStringarses supported hash mechanisms from a string.
func hashMechanismFromString(mech string) (uint, error) {
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
		return 0, fmt.Errorf("unsupported hash mechanism: %s", mech)
	}
}

// hashMechanismFromCrypto converts a crypto.Hash to the PKCS#11 equivalent.
func hashMechanismFromCrypto(mech crypto.Hash) (uint, error) {
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
		return 0, fmt.Errorf("unsupported hash mechanism: %s", mech)
	}
}

// hashMechanismToMgf gets the CKG_MGF1_SHA* for a CKM_SHA*.
func hashMechanismToMgf(mech uint) uint {
	switch mech {
	case pkcs11.CKM_SHA_1:
		return pkcs11.CKG_MGF1_SHA1
	case pkcs11.CKM_SHA224:
		return pkcs11.CKG_MGF1_SHA224
	case pkcs11.CKM_SHA256:
		return pkcs11.CKG_MGF1_SHA256
	case pkcs11.CKM_SHA384:
		return pkcs11.CKG_MGF1_SHA384
	case pkcs11.CKM_SHA512:
		return pkcs11.CKG_MGF1_SHA512
	default:
		// Unreachable, only called on previously resolved hash mechanism.
		panic("internal error: unknown hash mechanism")
	}
}

// hashMechanismToString stringifies supported hash mechanisms.
func hashMechanismToString(mech uint) string {
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
		// Unreachable, only called on previously resolved hash mechanism.
		panic("internal error: unknown hash mechanism")
	}
}

// parseSlotNumber parses a HSM slot number/ID from a string.
// Both Hex values (prefixed with "0x") and decimal values are supported.
// A slot number may be nil (= not specified).
func parseSlotNumber(value string) (uint, error) {
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

// parseIDLabel parses a key ID, label pair to bytes.
// It ensures that at least one of the resulting id, label are non-nil.
func parseIDLabel(id, label string) ([]byte, []byte, error) {
	var byteID, byteLabel []byte = nil, nil

	if strings.HasPrefix(id, "0x") {
		id = id[2:]
	}
	if decoded, err := hex.DecodeString(id); err == nil && len(decoded) != 0 {
		byteID = decoded
	}

	if label != "" {
		byteLabel = []byte(label)
	}

	if byteID == nil && byteLabel == nil {
		return nil, nil, fmt.Errorf("at least one of key id, key label must be set")
	}

	return byteID, byteLabel, nil
}

// bytesToUint converts a byte slice of either 1, 2, 4 or 8 bytes to a uint.
func bytesToUint(value []byte) (uint64, error) {
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
