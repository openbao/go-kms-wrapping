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
func mechanismFromString(input string) (uint, uint, error) {
	upper := strings.ToUpper(input)
	switch upper {
	case "CKM_AES_GCM", "AES_GCM":
		return pkcs11.CKM_AES_GCM, pkcs11.CKK_AES, nil
	case "CKM_RSA_PKCS_OAEP", "RSA_PKCS_OAEP":
		return pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.CKK_RSA, nil
	// Deprecated mechanisms
	case "CKM_AES_CBC_PAD", "AES_CBC_PAD", "CKM_RSA_PKCS", "RSA_PKCS":
		return 0, 0, fmt.Errorf("deprecated mechanism: %s", upper)
	}

	var err error
	var id uint64

	if strings.HasPrefix(input, "0x") {
		id, err = strconv.ParseUint(input[2:], 16, 32)
	} else {
		id, err = strconv.ParseUint(input, 10, 32)
	}

	if err != nil {
		return 0, 0, fmt.Errorf("unsupported mechanism: %s", input)
	}

	switch uint(id) {
	case pkcs11.CKM_AES_GCM:
		return pkcs11.CKM_AES_GCM, pkcs11.CKK_AES, nil
	case pkcs11.CKM_RSA_PKCS_OAEP:
		return pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.CKK_RSA, nil
	case pkcs11.CKM_AES_CBC, pkcs11.CKM_AES_CBC_PAD, pkcs11.CKM_RSA_PKCS:
		return 0, 0, fmt.Errorf("deprecated mechanism: %s", upper)
	default:
		return 0, 0, fmt.Errorf("unsupported mechanism: %s", input)
	}
}

// maybeMechanismFromString calls mechanismFromString, but returns
// nil values if the input is empty.
func maybeMechanismFromString(input string) (*uint, *uint, error) {
	if input == "" {
		return nil, nil, nil
	}
	mechanism, keytype, err := mechanismFromString(input)
	if err != nil {
		return nil, nil, err
	}
	return &mechanism, &keytype, nil
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

// hashMechanismFromString parses supported hash mechanisms from a string.
func hashMechanismFromString(input string) (uint, error) {
	switch strings.ToUpper(input) {
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
		return 0, fmt.Errorf("unsupported hash mechanism: %s", input)
	}
}

// hashMechanismFromStringOrDefault calls hashMechanismFromString,
// but returns DefaultRSAOAEPHash if the input is empty.
func hashMechanismFromStringOrDefault(input string) (uint, error) {
	switch input {
	case "":
		return DefaultRSAOAEPHash, nil
	default:
		return hashMechanismFromString(input)
	}
}

// hashMechanismFromCrypto converts a crypto.Hash to the PKCS#11 equivalent.
func hashMechanismFromCrypto(hash crypto.Hash) (uint, error) {
	switch hash {
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
		return 0, fmt.Errorf("unsupported hash mechanism: %s", hash)
	}
}

// hashMechanismToCrypto converts a PKCS#11 hash mechanism to the crypto.Hash equivalent.
func hashMechanismToCrypto(mech uint) crypto.Hash {
	switch mech {
	case pkcs11.CKM_SHA_1:
		return crypto.SHA1
	case pkcs11.CKM_SHA224:
		return crypto.SHA224
	case pkcs11.CKM_SHA256:
		return crypto.SHA256
	case pkcs11.CKM_SHA384:
		return crypto.SHA384
	case pkcs11.CKM_SHA512:
		return crypto.SHA512
	default:
		// Unreachable, only called on previously resolved hash mechanism.
		panic("internal error: unknown hash mechanism")
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
func parseSlotNumber(input string) (uint, error) {
	var slot uint64
	var err error

	input = strings.ToLower(input)
	if strings.HasPrefix(input, "0x") {
		slot, err = strconv.ParseUint(input[2:], 16, 32)
	} else {
		slot, err = strconv.ParseUint(input, 10, 32)
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

	id = strings.TrimPrefix(id, "0x")
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

// parseBool parses a boolean value from a string.
func parseBool(value string) (bool, error) {
	switch strings.ToLower(value) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	default:
		return false, fmt.Errorf("failed to parse boolean value: %s", value)
	}
}

// wrapErr is fmt.Errorf("message: %w", err), but returns nil
// if the error to be wrapped is nil. This cleans up some
// PKCS#11 error handling control flow where a failed call
// makes us make another fallible call for cleanup, and
// we need to errors.Join(...) both errors at the end.
func wrapErr(err error, format string, args ...any) error {
	if err != nil {
		return fmt.Errorf(format+": %w", append(args, err)...)
	} else {
		return nil
	}
}
