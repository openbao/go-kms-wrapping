// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package wrapping

type WrapperType string

// These constants define types of Wrappers known by the main go-kms-wrapping
// module. Submodules that provide additional Wrapper implementations should
// export their own type constant for convenience.
const (
	WrapperTypeUnknown WrapperType = "unknown"
	WrapperTypeAead    WrapperType = "aead"
	WrapperTypeTest    WrapperType = "test-auto"
)

func (t WrapperType) String() string {
	return string(t)
}

type AeadType uint32

// These values define supported types of AEADs
const (
	AeadTypeUnknown AeadType = iota
	AeadTypeAesGcm
)

func (t AeadType) String() string {
	switch t {
	case AeadTypeAesGcm:
		return "aes-gcm"
	default:
		return "unknown"
	}
}

func AeadTypeMap(t string) AeadType {
	switch t {
	case "aes-gcm":
		return AeadTypeAesGcm
	default:
		return AeadTypeUnknown
	}
}

type HashType uint32

// These values define supported types of hashes
const (
	HashTypeUnknown HashType = iota
	HashTypeSha256
)

func (t HashType) String() string {
	switch t {
	case HashTypeSha256:
		return "sha256"
	default:
		return "unknown"
	}
}

func HashTypeMap(t string) HashType {
	switch t {
	case "sha256":
		return HashTypeSha256
	default:
		return HashTypeUnknown
	}
}
