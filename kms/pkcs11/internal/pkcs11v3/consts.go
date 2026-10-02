// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// package pkcs11v3 declares constant values present in PKCS#11 v3.x headers
// that are used by this module. While miekg/pkcs11 only includes support for
// v2.x headers and APIs, it is able to load v3.x libraries, and we can access
// several v3.x features just by knowing the right constant values.
//
// Once miekg/pkcs11 is at v3.x, this package can be dropped as all constants
// declared below should become available there.
package pkcs11v3

const (
	// Key types:
	CKK_ML_DSA     = 0x0000004A
	CKK_EC_EDWARDS = 0x00000040

	// Key generation mechanisms:
	CKM_ML_DSA_KEY_PAIR_GEN     = 0x0000001C
	CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x00001055

	// Signature schemes:
	CKM_ML_DSA = 0x0000001D
	CKM_EDDSA  = 0x00001057

	// Attributes:
	CKA_PARAMETER_SET = 0x0000061D

	// Parameter sets:
	CKP_ML_DSA_44 = 0x00000001
	CKP_ML_DSA_65 = 0x00000002
	CKP_ML_DSA_87 = 0x00000003
)
