// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0

//go:build go1.27

package securosyshsm

import (
	"crypto"
	"crypto/mldsa"
)

func isMLDSAPublicKey(pub crypto.PublicKey) bool {
	_, ok := pub.(*mldsa.PublicKey)
	return ok
}
