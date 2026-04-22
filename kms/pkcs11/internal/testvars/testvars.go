// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package testvars

import (
	"os"
	"testing"
)

// Vars returns the PKCS#11 library path, token label and PIN to use in tests.
// The passed test is skipped if any of the required environment variables is
// not set.
func Vars(t *testing.T) (string, string, string) {
	lib, ok := os.LookupEnv("PKCS11_LIBRARY")
	if !ok {
		t.Skip("PKCS11_LIBRARY is unset")
	}

	token, ok := os.LookupEnv("PKCS11_TOKEN")
	if !ok {
		t.Skip("PKCS11_TOKEN is unset")
	}

	pin, ok := os.LookupEnv("PKCS11_PIN")
	if !ok {
		t.Skip("PKCS11_PIN is unset")
	}

	return lib, token, pin
}
