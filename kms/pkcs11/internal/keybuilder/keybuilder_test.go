// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package keybuilder

import (
	"testing"

	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/module"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	module.TestSetup(m)
}

func Test(t *testing.T) {
	s, _ := session.TestSession(t)

	t.Run("Secret", func(t *testing.T) {
		t.Run("AES", func(t *testing.T) {
			_, err := AES(32).Label("foo").ID("bar").Generate(s)
			require.NoError(t, err)
		})
	})

	t.Run("Pair", func(t *testing.T) {
		t.Run("RSA", func(t *testing.T) {
			_, _, err := RSA(2048).Label("foo").ID("bar").Generate(s)
			require.NoError(t, err)
			_, _, err = RSA(4096).Label("foo").ID("bar").Generate(s)
			require.NoError(t, err)
		})

		t.Run("EC", func(t *testing.T) {
			_, _, err := EC(kms.Curve_P256).Label("p256").Generate(s)
			require.NoError(t, err)
			_, _, err = EC(kms.Curve_P384).Label("p384").Generate(s)
			require.NoError(t, err)
			_, _, err = EC(kms.Curve_P521).Label("p521").Generate(s)
			require.NoError(t, err)
		})
	})
}
