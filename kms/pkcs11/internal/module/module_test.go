// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package module

import (
	"testing"

	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/testvars"
	"github.com/stretchr/testify/require"
)

func Test(t *testing.T) {
	lib, label, _ := testvars.Vars(t)

	t.Run("Open+Drop", func(t *testing.T) {
		m1, err := Open(lib)
		require.NoError(t, err, "module should open")

		require.Len(t, cache, 1, "cache should have one module")
		require.Equal(t, m1.refs, 1, "module should have one reference")

		m2, err := Open(lib)
		require.NoError(t, err, "module should open")

		require.Equal(t, m1.module, m2.module, "modules referenced should be equal")
		require.Equal(t, m1.refs, 2, "module should have two references")
		require.Equal(t, m2.refs, 2, "module should have two references")

		require.Len(t, cache, 1, "cache should only have one module")

		require.NoError(t, m1.Drop(), "reference should drop on first call")
		require.Error(t, m1.Drop(), "dropping a reference twice should error")
		require.Len(t, cache, 1, "cache should still have the module")

		require.NoError(t, m2.Drop(), "reference should drop on first call")
		require.Len(t, cache, 0, "cache should be empty after dropping all references")
		require.Equal(t, m1.refs, 0, "module should have no more references")
	})

	t.Run("GetToken", func(t *testing.T) {
		mod, err := Open(lib)
		require.NoError(t, err)

		token, err := mod.GetToken(SelectLabel(label))
		require.NoError(t, err, "should find token by label")
		require.Equal(t, label, token.Info.Label, "label should match searched label")

		{
			tok, err := mod.GetToken(SelectID(token.ID))
			require.NoError(t, err, "should find token by slot ID")
			require.Equal(t, token.ID, tok.ID, "slot ID should match searched ID")
		}

		{
			tok, err := mod.GetToken(SelectID(token.ID), SelectLabel("foobar"))
			require.Nil(t, tok, "should not find bogus token")
			require.Error(t, err, "should error when token is not found")
		}

		{
			tok, err := mod.GetToken(SelectID(token.ID), SelectLabel(token.Info.Label))
			require.NoError(t, err, "should find token")
			require.Equal(t, token.ID, tok.ID, "slot ID should match searched ID")
			require.Equal(t, token.Info.Label, tok.Info.Label, "label should match searched label")
		}

		{
			tok, err := mod.GetToken(SelectSerial(token.Info.SerialNumber))
			require.NoError(t, err, "should find token")
			require.Equal(t, token.Info.SerialNumber, tok.Info.SerialNumber, "serial should match searched serial")
			require.Equal(t, token.ID, tok.ID, "slot ID should match known ID")

			tok, err = mod.GetToken(SelectID(token.ID), SelectSerial(tok.Info.SerialNumber))
			require.NoError(t, err, "should find token")
			require.Equal(t, token.ID, tok.ID, "slot ID should match searched ID")
			require.Equal(t, token.Info.SerialNumber, tok.Info.SerialNumber, "serial number should match searched serial number")
		}
	})
}
