// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package module

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	TestSetup(m)
}

func Test(t *testing.T) {
	t.Run("Get+Drop", func(t *testing.T) {
		m1, err := Open(TestPath)
		require.NoError(t, err, "module should open")

		require.Len(t, cache, 1, "cache should have one module")
		require.Equal(t, m1.refs, 1, "module should have one reference")

		m2, err := Open(TestPath)
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
		mod, tokens := TestTokens(t, 5)

		for _, token := range tokens {
			{
				tok, err := mod.GetToken(SelectID(token.ID))
				require.NoError(t, err, "should find token by slot ID")
				require.Equal(t, token.ID, tok.ID, "slot ID should match search ID")
			}

			{
				tok, err := mod.GetToken(SelectID(token.ID), SelectLabel("foobar"))
				require.Nil(t, tok, "should not find bogus token")
				require.Error(t, err, "should error when token is not found")
			}

			{
				tok, err := mod.GetToken(SelectLabel(token.Info.Label))
				require.NoError(t, err, "should find token by label")
				require.Equal(t, token.Info.Label, tok.Info.Label, "label should match search label")
				require.Equal(t, token.ID, tok.ID, "slot ID should match known ID")

				tok, err = mod.GetToken(SelectID(tok.ID), SelectLabel(tok.Info.Label))
				require.NoError(t, err, "should find token")
				require.Equal(t, token.ID, tok.ID, "slot ID should match search ID")
				require.Equal(t, token.Info.Label, tok.Info.Label, "label should match search label")
			}

			{
				tok, err := mod.GetToken(SelectSerial(token.Info.SerialNumber))
				require.NoError(t, err, "should find token")
				require.Equal(t, token.Info.SerialNumber, tok.Info.SerialNumber, "serial should match search serial")
				require.Equal(t, token.ID, tok.ID, "slot ID should match known ID")

				tok, err = mod.GetToken(SelectID(tok.ID), SelectSerial(tok.Info.SerialNumber))
				require.NoError(t, err, "should find token")
				require.Equal(t, token.ID, tok.ID, "slot ID should match search ID")
				require.Equal(t, token.Info.SerialNumber, tok.Info.SerialNumber, "label should match search label")
			}
		}
	})
}
