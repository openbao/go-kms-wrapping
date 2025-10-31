// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package module

import (
	"testing"

	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/softhsm"
	"github.com/stretchr/testify/require"
)

func Test(t *testing.T) {
	t.Run("Get+Drop", func(t *testing.T) {
		hsm := softhsm.New(t)

		m1, err := Open(hsm.Path)
		require.NoError(t, err, "module should open")

		require.Len(t, cache, 1, "cache should have one module")
		require.Equal(t, m1.refs, 1, "module should have one reference")

		m2, err := Open(hsm.Path)
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
		t.Run("no tokens", func(t *testing.T) {
			hsm := softhsm.New(t)
			mod := TestOpen(t, hsm.Path)

			token, err := mod.GetToken(SelectID(123))
			require.Nil(t, token, "should not find bogus token")
			require.Error(t, err, "should error when token is not found")
		})

		t.Run("many tokens", func(t *testing.T) {
			hsm := softhsm.New(t)

			// Note: These must be initialized before loading the module,
			// or they will not be visible in GetSlotList().
			label1, _ := hsm.InitToken()
			label2, _ := hsm.InitToken()

			mod := TestOpen(t, hsm.Path)

			token1, err := mod.GetToken(SelectLabel(label1))
			require.NoError(t, err, "should find token by label")
			require.Equal(t, label1, token1.Info.Label, "label in token info should match search label")

			token2, err := mod.GetToken(SelectLabel(label2))
			require.NoError(t, err, "should find token by label")
			require.Equal(t, label2, token2.Info.Label, "label in token info should match search label")

			token3, err := mod.GetToken(SelectID(token1.ID))
			require.NoError(t, err, "should find token by ID")
			require.Equal(t, token1.ID, token3.ID, "slot ID should match search ID")
			require.Equal(t, label1, token3.Info.Label, "label in token info should match known label")

			token4, err := mod.GetToken(SelectID(token2.ID), SelectLabel(label2))
			require.NoError(t, err, "should find token")
			require.Equal(t, token1.ID, token3.ID, "slot ID should match search ID")
			require.Equal(t, label2, token4.Info.Label, "label in token info should match search label")

			token5, err := mod.GetToken(SelectLabel("foobar"))
			require.Nil(t, token5, "should not find bogus token")
			require.Error(t, err, "should error when token is not found")
		})
	})
}
