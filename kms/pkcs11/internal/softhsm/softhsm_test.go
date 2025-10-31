// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package softhsm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test(t *testing.T) {
	t.Run("New", func(t *testing.T) {
		New(t)
	})

	t.Run("InitToken", func(t *testing.T) {
		hsm := New(t)

		label1, pin1 := hsm.InitToken()
		label2, pin2 := hsm.InitToken()

		require.NotEqual(t, pin1, pin2)
		require.NotEqual(t, label1, label2)
	})
}
