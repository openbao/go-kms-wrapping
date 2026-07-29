// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithKeyId", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withKeyId = ""
		assert.Equal(opts, testOpts)

		const with = "testKeyId"
		cfg := map[string]string{"key_id": with}
		opts, err = getOpts(wrapping.WithConfigMap(cfg))
		require.NoError(err)
		testOpts.withKeyId = with
		testOpts.WithConfigMap = cfg
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSlot", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withSlot = ""
		assert.Equal(opts, testOpts)

		const with = "1024"
		cfg := map[string]string{"slot": with}
		opts, err = getOpts(wrapping.WithConfigMap(cfg))
		require.NoError(err)
		testOpts.withSlot = with
		testOpts.WithConfigMap = cfg
		assert.Equal(opts, testOpts)
	})
	t.Run("WithPin", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withPin = ""
		assert.Equal(opts, testOpts)

		const with = "000000"
		cfg := map[string]string{"pin": with}
		opts, err = getOpts(wrapping.WithConfigMap(cfg))
		require.NoError(err)
		testOpts.withPin = with
		testOpts.WithConfigMap = cfg
		assert.Equal(opts, testOpts)
	})
	t.Run("WithLib", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withLib = ""
		assert.Equal(opts, testOpts)

		const with = "/usr/lib/pkcs11.so"
		cfg := map[string]string{"lib": with}
		opts, err = getOpts(wrapping.WithConfigMap(cfg))
		require.NoError(err)
		testOpts.withLib = with
		testOpts.WithConfigMap = cfg
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTokenLabel", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withTokenLabel = ""
		assert.Equal(opts, testOpts)

		const with = "labelTest"
		cfg := map[string]string{"token": with}
		opts, err = getOpts(wrapping.WithConfigMap(cfg))
		require.NoError(err)
		testOpts.WithConfigMap = cfg
		testOpts.withTokenLabel = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithMechanism", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withMechanism = ""
		assert.Equal(opts, testOpts)

		const with = "CKM_AES_GCM"
		cfg := map[string]string{"mechanism": with}
		opts, err = getOpts(wrapping.WithConfigMap(cfg))
		require.NoError(err)
		testOpts.WithConfigMap = cfg
		testOpts.withMechanism = with
		assert.Equal(opts, testOpts)
	})
}
