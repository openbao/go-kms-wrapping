// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithMountPath", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withMountPath = ""
		assert.Equal(opts, testOpts)

		const with = "/test/path"
		cfg := map[string]string{"mount_path": with}
		opts, err = getOpts(wrapping.WithConfigMap(cfg))
		require.NoError(err)
		testOpts.WithConfigMap = cfg
		testOpts.withMountPath = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithKeyName", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withKeyName = ""
		assert.Equal(opts, testOpts)

		const with = "testKey"
		cfg := map[string]string{"key_name": with}
		opts, err = getOpts(wrapping.WithConfigMap(cfg))
		require.NoError(err)
		testOpts.WithConfigMap = cfg
		testOpts.withKeyName = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDisableRenewal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withDisableRenewal = ""
		assert.Equal(opts, testOpts)

		const with = "test"
		cfg := map[string]string{"disable_renewal": with}
		opts, err = getOpts(wrapping.WithConfigMap(cfg))
		require.NoError(err)
		testOpts.WithConfigMap = cfg
		testOpts.withDisableRenewal = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithNamespace", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withNamespace = ""
		assert.Equal(opts, testOpts)

		const with = "test"
		cfg := map[string]string{"namespace": with}
		opts, err = getOpts(wrapping.WithConfigMap(cfg))
		require.NoError(err)
		testOpts.WithConfigMap = cfg
		testOpts.withNamespace = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithAddress", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withAddress = ""
		assert.Equal(opts, testOpts)

		const with = "test"
		cfg := map[string]string{"address": with}
		opts, err = getOpts(wrapping.WithConfigMap(cfg))
		require.NoError(err)
		testOpts.WithConfigMap = cfg
		testOpts.withAddress = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTlsCaCert", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withTlsCaCert = ""
		assert.Equal(opts, testOpts)

		const with = "test"
		cfg := map[string]string{"tls_ca_cert": with}
		opts, err = getOpts(wrapping.WithConfigMap(cfg))
		require.NoError(err)
		testOpts.WithConfigMap = cfg
		testOpts.withTlsCaCert = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTlsCaPath", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withTlsCaCertDir = ""
		assert.Equal(opts, testOpts)

		const with = "test"
		cfg := map[string]string{"tls_ca_path": with}
		opts, err = getOpts(wrapping.WithConfigMap(cfg))
		require.NoError(err)
		testOpts.WithConfigMap = cfg
		testOpts.withTlsCaCertDir = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTlsClientCert", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withTlsClientCert = ""
		assert.Equal(opts, testOpts)

		const with = "test"
		cfg := map[string]string{"tls_client_cert": with}
		opts, err = getOpts(wrapping.WithConfigMap(cfg))
		require.NoError(err)
		testOpts.WithConfigMap = cfg
		testOpts.withTlsClientCert = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTlsClientKey", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withTlsClientKey = ""
		assert.Equal(opts, testOpts)

		const with = "test"
		cfg := map[string]string{"tls_client_key": with}
		opts, err = getOpts(wrapping.WithConfigMap(cfg))
		require.NoError(err)
		testOpts.WithConfigMap = cfg
		testOpts.withTlsClientKey = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTlsServerName", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withTlsServerName = ""
		assert.Equal(opts, testOpts)

		const with = "test"
		cfg := map[string]string{"tls_server_name": with}
		opts, err = getOpts(wrapping.WithConfigMap(cfg))
		require.NoError(err)
		testOpts.WithConfigMap = cfg
		testOpts.withTlsServerName = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTlsSkipVerify", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withTlsSkipVerify = false
		assert.Equal(opts, testOpts)

		cfg := map[string]string{"tls_skip_verify": "true"}
		opts, err = getOpts(wrapping.WithConfigMap(cfg))
		require.NoError(err)
		testOpts.WithConfigMap = cfg
		testOpts.withTlsSkipVerify = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithToken", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withToken = ""
		assert.Equal(opts, testOpts)

		const with = "test"
		cfg := map[string]string{"token": with}
		opts, err = getOpts(wrapping.WithConfigMap(cfg))
		require.NoError(err)
		testOpts.WithConfigMap = cfg
		testOpts.withToken = with
		assert.Equal(opts, testOpts)
	})
}
