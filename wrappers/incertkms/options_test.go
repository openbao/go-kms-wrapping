// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package incertkms

import (
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("default", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := getOpts()
		require.NoError(err)
		// default is the public UAT endpoint
		assert.Equal("https://kms-uat.incert.lu/kms", opts.withUrl)
		assert.Empty(opts.withUsername)
		assert.Empty(opts.withPassword)
		assert.Empty(opts.withVSlot)
		assert.Empty(opts.withKey)
		assert.Empty(opts.withKeyName)
		// TLS verification is on by default; no TLS material configured.
		assert.False(opts.withTlsSkipVerify)
		assert.False(opts.tlsConfigured())
	})
	t.Run("WithConfigMap", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		configMap := map[string]string{
			"url":             "http://localhost:3000",
			"username":        "opo",
			"password":        "Parizer1!",
			"vslot":           "a73b7303-ce75-4666-8a3d-e9fb269424fb",
			"key":             "bd5d7c4b-8ed3-4390-bcee-f37446bb420f",
			"key_name":        "openbao-seal-key",
			"tls_ca_cert":     "/etc/incert/ca.pem",
			"tls_ca_path":     "/etc/incert/ca.d",
			"tls_skip_verify": "true",
		}

		opts, err := getOpts(wrapping.WithConfigMap(configMap))
		require.NoError(err)
		assert.Equal("http://localhost:3000", opts.withUrl)
		assert.Equal("opo", opts.withUsername)
		assert.Equal("Parizer1!", opts.withPassword)
		assert.Equal("a73b7303-ce75-4666-8a3d-e9fb269424fb", opts.withVSlot)
		assert.Equal("bd5d7c4b-8ed3-4390-bcee-f37446bb420f", opts.withKey)
		assert.Equal("openbao-seal-key", opts.withKeyName)
		assert.Equal("/etc/incert/ca.pem", opts.withTlsCaCert)
		assert.Equal("/etc/incert/ca.d", opts.withTlsCaPath)
		assert.True(opts.withTlsSkipVerify)
		assert.True(opts.tlsConfigured())
	})
	t.Run("tls_skip_verify invalid", func(t *testing.T) {
		require := require.New(t)
		_, err := getOpts(wrapping.WithConfigMap(map[string]string{
			"tls_skip_verify": "notabool",
		}))
		require.Error(err)
	})
}
