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
		assert.Equal("https://kms-uat.incert.lu/kms", opts.withKmsUrl)
		assert.Empty(opts.withKmsUsername)
		assert.Empty(opts.withKmsPassword)
		assert.Empty(opts.withKmsVSlot)
		assert.Empty(opts.withKmsKey)
		assert.Empty(opts.withKmsKeyName)
	})
	t.Run("WithConfigMap", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		configMap := map[string]string{
			"kms_url":      "http://localhost:3000",
			"kms_username": "opo",
			"kms_password": "Parizer1!",
			"kms_vslot":    "a73b7303-ce75-4666-8a3d-e9fb269424fb",
			"kms_key":      "bd5d7c4b-8ed3-4390-bcee-f37446bb420f",
			"kms_key_name": "openbao-seal-key",
		}

		opts, err := getOpts(wrapping.WithConfigMap(configMap))
		require.NoError(err)
		assert.Equal("http://localhost:3000", opts.withKmsUrl)
		assert.Equal("opo", opts.withKmsUsername)
		assert.Equal("Parizer1!", opts.withKmsPassword)
		assert.Equal("a73b7303-ce75-4666-8a3d-e9fb269424fb", opts.withKmsVSlot)
		assert.Equal("bd5d7c4b-8ed3-4390-bcee-f37446bb420f", opts.withKmsKey)
		assert.Equal("openbao-seal-key", opts.withKmsKeyName)
	})
}
