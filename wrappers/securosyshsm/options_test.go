// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithApprovalTimeout", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withApprovalTimeout = ""
		assert.Equal(opts, testOpts)

		const with = "600"
		opts, err = getOpts(WithApprovalTimeout(with))
		require.NoError(err)
		testOpts.withApprovalTimeout = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithKeyLabel", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withKeyLabel = ""
		assert.Equal(opts, testOpts)

		const with = "TEST"
		opts, err = getOpts(WithKeyLabel(with))
		require.NoError(err)
		testOpts.withKeyLabel = with
		assert.Equal(opts, testOpts)
	})
	// t.Run("withKeyPassword", func(t *testing.T) {
	// 	assert, require := assert.New(t), require.New(t)
	// 	// test default of 0
	// 	opts, err := getOpts()
	// 	require.NoError(err)
	// 	testOpts, err := getOpts()
	// 	require.NoError(err)
	// 	testOpts.withKeyPassword = ""
	// 	assert.Equal(opts, testOpts)

	// 	const with = "TEST"
	// 	opts, err = getOpts(WithKeyLabel(with))
	// 	require.NoError(err)
	// 	testOpts.withKeyPassword = with
	// 	assert.Equal(opts, testOpts)
	// })
	t.Run("WithAuth", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withAuth = ""
		assert.Equal(opts, testOpts)

		const with = "NONE"
		opts, err = getOpts(WithAuth(with))
		require.NoError(err)
		testOpts.withAuth = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithBearerToken", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withBearerToken = ""
		assert.Equal(opts, testOpts)

		const with = "test"
		opts, err = getOpts(WithBearerToken(with))
		require.NoError(err)
		testOpts.withBearerToken = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithCheckEvery", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withCheckEvery = ""
		assert.Equal(opts, testOpts)

		const with = "20"
		opts, err = getOpts(WithCheckEvery(with))
		require.NoError(err)
		testOpts.withCheckEvery = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTSBApiEndpoint", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withTSBApiEndpoint = ""
		assert.Equal(opts, testOpts)

		const with = "https://test.com"
		opts, err = getOpts(WithTSBApiEndpoint(with))
		require.NoError(err)
		testOpts.withTSBApiEndpoint = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithCertPath", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withCertPath = ""
		assert.Equal(opts, testOpts)

		const with = "mtls.crt"
		opts, err = getOpts(WithCertPath(with))
		require.NoError(err)
		testOpts.withCertPath = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithKeyPath", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withKeyPath = ""
		assert.Equal(opts, testOpts)

		const with = "mtls.key"
		opts, err = getOpts(WithKeyPath(with))
		require.NoError(err)
		testOpts.withKeyPath = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithKeyPath", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withKeyPath = ""
		assert.Equal(opts, testOpts)

		const with = "mtls.key"
		opts, err = getOpts(WithKeyPath(with))
		require.NoError(err)
		testOpts.withKeyPath = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithPolicy", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withPolicy = ""
		assert.Equal(opts, testOpts)

		const with = "{}"
		opts, err = getOpts(WithPolicy(with))
		require.NoError(err)
		testOpts.withPolicy = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithFullPolicy", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withFullPolicy = ""
		assert.Equal(opts, testOpts)

		const with = "{}"
		opts, err = getOpts(WithFullPolicy(with))
		require.NoError(err)
		testOpts.withFullPolicy = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithFullPolicyFile", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withFullPolicyFile = ""
		assert.Equal(opts, testOpts)

		const with = "policy.json"
		opts, err = getOpts(WithFullPolicyFile(with))
		require.NoError(err)
		testOpts.withFullPolicyFile = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithPolicyRuleUse", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withPolicyRuleUse = ""
		assert.Equal(opts, testOpts)

		const with = "{}"
		opts, err = getOpts(WithPolicyRuleUse(with))
		require.NoError(err)
		testOpts.withPolicyRuleUse = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithPolicyRuleModify", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withPolicyRuleModify = ""
		assert.Equal(opts, testOpts)

		const with = "{}"
		opts, err = getOpts(WithPolicyRuleModify(with))
		require.NoError(err)
		testOpts.withPolicyRuleModify = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithPolicyRuleBlock", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withPolicyRuleBlock = ""
		assert.Equal(opts, testOpts)

		const with = "{}"
		opts, err = getOpts(WithPolicyRuleBlock(with))
		require.NoError(err)
		testOpts.withPolicyRuleBlock = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithPolicyRuleUnBlock", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withPolicyRuleUnBlock = ""
		assert.Equal(opts, testOpts)

		const with = "{}"
		opts, err = getOpts(WithPolicyRuleUnBlock(with))
		require.NoError(err)
		testOpts.withPolicyRuleUnBlock = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithApplicationKeyPair", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withApplicationKeyPair = ""
		assert.Equal(opts, testOpts)

		const with = "{}"
		opts, err = getOpts(WithApplicationKeyPair(with))
		require.NoError(err)
		testOpts.withApplicationKeyPair = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithApiKeys", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withApiKeys = ""
		assert.Equal(opts, testOpts)

		const with = "{}"
		opts, err = getOpts(WithApiKeys(with))
		require.NoError(err)
		testOpts.withApiKeys = with
		assert.Equal(opts, testOpts)
	})

}
