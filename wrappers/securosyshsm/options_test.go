// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

func TestGetOptsDefaults(t *testing.T) {
	t.Parallel()

	opts, err := getOpts()
	require.NoError(t, err)
	require.NotNil(t, opts.Options)
	require.Empty(t, opts.withApprovalTimeout)
	require.Empty(t, opts.withKeyLabel)
	require.Empty(t, opts.withKeyPassword)
	require.Empty(t, opts.withAuth)
	require.Empty(t, opts.withBearerToken)
	require.Empty(t, opts.withCheckEvery)
	require.Empty(t, opts.withTSBApiEndpoint)
	require.Empty(t, opts.withCertPEM)
	require.Empty(t, opts.withKeyPEM)
	require.Empty(t, opts.withApplicationKeyPair)
	require.Empty(t, opts.withApiKeys)
}

func TestGetOptsFromConfigMap(t *testing.T) {
	t.Parallel()

	config := map[string]string{
		"approval_timeout":     "600",
		"key_label":            "TEST",
		"key_password":         "secret",
		"auth":                 "NONE",
		"bearer_token":         "token",
		"check_every":          "20",
		"tsb_api_endpoint":     "https://test.com",
		"cert_pem":             "certificate PEM",
		"key_pem":              "key PEM",
		"application_key_pair": "{}",
		"api_keys":             "{}",
	}

	opts, err := getOpts(wrapping.WithConfigMap(config))
	require.NoError(t, err)
	require.Equal(t, config, opts.WithConfigMap)
	require.Equal(t, "600", opts.withApprovalTimeout)
	require.Equal(t, "TEST", opts.withKeyLabel)
	require.Equal(t, "secret", opts.withKeyPassword)
	require.Equal(t, "NONE", opts.withAuth)
	require.Equal(t, "token", opts.withBearerToken)
	require.Equal(t, "20", opts.withCheckEvery)
	require.Equal(t, "https://test.com", opts.withTSBApiEndpoint)
	require.Equal(t, "certificate PEM", opts.withCertPEM)
	require.Equal(t, "key PEM", opts.withKeyPEM)
	require.Equal(t, "{}", opts.withApplicationKeyPair)
	require.Equal(t, "{}", opts.withApiKeys)
}
