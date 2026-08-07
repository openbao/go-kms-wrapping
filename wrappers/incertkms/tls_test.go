// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package incertkms

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildHTTPClient_SkipVerify(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	o := &options{withTlsSkipVerify: true}
	require.True(o.tlsConfigured())

	hc, err := o.buildHTTPClient()
	require.NoError(err)
	require.NotNil(hc)

	tr, ok := hc.Transport.(*http.Transport)
	require.True(ok)
	require.NotNil(tr.TLSClientConfig)
	assert.True(tr.TLSClientConfig.InsecureSkipVerify)
	assert.Equal(httpClientTimeout, hc.Timeout)
}

func TestBuildHTTPClient_BadCaFile(t *testing.T) {
	require := require.New(t)

	o := &options{withTlsCaCert: "/no/such/ca.pem"}
	_, err := o.buildHTTPClient()
	require.Error(err)
	require.Contains(err.Error(), "tls_ca_cert")
}

func TestBuildHTTPClient_CaFileNoCerts(t *testing.T) {
	require := require.New(t)

	// A readable file that contains no PEM certificates is a misconfiguration.
	bogus := filepath.Join(t.TempDir(), "empty.pem")
	require.NoError(os.WriteFile(bogus, []byte("not a certificate"), 0o600))

	o := &options{withTlsCaCert: bogus}
	_, err := o.buildHTTPClient()
	require.Error(err)
	require.Contains(err.Error(), "no valid certificates")
}
