// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package incertkms

import (
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
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

// newTLSFake starts a TLS server with a self-signed certificate and writes
// that certificate as a PEM file named name inside dir.
func newTLSFake(t *testing.T, dir, name string) (*httptest.Server, string) {
	t.Helper()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)

	path := filepath.Join(dir, name)
	block := &pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(block), 0o600))

	return srv, path
}

func TestBuildHTTPClient_CaFile(t *testing.T) {
	require := require.New(t)
	srv, caFile := newTLSFake(t, t.TempDir(), "ca.pem")

	o := &options{withTlsCaCert: caFile}
	require.True(o.tlsConfigured())

	hc, err := o.buildHTTPClient()
	require.NoError(err)
	require.False(hc.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify)

	resp, err := hc.Get(srv.URL)
	require.NoError(err, "server certificate should verify against tls_ca_cert")
	defer resp.Body.Close()
	require.Equal(http.StatusOK, resp.StatusCode)
}

func TestBuildHTTPClient_CaPath(t *testing.T) {
	require := require.New(t)
	dir := t.TempDir()
	srv, _ := newTLSFake(t, dir, "kms-ca.pem")
	// Non-certificate files in the directory are skipped, not fatal.
	require.NoError(os.WriteFile(filepath.Join(dir, "README"), []byte("not a certificate"), 0o600))

	o := &options{withTlsCaPath: dir}
	hc, err := o.buildHTTPClient()
	require.NoError(err)

	resp, err := hc.Get(srv.URL)
	require.NoError(err, "server certificate should verify against tls_ca_path")
	defer resp.Body.Close()
	require.Equal(http.StatusOK, resp.StatusCode)
}

func TestBuildHTTPClient_CaPathNoCerts(t *testing.T) {
	require := require.New(t)
	dir := t.TempDir()
	require.NoError(os.WriteFile(filepath.Join(dir, "README"), []byte("not a certificate"), 0o600))

	o := &options{withTlsCaPath: dir}
	_, err := o.buildHTTPClient()
	require.Error(err)
	require.Contains(err.Error(), "no valid certificates")
}

func TestBuildHTTPClient_KeepsTransportDefaults(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	o := &options{withTlsSkipVerify: true}
	hc, err := o.buildHTTPClient()
	require.NoError(err)

	tr, ok := hc.Transport.(*http.Transport)
	require.True(ok)
	def := http.DefaultTransport.(*http.Transport)

	assert.NotNil(tr.Proxy, "proxy-from-environment should be inherited")
	assert.Equal(def.TLSHandshakeTimeout, tr.TLSHandshakeTimeout)
	assert.Equal(def.MaxIdleConns, tr.MaxIdleConns)
	assert.Equal(def.ForceAttemptHTTP2, tr.ForceAttemptHTTP2)
	assert.Equal(uint16(tls.VersionTLS12), tr.TLSClientConfig.MinVersion)
}
