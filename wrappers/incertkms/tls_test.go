// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package incertkms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

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

	return srv, writeCertPEM(t, dir, name, srv.Certificate().Raw)
}

// writeCertPEM writes a DER certificate as a PEM file named name inside dir
// and returns its path.
func writeCertPEM(t *testing.T, dir, name string, der []byte) string {
	t.Helper()

	path := filepath.Join(dir, name)
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(block), 0o600))
	return path
}

// writeClientCert generates a self-signed client certificate, writes it and
// its private key as PEM files inside dir, and returns both paths plus the
// parsed certificate so a server can be told to trust it.
func writeClientCert(t *testing.T, dir string) (certPath, keyPath string, cert *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "openbao-seal-client"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err = x509.ParseCertificate(der)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPath = filepath.Join(dir, "client-key.pem")
	keyBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(keyBlock), 0o600))

	return writeCertPEM(t, dir, "client.pem", der), keyPath, cert
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

func TestBuildHTTPClient_ClientCert(t *testing.T) {
	require := require.New(t)
	dir := t.TempDir()
	clientCert, clientKey, parsed := writeClientCert(t, dir)

	// A server that demands a client certificate it trusts.
	clientPool := x509.NewCertPool()
	clientPool.AddCert(parsed)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientPool,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	caFile := writeCertPEM(t, dir, "server-ca.pem", srv.Certificate().Raw)

	// Without a client certificate the server must refuse us, otherwise the
	// positive case below proves nothing.
	o := &options{withTlsCaCert: caFile}
	hc, err := o.buildHTTPClient()
	require.NoError(err)
	_, err = hc.Get(srv.URL)
	require.Error(err, "server should reject a client without a certificate")

	o = &options{withTlsCaCert: caFile, withTlsClientCert: clientCert, withTlsClientKey: clientKey}
	require.True(o.tlsConfigured())
	hc, err = o.buildHTTPClient()
	require.NoError(err)
	resp, err := hc.Get(srv.URL)
	require.NoError(err, "client certificate should satisfy the server")
	defer resp.Body.Close()
	require.Equal(http.StatusOK, resp.StatusCode)
}

func TestBuildHTTPClient_ClientCertNeedsBoth(t *testing.T) {
	require := require.New(t)

	for _, o := range []*options{
		{withTlsClientCert: "/etc/incert/client.pem"},
		{withTlsClientKey: "/etc/incert/client-key.pem"},
	} {
		_, err := o.buildHTTPClient()
		require.Error(err)
		require.Contains(err.Error(), "must be set together")
	}
}

func TestBuildHTTPClient_BadClientCert(t *testing.T) {
	require := require.New(t)
	bogus := filepath.Join(t.TempDir(), "client.pem")
	require.NoError(os.WriteFile(bogus, []byte("not a certificate"), 0o600))

	o := &options{withTlsClientCert: bogus, withTlsClientKey: bogus}
	_, err := o.buildHTTPClient()
	require.Error(err)
	require.Contains(err.Error(), "tls_client_cert")
}

func TestBuildHTTPClient_ServerName(t *testing.T) {
	require := require.New(t)
	// The httptest certificate is issued for example.com and the loopback
	// addresses, while srv.URL addresses the server by IP.
	srv, caFile := newTLSFake(t, t.TempDir(), "ca.pem")

	o := &options{withTlsCaCert: caFile, withTlsServerName: "example.com"}
	require.True(o.tlsConfigured())
	hc, err := o.buildHTTPClient()
	require.NoError(err)
	resp, err := hc.Get(srv.URL)
	require.NoError(err, "certificate should verify for the configured server name")
	resp.Body.Close()

	o = &options{withTlsCaCert: caFile, withTlsServerName: "kms.invalid"}
	hc, err = o.buildHTTPClient()
	require.NoError(err)
	_, err = hc.Get(srv.URL)
	require.Error(err, "certificate must not verify for a name it was not issued for")
}
