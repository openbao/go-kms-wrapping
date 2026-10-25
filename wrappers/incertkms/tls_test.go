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
	"os"
	"path/filepath"
	"testing"
	"time"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

// writeCertPEM writes a DER certificate as a PEM file named name inside dir,
// creating dir as needed, and returns its path.
func writeCertPEM(t *testing.T, dir, name string, der []byte) string {
	t.Helper()

	require.NoError(t, os.MkdirAll(dir, 0o750))
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

// configure creates a wrapper and configures it against f by key id with the
// given extra (TLS) keys, returning the wrapper and the SetConfig error.
func configure(t *testing.T, f *fakeKMS, extra map[string]string) (*Wrapper, error) {
	t.Helper()

	cfg := f.config(extra)
	cfg["key"] = f.keyID.String()
	w := NewWrapper()
	_, err := w.SetConfig(t.Context(), wrapping.WithConfigMap(cfg))
	return w, err
}

// noServerConfig returns a configuration whose url points at a closed port,
// for tests that must fail before any connection is made.
func noServerConfig(extra map[string]string) map[string]string {
	cfg := map[string]string{
		"url":      "https://127.0.0.1:1",
		"username": incertkmsTestUsername,
		"password": incertkmsTestPassword,
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

func TestIncertKmsWrapper_TLS_DefaultVerifies(t *testing.T) {
	require := require.New(t)
	f := newFakeKMSTLS(t, nil)

	_, err := configure(t, f, nil)
	require.ErrorContains(err, "failed to verify certificate")
}

func TestIncertKmsWrapper_TLS_CACert(t *testing.T) {
	require := require.New(t)
	f := newFakeKMSTLS(t, nil)

	w, err := configure(t, f, map[string]string{"tls_ca_cert": f.caFile(t)})
	require.NoError(err)
	testEncryptionRoundTrip(t, w)
}

func TestIncertKmsWrapper_TLS_CAPath(t *testing.T) {
	require := require.New(t)
	f := newFakeKMSTLS(t, nil)
	dir := t.TempDir()
	writeCertPEM(t, filepath.Join(dir, "sub", "nested"), "kms-ca.pem", f.srv.Certificate().Raw)
	require.NoError(os.WriteFile(filepath.Join(dir, "README"), []byte("not a certificate"), 0o600))

	w, err := configure(t, f, map[string]string{"tls_ca_path": dir})
	require.NoError(err)
	testEncryptionRoundTrip(t, w)
}

func TestIncertKmsWrapper_TLS_SkipVerify(t *testing.T) {
	require := require.New(t)
	f := newFakeKMSTLS(t, nil)

	w, err := configure(t, f, map[string]string{"tls_skip_verify": "true"})
	require.NoError(err)
	testEncryptionRoundTrip(t, w)
}

func TestIncertKmsWrapper_TLS_ClientCert(t *testing.T) {
	require := require.New(t)
	certPath, keyPath, clientCert := writeClientCert(t, t.TempDir())
	pool := x509.NewCertPool()
	pool.AddCert(clientCert)
	f := newFakeKMSTLS(t, &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool})
	caFile := f.caFile(t)

	// Without a client certificate the server must refuse us, otherwise the
	// positive case below proves nothing.
	_, err := configure(t, f, map[string]string{"tls_ca_cert": caFile})
	require.ErrorContains(err, "getting config")

	w, err := configure(t, f, map[string]string{
		"tls_ca_cert":     caFile,
		"tls_client_cert": certPath,
		"tls_client_key":  keyPath,
	})
	require.NoError(err)
	testEncryptionRoundTrip(t, w)
}

func TestIncertKmsWrapper_TLS_ServerName(t *testing.T) {
	f := newFakeKMSTLS(t, nil)
	caFile := f.caFile(t)

	t.Run("name in certificate", func(t *testing.T) {
		w, err := configure(t, f, map[string]string{"tls_ca_cert": caFile, "tls_server_name": "example.com"})
		require.NoError(t, err)
		testEncryptionRoundTrip(t, w)
	})
	t.Run("name not in certificate", func(t *testing.T) {
		_, err := configure(t, f, map[string]string{"tls_ca_cert": caFile, "tls_server_name": "kms.invalid"})
		require.ErrorContains(t, err, "failed to verify certificate")
		require.ErrorContains(t, err, "kms.invalid")
	})
}

func TestIncertKmsWrapper_TLS_ClientCertNeedsBoth(t *testing.T) {
	cases := []struct{ name, key string }{
		{"cert only", "tls_client_cert"},
		{"key only", "tls_client_key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := NewWrapper()
			_, err := w.SetConfig(t.Context(), wrapping.WithConfigMap(noServerConfig(map[string]string{
				tc.key: "/etc/incert/client.pem",
			})))
			require.EqualError(t, err, "incertkms: tls_client_cert and tls_client_key must be set together")
		})
	}
}

func TestIncertKmsWrapper_TLS_BadMaterial(t *testing.T) {
	dir := t.TempDir()
	bogus := filepath.Join(dir, "bogus.pem")
	require.NoError(t, os.WriteFile(bogus, []byte("not a certificate"), 0o600))
	noCerts := filepath.Join(dir, "no-certs")
	require.NoError(t, os.MkdirAll(noCerts, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(noCerts, "README"), []byte("not a certificate"), 0o600))

	cases := []struct {
		name    string
		config  map[string]string
		wantErr string
	}{
		{"missing ca file", map[string]string{"tls_ca_cert": filepath.Join(dir, "missing.pem")}, "reading ca certificate file"},
		{"ca file without certificates", map[string]string{"tls_ca_cert": bogus}, "no certificates found in ca certificate file"},
		{"missing ca path", map[string]string{"tls_ca_path": filepath.Join(dir, "missing")}, "reading ca certificate directory"},
		{"ca path without certificates", map[string]string{"tls_ca_path": noCerts}, "no certificates found in ca certificate directory"},
		{"unparsable client cert", map[string]string{"tls_client_cert": bogus, "tls_client_key": bogus}, "loading client certificate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := NewWrapper()
			_, err := w.SetConfig(t.Context(), wrapping.WithConfigMap(noServerConfig(tc.config)))
			require.ErrorContains(t, err, "unexpected error: tls configuration: ")
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}
