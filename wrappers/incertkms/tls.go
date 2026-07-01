// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package incertkms

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const httpClientTimeout = 10 * time.Second

func (o *options) tlsConfigured() bool {
	return o.withTlsCaCert != "" ||
		o.withTlsCaPath != "" ||
		o.withTlsSkipVerify
}

func (o *options) buildHTTPClient() (*http.Client, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: o.withTlsSkipVerify, //nolint:gosec
	}

	if o.withTlsCaCert != "" || o.withTlsCaPath != "" {
		pool := x509.NewCertPool()
		if err := appendCAFile(pool, o.withTlsCaCert); err != nil {
			return nil, err
		}
		if err := appendCAPath(pool, o.withTlsCaPath); err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = pool
	}

	return &http.Client{
		Timeout:   httpClientTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}, nil
}

func appendCAFile(pool *x509.CertPool, path string) error {
	if path == "" {
		return nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("incertkms: reading tls_ca_cert %q: %w", path, err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("incertkms: no valid certificates found in tls_ca_cert %q", path)
	}
	return nil
}

func appendCAPath(pool *x509.CertPool, dir string) error {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("incertkms: reading tls_ca_path %q: %w", dir, err)
	}
	var added bool
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		pem, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return fmt.Errorf("incertkms: reading CA file in tls_ca_path: %w", err)
		}
		if pool.AppendCertsFromPEM(pem) {
			added = true
		}
	}
	if !added {
		return fmt.Errorf("incertkms: no valid certificates found in tls_ca_path %q", dir)
	}
	return nil
}
