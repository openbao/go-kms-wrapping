// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"strconv"
	"strings"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

func getDefaultOptions() options {
	return options{
		withTimeout:      10,
		withCryptoParams: "AES_GCM",
	}
}

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...wrapping.Option) (*options, error) {
	opts := getDefaultOptions()

	var err error
	opts.Options, err = wrapping.GetOpts(opt...)
	if err != nil {
		return nil, err
	}

	// Local options can be provided either via the WithConfigMap field
	// (for over the plugin barrier or embedding) or via local option functions
	// (for embedding). First pull from the option.
	if opts.WithConfigMap != nil {
		for k, v := range opts.WithConfigMap {
			switch k {
			case "kms_key_id": // deprecated backend-specific value, set global
				opts.WithKeyId = v
			case "endpoint":
				opts.withEndpoint = v
			case "ca_cert":
				opts.withCaCertFile = v
			case "client_cert":
				opts.withClientCertFile = v
			case "client_key":
				opts.withClientKeyFile = v
			case "ca_cert_bytes":
				opts.withCaCertBytes = v
			case "client_cert_bytes":
				opts.withClientCertBytes = v
			case "client_key_bytes":
				opts.withClientKeyBytes = v
			case "server_name":
				opts.withServerName = v
			case "timeout":
				var err error
				var timeout uint64
				timeout, err = strconv.ParseUint(v, 10, 64)
				if err != nil {
					return nil, err
				}
				opts.withTimeout = timeout
			case "encrypt_alg":
				opts.withCryptoParams = v
			case "tls12_ciphers":
				for cipher := range strings.SplitSeq(v, ",") {
					cipher = strings.TrimSpace(cipher)
					opts.withTls12Ciphers = append(opts.withTls12Ciphers, cipher)
				}
			}
		}
	}

	return &opts, nil
}

// options = how options are represented
type options struct {
	*wrapping.Options

	// mTLS setup file paths
	withCaCertFile     string
	withClientCertFile string
	withClientKeyFile  string
	// mTLS setup inmem
	withCaCertBytes     string
	withClientCertBytes string
	withClientKeyBytes  string

	withEndpoint     string
	withServerName   string
	withTimeout      uint64
	withCryptoParams string
	withTls12Ciphers []string
}
