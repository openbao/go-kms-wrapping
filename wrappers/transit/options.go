// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"strconv"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

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
			case "mount_path":
				opts.withMountPath = v
			case "key_name":
				opts.withKeyName = v
			case "disable_renewal":
				opts.withDisableRenewal = v
			case "namespace":
				opts.withNamespace = v
			case "address":
				opts.withAddress = v
			case "tls_ca_cert":
				opts.withTlsCaCert = v
			case "tls_ca_path":
				opts.withTlsCaCertDir = v
			case "tls_client_cert":
				opts.withTlsClientCert = v
			case "tls_client_key":
				opts.withTlsClientKey = v
			case "tls_ca_cert_bytes":
				opts.withTlsCaCertBytes = v
			case "tls_client_cert_bytes":
				opts.withTlsClientCertBytes = v
			case "tls_client_key_bytes":
				opts.withTlsClientKeyBytes = v
			case "tls_server_name":
				opts.withTlsServerName = v
			case "tls_skip_verify":
				var err error
				opts.withTlsSkipVerify, err = strconv.ParseBool(v)
				if err != nil {
					return nil, err
				}
			case "key_id_prefix":
				opts.withKeyIdPrefix = v
			case "token":
				opts.withToken = v
			}
		}
	}

	if !opts.WithDisallowEnvVars {
		if err := wrapping.ParsePaths(&opts.withToken, &opts.withTlsClientKey); err != nil {
			return nil, err
		}
	}

	return &opts, nil
}

// options = how options are represented
type options struct {
	*wrapping.Options

	withMountPath          string
	withKeyName            string
	withDisableRenewal     string
	withNamespace          string
	withAddress            string
	withTlsCaCert          string
	withTlsCaCertDir       string
	withTlsClientCert      string
	withTlsClientKey       string
	withTlsCaCertBytes     string
	withTlsClientCertBytes string
	withTlsClientKeyBytes  string
	withTlsServerName      string
	withTlsSkipVerify      bool
	withToken              string
	withKeyIdPrefix        string
}

func getDefaultOptions() options {
	return options{}
}
