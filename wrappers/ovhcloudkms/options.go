// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package ovhcloudkms

import (
	"github.com/google/uuid"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

func getDefaultOptions() options {
	return options{}
}

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...wrapping.Option) (*options, error) {
	opts := getDefaultOptions()

	var err error
	opts.Options, err = wrapping.GetOpts(opt...)
	if err != nil {
		return nil, err
	}

	for k, v := range opts.WithConfigMap {
		switch k {
		case "key_id": // deprecated backend-specific value, set global
			opts.WithKeyId = v
		case "endpoint":
			opts.withEndpoint = v
		case "kms_id":
			opts.withKmsId, err = uuid.Parse(v)
			if err != nil {
				return nil, err
			}
		case "client_cert":
			opts.withClientCert = v
		case "client_key":
			opts.withClientKey = v
		case "ca_cert":
			opts.withCACert = v
		case "client_cert_bytes":
			opts.withClientCertBytes = v
		case "client_key_bytes":
			opts.withClientKeyBytes = v
		case "ca_cert_bytes":
			opts.withCACertBytes = v
		case "token":
			opts.withToken = v
		}
	}

	return &opts, nil
}

// options = how options are represented
type options struct {
	*wrapping.Options

	withEndpoint string
	withKmsId    uuid.UUID

	// file-based mTLS configuration
	withClientCert string
	withClientKey  string
	withCACert     string

	// in-mem mTLS configuration
	withClientCertBytes string
	withClientKeyBytes  string
	withCACertBytes     string

	withToken string
}
