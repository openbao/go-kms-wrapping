// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package stackitkms

import (
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
		case "key_id": // backend-specific value, set global
			opts.WithKeyId = v
		case "project_id":
			opts.withProjectId = v
		case "region":
			opts.withRegion = v
		case "key_ring_id":
			opts.withKeyRingId = v
		case "key_version":
			opts.withKeyVersion = v
		case "endpoint":
			opts.withEndpoint = v
		case "service_account_key":
			opts.withServiceAccountKey = v
		case "service_account_key_path":
			opts.withServiceAccountKeyPath = v
		case "private_key":
			opts.withPrivateKey = v
		case "private_key_path":
			opts.withPrivateKeyPath = v
		case "token":
			opts.withToken = v
		}
	}

	return &opts, nil
}

// options = how options are represented
type options struct {
	*wrapping.Options

	withProjectId  string
	withRegion     string
	withKeyRingId  string
	withKeyVersion string
	withEndpoint   string

	withServiceAccountKey     string
	withServiceAccountKeyPath string
	withPrivateKey            string
	withPrivateKeyPath        string
	withToken                 string
}
