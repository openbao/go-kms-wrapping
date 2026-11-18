// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package exoscalekms

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
		case "key_id":
			opts.WithKeyId = v
		case "zone":
			opts.withZone = v
		case "endpoint":
			opts.withEndpoint = v
		case "api_key":
			opts.withApiKey = v
		case "api_secret":
			opts.withApiSecret = v
		}
	}

	if !opts.WithDisallowEnvVars {
		if err := wrapping.ParsePaths(&opts.withApiKey, &opts.withApiSecret); err != nil {
			return nil, err
		}
	}

	return &opts, nil
}

// options = how options are represented
type options struct {
	*wrapping.Options

	withZone      string
	withEndpoint  string
	withApiKey    string
	withApiSecret string
}
