// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package scalewaykms

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
		case "key_id": // deprecated backend-specific value, set global
			opts.WithKeyId = v
		case "region":
			opts.withRegion = v
		case "project_id":
			opts.withProjectID = v
		case "access_key":
			opts.withAccessKey = v
		case "secret_key":
			opts.withSecretKey = v
		case "api_url":
			opts.withAPIURL = v
		}
	}

	if !opts.WithDisallowEnvVars {
		if err := wrapping.ParsePaths(&opts.withAccessKey, &opts.withSecretKey); err != nil {
			return nil, err
		}
	}

	return &opts, nil
}

type options struct {
	*wrapping.Options

	withRegion    string
	withProjectID string
	withAccessKey string
	withSecretKey string
	withAPIURL    string
}
