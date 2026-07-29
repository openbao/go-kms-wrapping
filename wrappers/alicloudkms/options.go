// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package alicloudkms

import (
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

	for k, v := range opts.WithConfigMap {
		switch k {
		case "kms_key_id": // deprecated backend-specific value, set global
			opts.WithKeyId = v
		case "region":
			opts.withRegion = v
		case "domain":
			opts.withDomain = v
		case "access_key":
			opts.withAccessKey = v
		case "secret_key":
			opts.withSecretKey = v
		case "access_secret":
			opts.withAccessSecret = v
		}
	}

	if !opts.WithDisallowEnvVars {
		if err := wrapping.ParsePaths(&opts.withAccessSecret, &opts.withSecretKey, &opts.withAccessKey); err != nil {
			return nil, err
		}
	}

	return &opts, nil
}

// options = how options are represented
type options struct {
	*wrapping.Options

	withRegion       string
	withDomain       string
	withAccessKey    string
	withSecretKey    string
	withAccessSecret string
}

func getDefaultOptions() options {
	return options{
		withRegion: "cn-beijing",
	}
}
