// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tencentcloudkms

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
		case "kms_key_id": // Handle deprecated KMS-specific value
			opts.WithKeyId = v
		case "region":
			opts.withRegion = v
		case "access_key":
			opts.withAccessKey = v
		case "secret_key":
			opts.withSecretKey = v
		case "session_token":
			opts.withSessionToken = v
		}
	}

	if !opts.WithDisallowEnvVars {
		if err := wrapping.ParsePaths(&opts.withSecretKey, &opts.withAccessKey, &opts.withSessionToken); err != nil {
			return nil, err
		}
	}

	return &opts, nil
}

// options = how options are represented
type options struct {
	*wrapping.Options

	withRegion       string
	withAccessKey    string
	withSecretKey    string
	withSessionToken string
}

func getDefaultOptions() options {
	return options{
		withRegion: "ap-guangzhou",
	}
}
