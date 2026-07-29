// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package huaweicloudkms

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

	// Local options can be provided either via the WithConfigMap field
	// (for over the plugin barrier or embedding) or via local option functions
	// (for embedding). First pull from the option.
	if opts.WithConfigMap != nil {
		for k, v := range opts.WithConfigMap {
			switch k {
			case "kms_key_id": // Handle deprecated parameter
				opts.WithKeyId = v
			case "region":
				opts.withRegion = v
			case "project":
				opts.withProject = v
			case "access_key":
				opts.withAccessKey = v
			case "secret_key":
				opts.withSecretKey = v
			case "identity_endpoint":
				opts.withIdentityEndpoint = v
			}
		}
	}

	if !opts.WithDisallowEnvVars {
		if err := wrapping.ParsePaths(&opts.withSecretKey, &opts.withAccessKey); err != nil {
			return nil, err
		}
	}

	return &opts, nil
}

// options = how options are represented
type options struct {
	*wrapping.Options

	withRegion           string
	withProject          string
	withAccessKey        string
	withSecretKey        string
	withIdentityEndpoint string
}

func getDefaultOptions() options {
	return options{
		withIdentityEndpoint: "https://iam.myhwclouds.com:443/v3",
	}
}
