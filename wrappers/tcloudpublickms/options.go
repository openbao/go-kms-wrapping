// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package tcloudpublickms

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
			case "key_id":
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

	return &opts, nil
}

// options = how options are represented
type options struct {
	*wrapping.Options

	withIdentityEndpoint string
	withRegion           string
	withProject          string
	withAccessKey        string
	withSecretKey        string
}

func getDefaultOptions() options {
	return options{
		withIdentityEndpoint: "https://iam.eu-de.otc.t-systems.com:443/v3",
		withRegion:           "eu-de",
	}
}
