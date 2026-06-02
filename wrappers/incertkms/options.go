// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package incertkms

import wrapping "github.com/openbao/go-kms-wrapping/v2"

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...wrapping.Option) (*options, error) {
	opts := getDefaultOptions()

	// Parse the global options
	wrappingOpts, err := wrapping.GetOpts(opt...)
	if err != nil {
		return nil, err
	}

	// Don't ever return blank options
	if wrappingOpts == nil {
		wrappingOpts = new(wrapping.Options)
	}
	opts.Options = wrappingOpts

	// Configuration is provided via the WithConfigMap field, either over the
	// plugin barrier or when embedding.
	if opts.WithConfigMap != nil {
		for k, v := range opts.WithConfigMap {
			switch k {
			case "kms_url":
				opts.withKmsUrl = v
			case "kms_username":
				opts.withKmsUsername = v
			case "kms_password":
				opts.withKmsPassword = v
			case "kms_key":
				opts.withKmsKey = v
			case "kms_vslot":
				opts.withKmsVSlot = v
			case "kms_key_name":
				opts.withKmsKeyName = v
			}
		}
	}

	return &opts, nil
}

type options struct {
	*wrapping.Options

	withKmsUrl      string
	withKmsUsername string
	withKmsPassword string
	withKmsKey      string
	withKmsVSlot    string
	withKmsKeyName  string
}

func getDefaultOptions() options {
	return options{
		withKmsUrl: "https://kms-uat.incert.lu/kms",
	}
}
