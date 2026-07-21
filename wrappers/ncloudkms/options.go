// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package ncloudkms

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

	// Wrapper-specific fields are provided via the WithConfigMap option (e.g.
	// an OpenBao seal block or over the plugin barrier).
	if opts.WithConfigMap != nil {
		for k, v := range opts.WithConfigMap {
			switch k {
			case "key_tag": // key tag from the config map (e.g. an OpenBao seal block)
				opts.withKeyTag = v
			case "domain":
				opts.withDomain = v
			case "access_key":
				opts.withAccessKey = v
			case "secret_key":
				opts.withSecretKey = v
			}
		}
	}

	return &opts, nil
}

// options = how options are represented
type options struct {
	*wrapping.Options

	withKeyTag    string
	withDomain    string
	withAccessKey string
	withSecretKey string
}

func getDefaultOptions() options {
	return options{
		withDomain: defaultDomain,
	}
}
