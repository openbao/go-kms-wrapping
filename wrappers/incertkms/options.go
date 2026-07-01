// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package incertkms

import (
	"fmt"
	"strconv"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

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
			case "url":
				opts.withUrl = v
			case "username":
				opts.withUsername = v
			case "password":
				opts.withPassword = v
			case "key":
				opts.withKey = v
			case "vslot":
				opts.withVSlot = v
			case "key_name":
				opts.withKeyName = v
			case "tls_ca_cert":
				opts.withTlsCaCert = v
			case "tls_ca_path":
				opts.withTlsCaPath = v
			case "tls_skip_verify":
				opts.withTlsSkipVerify, err = strconv.ParseBool(v)
				if err != nil {
					return nil, fmt.Errorf("incertkms: invalid tls_skip_verify value %q: %w", v, err)
				}
			}
		}
	}

	return &opts, nil
}

type options struct {
	*wrapping.Options

	withUrl      string
	withUsername string
	withPassword string
	withKey      string
	withVSlot    string
	withKeyName  string

	withTlsCaCert     string
	withTlsCaPath     string
	withTlsSkipVerify bool
}

func getDefaultOptions() options {
	return options{
		withUrl: "https://kms-uat.incert.lu/kms",
	}
}
