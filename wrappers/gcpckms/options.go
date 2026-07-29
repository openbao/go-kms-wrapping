// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpckms

import (
	"strconv"

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
			case "key_not_required":
				keyNotRequired, err := strconv.ParseBool(v)
				if err != nil {
					return nil, err
				}
				opts.withKeyNotRequired = keyNotRequired
			case "user_agent":
				opts.withUserAgent = v
			case "credentials":
				opts.withCredentialsPath = v
			case "credentials_json":
				opts.withCredentialsJSON = v
			case "credentials_type":
				opts.withCredentialsType = v
			case "credentials_scopes":
				opts.withCredentialsScopes = v
			case "project":
				opts.withProject = v
			case "region":
				opts.withRegion = v
			case "key_ring":
				opts.withKeyRing = v
			case "crypto_key":
				opts.withCryptoKey = v
			}
		}
	}

	if !opts.WithDisallowEnvVars {
		if err := wrapping.ParsePaths(&opts.withCredentialsPath); err != nil {
			return nil, err
		}
	}

	return &opts, nil
}

// options = how options are represented
type options struct {
	*wrapping.Options

	withCredentialsPath string

	withCredentialsJSON   string
	withCredentialsType   string
	withCredentialsScopes string

	withProject   string
	withRegion    string
	withKeyRing   string
	withCryptoKey string

	withUserAgent      string
	withKeyNotRequired bool
}

func getDefaultOptions() options {
	return options{}
}
