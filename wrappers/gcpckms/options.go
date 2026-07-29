// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpckms

import (
	"strconv"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...wrapping.Option) (*options, error) {
	// First, separate out options into local and global
	opts := getDefaultOptions()
	var wrappingOptions []wrapping.Option
	var localOptions []OptionFunc
	for _, o := range opt {
		if o == nil {
			continue
		}
		iface := o()
		switch to := iface.(type) {
		case wrapping.OptionFunc:
			wrappingOptions = append(wrappingOptions, o)
		case OptionFunc:
			localOptions = append(localOptions, to)
		}
	}

	// Parse the global options
	var err error
	opts.Options, err = wrapping.GetOpts(wrappingOptions...)
	if err != nil {
		return nil, err
	}

	// Don't ever return blank options
	if opts.Options == nil {
		opts.Options = new(wrapping.Options)
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

	// Now run the local options functions. This may overwrite options set by
	// the options above.
	for _, o := range localOptions {
		if o != nil {
			if err := o(&opts); err != nil {
				return nil, err
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

// OptionFunc holds a function with local options
type OptionFunc func(*options) error

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
