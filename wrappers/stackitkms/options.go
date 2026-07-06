// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package stackitkms

import (
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// getOpts iterates the inbound Options and returns a struct.
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
	// (for over the plugin barrier or embedding) or via local option
	// functions (for embedding). First pull from the option.
	if opts.WithConfigMap != nil {
		for k, v := range opts.WithConfigMap {
			switch k {
			case "key_id": // backend-specific value, set global
				opts.WithKeyId = v
			case "project_id":
				opts.withProjectId = v
			case "region":
				opts.withRegion = v
			case "key_ring_id":
				opts.withKeyRingId = v
			case "key_version":
				opts.withKeyVersion = v
			case "endpoint":
				opts.withEndpoint = v
			case "service_account_key":
				opts.withServiceAccountKey = v
			case "service_account_key_path":
				opts.withServiceAccountKeyPath = v
			case "private_key":
				opts.withPrivateKey = v
			case "private_key_path":
				opts.withPrivateKeyPath = v
			case "token":
				opts.withToken = v
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

	return &opts, nil
}

// OptionFunc holds a function with local options.
type OptionFunc func(*options) error

// options = how options are represented.
type options struct {
	*wrapping.Options

	withProjectId  string
	withRegion     string
	withKeyRingId  string
	withKeyVersion string
	withEndpoint   string

	withServiceAccountKey     string
	withServiceAccountKeyPath string
	withPrivateKey            string
	withPrivateKeyPath        string
	withToken                 string
}

func getDefaultOptions() options {
	return options{}
}
