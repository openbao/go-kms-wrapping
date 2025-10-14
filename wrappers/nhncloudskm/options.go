// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package nhncloudskm

import (
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
			case "endpoint":
				opts.withEndpoint = v
			case "app_key":
				opts.withAppKey = v
			case "user_access_key_id":
				opts.withUserAccessKeyID = v
			case "user_secret_access_key":
				opts.withUserSecretAccessKey = v
			case "mac_address":
				opts.withMACAddress = v
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

	if err := wrapping.ParsePaths(&opts.withUserSecretAccessKey); err != nil {
		return nil, err
	}

	return &opts, nil
}

// OptionFunc holds a function with local options
type OptionFunc func(*options) error

// options = how options are represented
type options struct {
	*wrapping.Options

	withEndpoint            string
	withAppKey              string
	withUserAccessKeyID     string
	withUserSecretAccessKey string
	withMACAddress          string
}

func getDefaultOptions() options {
	return options{}
}

// WithEndpoint provides a way to specify the NHN Cloud SKM API endpoint
func WithEndpoint(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withEndpoint = with
			return nil
		})
	}
}

// WithAppKey provides a way to specify the NHN Cloud App Key
func WithAppKey(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withAppKey = with
			return nil
		})
	}
}

// WithUserAccessKeyID provides a way to specify the User Access Key ID
func WithUserAccessKeyID(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withUserAccessKeyID = with
			return nil
		})
	}
}

// WithUserSecretAccessKey provides a way to specify the User Secret Access Key
func WithUserSecretAccessKey(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withUserSecretAccessKey = with
			return nil
		})
	}
}

// WithMACAddress provides a way to specify the MAC address for client identification
func WithMACAddress(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withMACAddress = with
			return nil
		})
	}
}
