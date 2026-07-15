// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package ncloudkms

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

// OptionFunc holds a function with local options
type OptionFunc func(*options) error

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

// WithKeyTag provides a way to choose the key tag identifying the KMS key.
func WithKeyTag(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withKeyTag = with
			return nil
		})
	}
}

// WithDomain provides a way to choose the KMS API gateway domain. Defaults to
// the civilian cloud ("kms.apigw.ntruss.com"); use "kms.apigw.gov-ntruss.com"
// for the public-sector (government) cloud.
func WithDomain(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withDomain = with
			return nil
		})
	}
}

// WithAccessKey provides a way to choose the access key
func WithAccessKey(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withAccessKey = with
			return nil
		})
	}
}

// WithSecretKey provides a way to choose the secret key
func WithSecretKey(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withSecretKey = with
			return nil
		})
	}
}
