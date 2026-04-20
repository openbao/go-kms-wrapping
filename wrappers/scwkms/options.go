// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package scwkms

import (
	"strconv"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// getOpts iterates the inbound Options and returns a struct.
func getOpts(opt ...wrapping.Option) (*options, error) {
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

	var err error
	opts.Options, err = wrapping.GetOpts(wrappingOptions...)
	if err != nil {
		return nil, err
	}

	if opts.Options == nil {
		opts.Options = new(wrapping.Options)
	}

	// Local options can be provided either via the WithConfigMap field
	// (for over the plugin barrier or embedding) or via local option functions.
	if opts.WithConfigMap != nil {
		for k, v := range opts.WithConfigMap {
			switch k {
			case "disallow_env_vars":
				disallowEnvVars, err := strconv.ParseBool(v)
				if err != nil {
					return nil, err
				}
				opts.withDisallowEnvVars = disallowEnvVars
			case "key_not_required":
				keyNotRequired, err := strconv.ParseBool(v)
				if err != nil {
					return nil, err
				}
				opts.withKeyNotRequired = keyNotRequired
			case "kms_key_id":
				opts.WithKeyId = v
			case "region":
				opts.withRegion = v
			case "project_id":
				opts.withProjectID = v
			case "access_key":
				opts.withAccessKey = v
			case "secret_key":
				opts.withSecretKey = v
			}
		}
	}

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

// options represents how options are stored.
type options struct {
	*wrapping.Options

	withDisallowEnvVars bool
	withKeyNotRequired  bool
	withRegion          string
	withProjectID       string
	withAccessKey       string
	withSecretKey       string
}

func getDefaultOptions() options {
	return options{}
}

// WithDisallowEnvVars disables reading configuration from environment variables.
func WithDisallowEnvVars(with bool) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withDisallowEnvVars = with
			return nil
		})
	}
}

// WithKeyNotRequired allows the wrapper to be configured without a key ID.
func WithKeyNotRequired(with bool) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withKeyNotRequired = with
			return nil
		})
	}
}

// WithRegion sets the Scaleway region (e.g. "fr-par", "nl-ams", "pl-waw").
func WithRegion(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withRegion = with
			return nil
		})
	}
}

// WithProjectID sets the Scaleway project ID.
func WithProjectID(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withProjectID = with
			return nil
		})
	}
}

// WithAccessKey sets the Scaleway access key.
func WithAccessKey(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withAccessKey = with
			return nil
		})
	}
}

// WithSecretKey sets the Scaleway secret key.
func WithSecretKey(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withSecretKey = with
			return nil
		})
	}
}
