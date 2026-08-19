package tpm

import (
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

type Option func(*options)

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...wrapping.Option) (*options, error) {
	opts := getDefaultOptions()

	var err error
	opts.Options, err = wrapping.GetOpts(opt...)
	if err != nil {
		return nil, err
	}

	for k, v := range opts.WithConfigMap {
		switch k {
		case TPM_PATH:
			opts.withTPMPath = v
		case PCR_VALUES:
			opts.withPCRValues = v
		case USER_AUTH:
			opts.withUserAuth = v
		case HIERARCHY_AUTH:
			opts.withHierarchyAuth = v
		}
	}

	return &opts, nil
}

// OptionFunc holds a function with local options
type OptionFunc func(*options) error

// options = how options are represented
type options struct {
	*wrapping.Options
	withTPMPath       string
	withPCRValues     string
	withUserAuth      string
	withHierarchyAuth string
}

func getDefaultOptions() options {
	return options{}
}

// WithUserAuth provides a way to chose the user agent
func WithUserAuth(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withUserAuth = with
			return nil
		})
	}
}

// WithHierarchyAuth provides a way to set the passphrase on the hierarchy (if any)
func WithHierarchyAuth(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withHierarchyAuth = with
			return nil
		})
	}
}

// Path to the TPM device (/dev/tpm0)
func WithTPMPath(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withTPMPath = with
			return nil
		})
	}
}

// List of PCR banks Value
// Multiple PCR values are comma separated (.WithPCRValues("0:123abc,7:abcae"))
func WithPCRValues(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withPCRValues = with
			return nil
		})
	}
}
