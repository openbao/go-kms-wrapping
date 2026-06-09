// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package openstackbarbican

import (
	"fmt"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

const (
	configSecretRef = "secret_ref"
	configSecretID  = "secret_id"
	configRegion    = "region"
	configEndpoint  = "endpoint"
)

type OptionFunc func(*options) error

type options struct {
	*wrapping.Options

	withSecretRef string
	withRegion    string
	withEndpoint  string
}

func getOpts(opt ...wrapping.Option) (*options, error) {
	opts := options{}
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
		return nil, fmt.Errorf("openstackbarbican: parse options: %w", err)
	}
	if opts.Options == nil {
		opts.Options = new(wrapping.Options)
	}

	if opts.WithConfigMap != nil {
		for k, v := range opts.WithConfigMap {
			switch k {
			case configSecretRef:
				opts.withSecretRef = v
			case configRegion:
				opts.withRegion = v
			case configEndpoint:
				opts.withEndpoint = v
			}
		}
	}

	for _, o := range localOptions {
		if o != nil {
			if err := o(&opts); err != nil {
				return nil, fmt.Errorf("openstackbarbican: parse options: %w", err)
			}
		}
	}

	if err := wrapping.ParsePaths(&opts.withSecretRef, &opts.withEndpoint); err != nil {
		return nil, fmt.Errorf("openstackbarbican: parse options: %w", err)
	}

	return &opts, nil
}

func WithSecretRef(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withSecretRef = with
			return nil
		})
	}
}

func WithRegion(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withRegion = with
			return nil
		})
	}
}

func WithEndpoint(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withEndpoint = with
			return nil
		})
	}
}
