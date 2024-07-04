// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pkcs11

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
			case "kms_key_id": // deprecated backend-specific value, set global
				opts.WithKeyId = v
			case "slot":
				var err error
				var slot uint64
				slot, err = strconv.ParseUint(v, 10, 64)
				if err != nil {
					return nil, err
				}
				opts.withSlot = uint(slot)
			case "pin":
				opts.withPin = v
			case "lib":
			case "module":
				opts.withModule = v
			case "key_label":
			case "label":
				opts.withLabel = v
			case "mechanism":
				opts.withMechanism = v
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

	withSlot      uint
	withPin       string
	withModule    string
	withLabel     string
	withMechanism string
}

func getDefaultOptions() options {
	return options{}
}

// WithSlot sets the slot
func WithSlot(slot uint) OptionFunc {
	return func(o *options) error {
		o.withSlot = slot
		return nil
	}
}

// WithPin sets the pin
func WithPin(pin string) OptionFunc {
	return func(o *options) error {
		o.withPin = pin
		return nil
	}
}

// WithModule sets the module
func WithModule(module string) OptionFunc {
	return func(o *options) error {
		o.withModule = module
		return nil
	}
}

// WithLabel sets the label
func WithLabel(label string) OptionFunc {
	return func(o *options) error {
		o.withLabel = label
		return nil
	}
}

// WithMechanism sets the mechanism
func WithMechanism(mechanism string) OptionFunc {
	return func(o *options) error {
		o.withMechanism = mechanism
		return nil
	}
}
