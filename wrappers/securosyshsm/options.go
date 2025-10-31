// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package securosyshsm

import (
	"github.com/hashicorp/go-hclog"
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
			case "key_label":
				opts.withKeyLabel = v
			case "key_password":
				opts.withKeyPassword = v
			case "approval_timeout":
				opts.withApprovalTimeout = v
			case "auth":
				opts.withAuth = v
			case "bearer_token":
				opts.withBearerToken = v
			case "cert_path":
				opts.withCertPath = v
			case "key_path":
				opts.withKeyPath = v
			case "check_every":
				opts.withCheckEvery = v
			case "tsb_api_endpoint":
				opts.withTSBApiEndpoint = v
			case "policy":
				opts.withPolicy = v
			case "policy_rule_use":
				opts.withPolicyRuleUse = v
			case "policy_rule_block":
				opts.withPolicyRuleBlock = v
			case "policy_rule_unblock":
				opts.withPolicyRuleUnBlock = v
			case "policy_rule_modify":
				opts.withPolicyRuleModify = v
			case "full_policy":
				opts.withFullPolicy = v
			case "full_policy_file":
				opts.withFullPolicyFile = v
			case "application_key_pair":
				opts.withApplicationKeyPair = v
			case "api_keys":
				opts.withApiKeys = v
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
	}

	return &opts, nil
}

// OptionFunc holds a function with local options
type OptionFunc func(*options) error

// options = how options are represented
type options struct {
	*wrapping.Options

	withKeyLabel        string
	withKeyPassword     string
	withApprovalTimeout string
	withAuth            string
	withBearerToken     string
	withCheckEvery      string
	withTSBApiEndpoint  string
	withCertPath        string
	withKeyPath         string
	withPolicy          string
	withFullPolicy      string
	withFullPolicyFile  string

	withPolicyRuleUse      string
	withPolicyRuleBlock    string
	withPolicyRuleUnBlock  string
	withPolicyRuleModify   string
	withApplicationKeyPair string
	withApiKeys            string
	withLogger             hclog.Logger
}

func getDefaultOptions() options {
	return options{}
}

// WithMountPath provides a way to choose the mount path
func WithApprovalTimeout(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withApprovalTimeout = with
			return nil
		})
	}
}

// WithKeyName provides a way to choose the key name
func WithKeyLabel(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withKeyLabel = with
			return nil
		})
	}
}

// WithKeyName provides a way to choose the key name
func WithPassword(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withKeyPassword = with
			return nil
		})
	}
}

func WithPolicy(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withPolicy = with
			return nil
		})
	}
}

func WithFullPolicy(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withFullPolicy = with
			return nil
		})
	}
}

func WithFullPolicyFile(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withFullPolicyFile = with
			return nil
		})
	}
}

func WithPolicyRuleUse(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withPolicyRuleUse = with
			return nil
		})
	}
}

func WithPolicyRuleBlock(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withPolicyRuleBlock = with
			return nil
		})
	}
}

func withPolicyRuleUnBlock(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withPolicyRuleUnBlock = with
			return nil
		})
	}
}

func withPolicyRuleModify(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withPolicyRuleModify = with
			return nil
		})
	}
}

// WithDisableRenewal provides a way to disable renewal
func WithAuth(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withAuth = with
			return nil
		})
	}
}

// WithNamespace provides a way to choose the namespace
func WithBearerToken(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withBearerToken = with
			return nil
		})
	}
}
func WithCertPath(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withCertPath = with
			return nil
		})
	}
}
func WithKeyPath(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withKeyPath = with
			return nil
		})
	}
}

// WithAddress provides a way to choose the address
func WithCheckEvery(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withCheckEvery = with
			return nil
		})
	}
}

func WithTSBApiEndpoint(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withTSBApiEndpoint = with
			return nil
		})
	}
}
func WithApiKeys(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withApiKeys = with
			return nil
		})
	}
}

func WithApplicationKeyPair(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withApplicationKeyPair = with
			return nil
		})
	}
}

// WithLogger provides a way to pass in a logger
func WithLogger(with hclog.Logger) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withLogger = with
			return nil
		})
	}
}
