// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package securosyshsm

import (
	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...wrapping.Option) (*options, error) {
	// First, separate out options into local and global
	opts := getDefaultOptions()
	var wrappingOptions []wrapping.Option
	for _, o := range opt {
		if o == nil {
			continue
		}
		wrappingOptions = append(wrappingOptions, o)
	}

	// Parse the global options
	var err error
	opts.Options, err = wrapping.GetOpts(wrappingOptions...)
	if err != nil {
		return nil, err
	}

	if opts.Options == nil {
		opts.Options = new(wrapping.Options)
	}

	if opts.WithConfigMap != nil {
		var config configMapOptions
		if err := mapstructure.WeakDecode(opts.WithConfigMap, &config); err != nil {
			return nil, err
		}

		opts.withKeyLabel = config.KeyLabel
		opts.withKeyPassword = config.KeyPassword
		opts.withApprovalTimeout = config.ApprovalTimeout
		opts.withAuth = config.Auth
		opts.withBearerToken = config.BearerToken
		opts.withCertPath = config.CertPath
		opts.withKeyPath = config.KeyPath
		opts.withCheckEvery = config.CheckEvery
		opts.withTSBApiEndpoint = config.TSBApiEndpoint
		opts.withApplicationKeyPair = config.ApplicationKeyPair
		opts.withApiKeys = config.ApiKeys
	}

	return &opts, nil
}

// OptionFunc holds a function with local options
type OptionFunc func(*options) error

type configMapOptions struct {
	KeyLabel           string `mapstructure:"key_label"`
	KeyPassword        string `mapstructure:"key_password"`
	ApprovalTimeout    string `mapstructure:"approval_timeout"`
	Auth               string `mapstructure:"auth"`
	BearerToken        string `mapstructure:"bearer_token"`
	CertPath           string `mapstructure:"cert_path"`
	KeyPath            string `mapstructure:"key_path"`
	CheckEvery         string `mapstructure:"check_every"`
	TSBApiEndpoint     string `mapstructure:"tsb_api_endpoint"`
	ApplicationKeyPair string `mapstructure:"application_key_pair"`
	ApiKeys            string `mapstructure:"api_keys"`
}

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

	withApplicationKeyPair string
	withApiKeys            string
	withLogger             hclog.Logger
}

func getDefaultOptions() options {
	return options{}
}
