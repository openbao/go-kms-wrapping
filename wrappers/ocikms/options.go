// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ocikms

import (
	"fmt"
	"strconv"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

const (
	// keyId config
	KmsConfigKeyId = "key_id"
	// cryptoEndpoint config
	KmsConfigCryptoEndpoint = "crypto_endpoint"
	// managementEndpoint config
	KmsConfigManagementEndpoint = "management_endpoint"
	// authTypeApiKey config
	KmsConfigAuthTypeApiKey = "auth_type_api_key"

	KmsConfigTenancyOCID          = "tenancy_ocid"
	KmsConfigUserOCID             = "user_ocid"
	KmsConfigKeyFingerprint       = "fingerprint"
	KmsConfigRegion               = "region"
	KmsConfigPrivateKey           = "private_key"
	KmsConfigPrivateKeyPassphrase = "private_key_passphrase"
)

func getDefaultOptions() options {
	return options{}
}

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
			case KmsConfigKeyId:
				opts.WithKeyId = v
			case KmsConfigCryptoEndpoint:
				opts.withCryptoEndpoint = v
			case KmsConfigManagementEndpoint:
				opts.withManagementEndpoint = v
			case KmsConfigTenancyOCID:
				opts.withTenancyOCID = v
			case KmsConfigUserOCID:
				opts.withUserOCID = v
			case KmsConfigKeyFingerprint:
				opts.withKeyFingerprint = v
			case KmsConfigRegion:
				opts.withRegion = v
			case KmsConfigPrivateKey:
				opts.withPrivateKey = v
			case KmsConfigPrivateKeyPassphrase:
				opts.withPrivateKeyPassphrase = v
			case KmsConfigAuthTypeApiKey:
				var err error
				opts.withAuthTypeApiKey, err = strconv.ParseBool(v)
				if err != nil {
					return nil, fmt.Errorf("failed parsing "+KmsConfigAuthTypeApiKey+" parameter: %w", err)
				}
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
		if err := wrapping.ParsePaths(&opts.WithKeyId); err != nil {
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

	withCryptoEndpoint       string
	withManagementEndpoint   string
	withAuthTypeApiKey       bool
	withTenancyOCID          string
	withUserOCID             string
	withKeyFingerprint       string
	withRegion               string
	withPrivateKey           string
	withPrivateKeyPassphrase string
}
