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
	opts := getDefaultOptions()

	var err error
	opts.Options, err = wrapping.GetOpts(opt...)
	if err != nil {
		return nil, err
	}

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

	if !opts.WithDisallowEnvVars {
		if err := wrapping.ParsePaths(&opts.WithKeyId); err != nil {
			return nil, err
		}
	}

	return &opts, nil
}

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
