// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

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
		// case "key_id", "kms_key_id": // deprecated backend-specific value, set global
		case "key_id":
			opts.withKeyId = v
		case "slot":
			opts.withSlot = v
		case "pin":
			opts.withPin = v
		case "lib", "module":
			opts.withLib = v
		case "token", "token_label":
			opts.withTokenLabel = v
		case "label", "key_label":
			opts.withKeyLabel = v
		case "mechanism":
			opts.withMechanism = v
		case "rsa_oaep_hash":
			opts.withRsaOaepHash = v
		case "disable_software_encryption":
			opts.withDisableSoftwareEncryption = v
		}
	}

	if !opts.WithDisallowEnvVars {
		if err := wrapping.ParsePaths(&opts.withPin); err != nil {
			return nil, err
		}
	}

	return &opts, nil
}

// options = how options are represented
type options struct {
	*wrapping.Options

	withSlot                      string
	withPin                       string
	withLib                       string
	withKeyId                     string
	withKeyLabel                  string
	withTokenLabel                string
	withMechanism                 string
	withRsaOaepHash               string
	withDisableSoftwareEncryption string
}

func getDefaultOptions() options {
	return options{}
}
