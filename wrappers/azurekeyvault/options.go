// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azurekeyvault

import (
	"strconv"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
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
		case "key_not_required":
			keyNotRequired, err := strconv.ParseBool(v)
			if err != nil {
				return nil, err
			}
			opts.withKeyNotRequired = keyNotRequired
		case "tenant_id":
			opts.withTenantId = v
		case "client_id":
			opts.withClientId = v
		case "client_secret":
			opts.withClientSecret = v
		case "environment":
			opts.withEnvironment = v
		case "resource":
			opts.withResource = v
		case "vault_name":
			opts.withVaultName = v
		case "key_name":
			opts.withKeyName = v
		case "auth_method":
			opts.withAuthMethod = v
		case "cert_path":
			opts.withCertPath = v
		case "cert_bytes":
			opts.withCertBytes = v
		case "cert_password":
			opts.withCertPassword = v
		case "managed_id_kind":
			opts.withManagedIdKind = v
		case "resource_id":
			opts.withResourceId = v
		}
	}

	if !opts.WithDisallowEnvVars {
		if err := wrapping.ParsePaths(&opts.withClientId, &opts.withClientSecret, &opts.withTenantId); err != nil {
			return nil, err
		}
	}

	return &opts, nil
}

// options = how options are represented
type options struct {
	*wrapping.Options

	withKeyNotRequired bool
	withTenantId       string
	withClientId       string
	withResourceId     string
	withManagedIdKind  string
	withClientSecret   string
	withEnvironment    string
	withResource       string
	withVaultName      string
	withKeyName        string
	withAuthMethod     string
	withCertPath       string
	withCertBytes      string
	withCertPassword   string
}
