// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package awskms

import (
	"strconv"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...wrapping.Option) (*options, error) {
	// First, separate out options into local and global
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
		case "kms_key_id": // deprecated backend-specific value, set global
			opts.WithKeyId = v
		case "region":
			opts.withRegion = v
		case "endpoint":
			opts.withEndpoint = v
		case "access_key":
			opts.withAccessKey = v
		case "secret_key":
			opts.withSecretKey = v
		case "session_token":
			opts.withSessionToken = v
		case "shared_creds_filename":
			opts.withSharedCredsFilename = v
		case "shared_creds_profile":
			opts.withSharedCredsProfile = v
		case "web_identity_token_file":
			opts.withWebIdentityTokenFile = v
		case "role_session_name":
			opts.withRoleSessionName = v
		case "role_arn":
			opts.withRoleArn = v
		}
	}

	if !opts.WithDisallowEnvVars {
		if err := wrapping.ParsePaths(&opts.withAccessKey, &opts.withSecretKey, &opts.withSessionToken); err != nil {
			return nil, err
		}
	}

	return &opts, nil
}

// options = how options are represented
type options struct {
	*wrapping.Options

	withKeyNotRequired       bool
	withRegion               string
	withEndpoint             string
	withAccessKey            string
	withSecretKey            string
	withSessionToken         string
	withSharedCredsFilename  string
	withSharedCredsProfile   string
	withWebIdentityTokenFile string
	withRoleSessionName      string
	withRoleArn              string
}

func getDefaultOptions() options {
	return options{}
}
