// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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
		case tpmPath:
			opts.withTPMPath = v
		case pcrValues:
			opts.withPCRValues = v
		case userAuth:
			opts.withUserAuth = v
		case hierarchyuAuth:
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
