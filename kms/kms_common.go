// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

// Credentials provides login credentials for a keystore provider
type Credentials struct {
	Username string
	Password string
}

// NewKeyStore should be implemented by all providers to allow creating a key
// store from the given configuration parameters. Parameters are provider
// specific except for standard ones defined here; these should be prefixed
// with a provider identifier to prevent overlap.
type NewKeyStore func(params map[string]interface{}) (KeyStore, error)

const (
	// WithLoggerKeyStoreParam allows specifying a go-hclog.Logger instance
	// for use by this provider.
	WithLoggerKeyStoreParam string = "with-go-hclog-logger"

	// WithEnvironmentKeyStoreParam should be set to bool(true) if the
	// provider is allowed to fall back to relevant environment variables
	// or other global configuration for missing (required) options.
	//
	// Explicitly specified configuration options take precedence over
	// discovered ones.
	WithEnvironmentKeyStoreParam string = "with-env-vars"
)
