// Copyright The OpenBao Contributors
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"fmt"
	"strconv"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/api/v2"
)

const (
	EnvHsmWrapperLib                = "BAO_HSM_LIB"
	EnvHsmWrapperSlot               = "BAO_HSM_SLOT"
	EnvHsmWrapperTokenLabel         = "BAO_HSM_TOKEN_LABEL"
	EnvHsmWrapperPin                = "BAO_HSM_PIN"
	EnvHsmWrapperMaxParallel        = "BAO_HSM_MAX_PARALLEL"
	EnvHsmWrapperKeyId              = "BAO_HSM_KEY_ID"
	EnvHsmWrapperKeyLabel           = "BAO_HSM_KEY_LABEL"
	EnvHsmWrapperMechanism          = "BAO_HSM_MECHANISM"
	EnvHsmWrapperRsaOaepHash        = "BAO_HSM_RSA_OAEP_HASH"
	EnvHsmWrapperSoftwareEncryption = "BAO_HSM_SOFTWARE_ENCRYPTION"
)

// clientOptions are the options relevant for client configuration.
type clientOptions struct {
	lib         string
	slotNumber  *uint
	tokenLabel  string
	pin         string
	maxSessions int
}

// keyOptions are the options relevant for key configuration and usage.
type keyOptions struct {
	keyId     string
	keyLabel  string
	mechanism string
	hash      string
	soft      bool
}

// wrapperOptions are the options relevant for wrapper configuration.
type wrapperOptions struct {
	*clientOptions
	*keyOptions
}

type (
	// ClientOption is used to set client-related options.
	ClientOption func(*clientOptions) error
	// KeyOption is used to set key-related options.
	KeyOption func(*keyOptions) error
)

// defaultClientOptions returns a new clientOptions with defaults set.
func defaultClientOptions() *clientOptions {
	var opts clientOptions
	return &opts
}

// defaultKeyOptions returns a new keyOptions with defaults set.
func defaultKeyOptions() *keyOptions {
	var opts keyOptions
	opts.soft = true
	return &opts
}

// sortOpts sorts a list of wrapping.Option into three buckets.
func sortOpts(opts []wrapping.Option) (*wrapping.Options, []ClientOption, []KeyOption, error) {
	var globalOpts []wrapping.Option
	var clientOpts []ClientOption
	var keyOpts []KeyOption

	for _, o := range opts {
		if o == nil {
			continue
		}
		iface := o()
		switch to := iface.(type) {
		case wrapping.OptionFunc:
			globalOpts = append(globalOpts, o)
		case ClientOption:
			clientOpts = append(clientOpts, to)
		case KeyOption:
			keyOpts = append(keyOpts, to)
		}
	}

	global, err := wrapping.GetOpts(globalOpts...)
	if err != nil {
		return nil, nil, nil, err
	}

	return global, clientOpts, keyOpts, nil
}

// clientOptsFromConfigMap gets a clientOptions from a config map.
func clientOptsFromConfigMap(config map[string]string) (*clientOptions, error) {
	opts := defaultClientOptions()
	for key, val := range config {
		switch key {
		case "lib":
			opts.lib = val
		case "slot":
			slot, err := parseSlotNumber(val)
			if err != nil {
				return nil, err
			}
			opts.slotNumber = &slot
		case "token_label":
			opts.tokenLabel = val
		case "pin":
			opts.pin = val
		case "max_parallel": // Called "max_parallel" for compability with upstream
			sessions, err := strconv.ParseInt(val, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("failed to parse max sessions value: %w", err)
			}
			opts.maxSessions = int(sessions)
		case "module":
			return nil, fmt.Errorf(`deprecated config option: "module", use "lib" instead`)
		case "token":
			return nil, fmt.Errorf(`deprecated config option: "token", use "token_label" instead`)
		}
	}
	return opts, nil
}

// keyOptsFromConfigMap gets a keyOptions with from a config map.
func keyOptsFromConfigMap(config map[string]string) (*keyOptions, error) {
	opts := defaultKeyOptions()
	for key, val := range config {
		switch key {
		case "key_id":
			opts.keyId = val
		case "key_label":
			opts.keyLabel = val
		case "mechanism":
			opts.mechanism = val
		case "rsa_oaep_hash":
			opts.hash = val
		case "software_encryption":
			soft, err := parseBool(val)
			if err != nil {
				return nil, err
			}
			opts.soft = soft
		case "key":
			return nil, fmt.Errorf(`deprecated config option: "key", use "key_label" instead`)
		}
	}
	return opts, nil
}

// getWrapperOpts evaluates options that apply to a Wrapper.
// Environment variables are read unless disallowed via WithDisallowEnvVars.
// The slot pin may be read via wrapping.ParsePaths if applicable.
func getWrapperOpts(opts []wrapping.Option) (*wrapperOptions, error) {
	globalOpts, clientOpts, keyOpts, err := sortOpts(opts)
	if err != nil {
		return nil, err
	}

	if !globalOpts.WithDisallowEnvVars {
		if globalOpts.WithConfigMap == nil {
			globalOpts.WithConfigMap = make(map[string]string)
		}
		mergeConfigMapWithEnv(globalOpts.WithConfigMap)
	}

	var options wrapperOptions
	options.clientOptions, err = clientOptsFromConfigMap(globalOpts.WithConfigMap)
	if err != nil {
		return nil, err
	}
	options.keyOptions, err = keyOptsFromConfigMap(globalOpts.WithConfigMap)
	if err != nil {
		return nil, err
	}

	for _, o := range clientOpts {
		if err := o(options.clientOptions); err != nil {
			return nil, err
		}
	}
	for _, o := range keyOpts {
		if err := o(options.keyOptions); err != nil {
			return nil, err
		}
	}

	if err := wrapping.ParsePaths(&options.pin); err != nil {
		return nil, err
	}

	return &options, nil
}

func mergeConfigMapWithEnv(config map[string]string) {
	if env := api.ReadBaoVariable(EnvHsmWrapperLib); env != "" {
		config["lib"] = env
	}
	if env := api.ReadBaoVariable(EnvHsmWrapperSlot); env != "" {
		config["slot"] = env
	}
	if env := api.ReadBaoVariable(EnvHsmWrapperTokenLabel); env != "" {
		config["token_label"] = env
	}
	if env := api.ReadBaoVariable(EnvHsmWrapperPin); env != "" {
		config["pin"] = env
	}
	if env := api.ReadBaoVariable(EnvHsmWrapperMaxParallel); env != "" {
		config["max_parallel"] = env
	}
	if env := api.ReadBaoVariable(EnvHsmWrapperKeyId); env != "" {
		config["key_id"] = env
	}
	if env := api.ReadBaoVariable(EnvHsmWrapperKeyLabel); env != "" {
		config["key_label"] = env
	}
	if env := api.ReadBaoVariable(EnvHsmWrapperMechanism); env != "" {
		config["mechanism"] = env
	}
	if env := api.ReadBaoVariable(EnvHsmWrapperRsaOaepHash); env != "" {
		config["rsa_oaep_hash"] = env
	}
	if env := api.ReadBaoVariable(EnvHsmWrapperSoftwareEncryption); env != "" {
		config["software_encryption"] = env
	}
}

// getHubOpts evaluates options that apply to a Hub.
// Environment variables are never read.
func getHubOpts(opts []wrapping.Option) (*clientOptions, error) {
	globalOpts, clientOpts, _, err := sortOpts(opts)
	if err != nil {
		return nil, err
	}
	options, err := clientOptsFromConfigMap(globalOpts.WithConfigMap)
	if err != nil {
		return nil, err
	}
	for _, o := range clientOpts {
		if err := o(options); err != nil {
			return nil, err
		}
	}
	return options, nil
}

// getSignerDecrypterOpts evaluates options that apply
// to signers/decrypters derived from a Hub.
// Environment variables are never read.
func getSignerDecrypterOpts(opts []wrapping.Option) (*keyOptions, error) {
	globalOpts, _, keyOpts, err := sortOpts(opts)
	if err != nil {
		return nil, err
	}
	options, err := keyOptsFromConfigMap(globalOpts.WithConfigMap)
	if err != nil {
		return nil, err
	}
	for _, o := range keyOpts {
		if err := o(options); err != nil {
			return nil, err
		}
	}
	return options, nil
}

// WithLib sets the PKCS#11 module (dynamic library).
func WithLib(lib string) wrapping.Option {
	return func() any {
		return ClientOption(func(o *clientOptions) error {
			o.lib = lib
			return nil
		})
	}
}

// WithSlot sets the token slot.
func WithSlot(slot uint) wrapping.Option {
	return func() any {
		return ClientOption(func(o *clientOptions) error {
			o.slotNumber = &slot
			return nil
		})
	}
}

// WithTokenLabel sets the token label.
func WithTokenLabel(label string) wrapping.Option {
	return func() any {
		return ClientOption(func(o *clientOptions) error {
			o.tokenLabel = label
			return nil
		})
	}
}

// WithPin sets the pin for the token slot.
func WithPin(pin string) wrapping.Option {
	return func() any {
		return ClientOption(func(o *clientOptions) error {
			o.pin = pin
			return nil
		})
	}
}

// WithMaxSessions sets the maximum concurrent sessions against the the token slot.
// Set to a value less than 1 to automatically choose the limit.
func WithMaxSessions(sessions int) wrapping.Option {
	return func() any {
		return ClientOption(func(o *clientOptions) error {
			o.maxSessions = sessions
			return nil
		})
	}
}

// WithKeyId sets the key id.
func WithKeyId(id string) wrapping.Option {
	return func() any {
		return KeyOption(func(o *keyOptions) error {
			o.keyId = id
			return nil
		})
	}
}

// WithKeyLabel sets the key label.
func WithKeyLabel(label string) wrapping.Option {
	return func() any {
		return KeyOption(func(o *keyOptions) error {
			o.keyLabel = label
			return nil
		})
	}
}

// WithMechanism sets the key mechanism.
func WithMechanism(mechanism string) wrapping.Option {
	return func() any {
		return KeyOption(func(o *keyOptions) error {
			o.mechanism = mechanism
			return nil
		})
	}
}

// WithHash sets the hash mechanism for RSA OAEP/PSS.
func WithHash(hash string) wrapping.Option {
	return func() any {
		return KeyOption(func(o *keyOptions) error {
			o.hash = hash
			return nil
		})
	}
}

// WithSoftwareEncryption enables/disables software encryption for asymmetric keys.
func WithSoftwareEncryption(value bool) wrapping.Option {
	return func() any {
		return KeyOption(func(o *keyOptions) error {
			o.soft = value
			return nil
		})
	}
}
