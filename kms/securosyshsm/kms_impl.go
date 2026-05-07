// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"context"
	"errors"

	"github.com/go-viper/mapstructure/v2"
	"github.com/openbao/go-kms-wrapping/kms/securosyshsm/v2/client"
	"github.com/openbao/go-kms-wrapping/kms/securosyshsm/v2/helpers"
	kms "github.com/openbao/go-kms-wrapping/v2/kms"
)

// Ensure securosysKMS implements kms.KMS
var _ kms.KMS = (*securosysKMS)(nil)

// securosysKMS implements kms.KMS using the Securosys HSM.
type securosysKMS struct {
	kms.UnimplementedKMS

	client *client.SecurosysClient
}

// New returns a new KMS that uses the Securosys HSM.
func New() kms.KMS {
	return &securosysKMS{}
}

// Open configures this KMS and acquires any necessary resources.
func (k *securosysKMS) Open(ctx context.Context, opts *kms.OpenOptions) error {
	if opts == nil || opts.ConfigMap == nil {
		return errors.New("config map is required")
	}

	var config helpers.SecurosysConfig
	if err := decodeConfig(opts.ConfigMap, &config); err != nil {
		return err
	}

	c, err := client.NewClient(&config)
	if err != nil {
		return err
	}

	// Verify connection
	connection, status, err := c.CheckConnection()
	if err != nil {
		return err
	}
	if status != 200 {
		return errors.New(connection)
	}

	k.client = c
	return nil
}

// GetKey returns an opaque Key using the passed options.
//
// Required ConfigMap key:
//   - "name": Securosys key label
//
// Optional ConfigMap keys:
//   - "password": key password, if the Securosys key requires one
//   - "cipher_algorithm": provider-specific cipher override. Native Securosys
//     values from helpers.AES_CIPHER_LIST and helpers.RSA_CIPHER_LIST are
//     accepted, as are compatibility names handled by helpers.MapCipherAlgorithm.
func (k *securosysKMS) GetKey(ctx context.Context, opts *kms.KeyOptions) (kms.Key, error) {
	if k.client == nil {
		return nil, errors.New("KMS not opened")
	}
	if opts == nil || opts.ConfigMap == nil {
		return nil, errors.New("key options config map is required")
	}

	var config keyConfig
	if err := decodeConfig(opts.ConfigMap, &config); err != nil {
		return nil, err
	}
	if config.Name == "" {
		return nil, errors.New("key name is required")
	}

	// Get key from client
	keyAttrs, err := k.client.GetKey(config.Name, config.Password)
	if err != nil {
		return nil, err
	}

	return &securosysKey{
		client:          k.client,
		keyAttrs:        keyAttrs,
		password:        config.Password,
		cipherAlgorithm: config.CipherAlgorithm,
	}, nil
}

// Close terminates this KMS.
func (k *securosysKMS) Close(ctx context.Context) error {
	if k.client != nil && k.client.HTTPClient != nil {
		k.client.HTTPClient.CloseIdleConnections()
	}
	k.client = nil
	return nil
}

// keyConfig holds provider-specific key configuration decoded from
// kms.KeyOptions.ConfigMap.
type keyConfig struct {
	Name            string `mapstructure:"name"`
	Password        string `mapstructure:"password"`
	CipherAlgorithm string `mapstructure:"cipher_algorithm"`
}

// decodeConfig decodes a ConfigMap into the given struct using mapstructure.
func decodeConfig(cfg kms.ConfigMap, target interface{}) error {
	return mapstructure.WeakDecode(cfg, target)
}
