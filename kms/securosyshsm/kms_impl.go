// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"context"
	"errors"
	"os"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/go-kms-wrapping/kms/securosyshsm/v2/internal/client"
	"github.com/openbao/go-kms-wrapping/kms/securosyshsm/v2/internal/helpers"
	kms "github.com/openbao/go-kms-wrapping/v2/kms"
)

// Ensure securosysKMS implements kms.KMS
var _ kms.KMS = (*securosysKMS)(nil)

// securosysKMS implements kms.KMS using the Securosys HSM.
type securosysKMS struct {
	kms.UnimplementedKMS

	client  *client.SecurosysClient
	logger  hclog.Logger
	logFile *os.File

	closeCtx    context.Context
	closeCancel context.CancelFunc
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
	connection, status, err := c.CheckConnection(ctx)
	if err != nil {
		return err
	}
	if status != 200 {
		return errors.New(connection)
	}

	var logger hclog.Logger
	var logFile *os.File
	closeCtx, closeCancel := context.WithCancel(context.Background())
	k.client = c
	k.logger = logger
	k.logFile = logFile
	k.closeCtx = closeCtx
	k.closeCancel = closeCancel
	if k.logger != nil {
		k.logger.Debug("opened securosys hsm kms", "status", status)
	}
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
	if k.logger != nil {
		k.logger.Debug("resolving securosys hsm key", "key_label", config.Name)
	}

	// Get key from client
	keyAttrs, err := k.client.GetKey(ctx, config.Name, config.Password)
	if err != nil {
		if k.logger != nil {
			k.logger.Debug("failed to resolve securosys hsm key", "key_label", config.Name, "error", err)
		}
		return nil, err
	}
	if k.logger != nil {
		k.logger.Debug("resolved securosys hsm key", "key_label", config.Name)
	}

	return &securosysKey{
		client:          k.client,
		keyAttrs:        keyAttrs,
		password:        config.Password,
		cipherAlgorithm: config.CipherAlgorithm,
		logger:          k.logger,
		closeCtx:        k.closeCtx,
	}, nil
}

// Close terminates this KMS.
func (k *securosysKMS) Close(ctx context.Context) error {
	if k.closeCancel != nil {
		k.closeCancel()
	}
	if k.client != nil && k.client.HTTPClient != nil {
		k.client.HTTPClient.CloseIdleConnections()
	}
	if k.logger != nil {
		k.logger.Debug("closed securosys hsm kms")
	}
	if k.logFile != nil {
		if err := k.logFile.Close(); err != nil {
			return err
		}
	}
	k.client = nil
	k.logger = nil
	k.logFile = nil
	k.closeCtx = nil
	k.closeCancel = nil
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
