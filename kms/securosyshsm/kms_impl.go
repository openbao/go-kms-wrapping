// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-hclog"
	kms "github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/securosys-com/tsb-client-go"
	"github.com/securosys-com/tsb-client-go/helpers"
)

// securosysKMS implements kms.KMS using the Securosys HSM.
type securosysKMS struct {
	kms.UnimplementedKMS

	client *client.SecurosysClient
	logger hclog.Logger

	approvalTimeout time.Duration
	pollInterval    time.Duration
	closeCtx        context.Context
	closeCancel     context.CancelFunc
}

// New returns a new KMS that uses the Securosys HSM.
func New() kms.KMS {
	return &securosysKMS{logger: hclog.NewNullLogger()}
}

// Open configures this KMS and acquires any necessary resources.
func (k *securosysKMS) Open(ctx context.Context, opts *kms.OpenOptions) error {
	if opts == nil || opts.ConfigMap == nil {
		return errors.New("config map is required")
	}

	var config openConfig
	if err := decodeConfig(opts.ConfigMap, &config); err != nil {
		return err
	}
	if err := validateOpenConfig(&config.SecurosysConfig); err != nil {
		return err
	}

	c, err := client.NewClient(&config.SecurosysConfig)
	if err != nil {
		return err
	}

	// Verify connection
	connection, status, err := c.CheckConnection(ctx)
	if err != nil {
		return err
	}
	if status != 200 {
		return connectionCheckError(status, connection)
	}

	logger := opts.Logger
	if logger == nil {
		logger = hclog.NewNullLogger()
	}
	closeCtx, closeCancel := context.WithCancel(context.Background())
	k.client = c
	k.logger = logger
	k.approvalTimeout = secondsDuration(config.ApprovalTimeout, defaultApprovalTimeout)
	k.pollInterval = secondsDuration(config.CheckEvery, defaultRequestPollInterval)
	k.closeCtx = closeCtx
	k.closeCancel = closeCancel
	k.logger.Debug("opened securosys hsm kms", "status", status)
	return nil
}

// GetKey returns an opaque Key using the passed options.
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
	k.logger.Debug("resolving securosys hsm key", "key_label", config.Name)

	// Get key from client
	keyAttrs, err := k.client.GetKey(ctx, config.Name, config.Password)
	if err != nil {
		k.logger.Debug("failed to resolve securosys hsm key", "key_label", config.Name, "error", err)
		return nil, err
	}
	k.logger.Debug("resolved securosys hsm key", "key_label", config.Name)

	return &securosysKey{
		client:          k.client,
		keyAttrs:        keyAttrs,
		password:        config.Password,
		cipherAlgorithm: config.CipherAlgorithm,
		logger:          k.logger,
		approvalTimeout: k.approvalTimeout,
		pollInterval:    k.pollInterval,
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
	k.logger.Debug("closed securosys hsm kms")
	k.client = nil
	k.logger = hclog.NewNullLogger()
	k.approvalTimeout = 0
	k.pollInterval = 0
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

type openConfig struct {
	helpers.SecurosysConfig `mapstructure:",squash"`
	CheckEvery              int `mapstructure:"check_every"`
	ApprovalTimeout         int `mapstructure:"approval_timeout"`
}

func connectionCheckError(status int, connection string) error {
	const message = "Unable to connect. Please check current config setting"

	connection = strings.TrimSpace(connection)
	if connection == "" {
		return fmt.Errorf("%s (status %d)", message, status)
	}
	return fmt.Errorf("%s (status %d): %s", message, status, connection)
}

func secondsDuration(seconds int, fallback time.Duration) time.Duration {
	if seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

func validateOpenConfig(config *helpers.SecurosysConfig) error {
	if config == nil {
		return errors.New("config is required")
	}

	config.RestApi = strings.TrimSpace(config.RestApi)
	config.Auth = strings.TrimSpace(strings.ToUpper(config.Auth))
	config.BearerToken = strings.TrimSpace(config.BearerToken)
	config.CertPath = strings.TrimSpace(config.CertPath)
	config.KeyPath = strings.TrimSpace(config.KeyPath)

	if config.RestApi == "" {
		return errors.New("rest_api is required")
	}
	if config.Auth == "" {
		return errors.New("auth is required")
	}

	switch config.Auth {
	case "NONE":
		return nil
	case "TOKEN":
		if config.BearerToken == "" {
			return errors.New("bearer_token is required when auth is TOKEN")
		}
		return nil
	case "CERT":
		if config.CertPath == "" {
			return errors.New("cert_path is required when auth is CERT")
		}
		if config.KeyPath == "" {
			return errors.New("key_path is required when auth is CERT")
		}
		if _, err := os.Stat(config.CertPath); err != nil {
			return fmt.Errorf("cert_path is invalid: %w", err)
		}
		if _, err := os.Stat(config.KeyPath); err != nil {
			return fmt.Errorf("key_path is invalid: %w", err)
		}
		return nil
	default:
		return errors.New("auth must be one of [TOKEN,CERT,NONE]")
	}
}

// decodeConfig decodes a ConfigMap into the given struct using mapstructure.
func decodeConfig(cfg kms.ConfigMap, target interface{}) error {
	return mapstructure.WeakDecode(cfg, target)
}
