// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-hclog"
	kms "github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/securosys-com/tsb-client-go"
)

// securosysKMS implements kms.KMS using the Securosys HSM.
type securosysKMS struct {
	kms.UnimplementedKMS

	client *client.SecurosysClient
	logger hclog.Logger

	approvalTimeout time.Duration
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
	if err := validateOpenConfig(&config); err != nil {
		return err
	}

	c, err := newClient(&config)
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
	k.client.Logger = logger
	k.client.ApprovalPollInterval = secondsDuration(config.CheckEvery, defaultRequestPollInterval)
	k.closeCtx = closeCtx
	k.closeCancel = closeCancel
	k.logger.Debug("opened securosys hsm kms", "status", status)
	return nil
}

// GetKey returns an opaque Key using the passed options.
func (k *securosysKMS) GetKey(ctx context.Context, opts *kms.KeyOptions) (kms.Key, error) {
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
		approvalTimeout: k.approvalTimeout,
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
	Auth               string `mapstructure:"auth"`
	BearerToken        string `mapstructure:"bearer_token"`
	CertPEM            string `mapstructure:"cert_pem"`
	KeyPEM             string `mapstructure:"key_pem"`
	RestAPI            string `mapstructure:"rest_api"`
	ApplicationKeyPair string `mapstructure:"application_key_pair"`
	APIKeys            string `mapstructure:"api_keys"`
	CheckEvery         int    `mapstructure:"check_every"`
	ApprovalTimeout    int    `mapstructure:"approval_timeout"`
}

func newClient(config *openConfig) (*client.SecurosysClient, error) {
	var keyPair client.KeyPair
	if err := json.Unmarshal([]byte(config.ApplicationKeyPair), &keyPair); config.ApplicationKeyPair != "" && err != nil {
		return nil, fmt.Errorf("invalid application_key_pair: %w", err)
	}

	var apiKeys client.ApiKeyTypes
	if err := json.Unmarshal([]byte(config.APIKeys), &apiKeys); config.APIKeys != "" && err != nil {
		return nil, fmt.Errorf("invalid api_keys: %w", err)
	}

	tsbClient, err := client.NewTSBClient(config.RestAPI, client.AuthStruct{
		AuthType:           config.Auth,
		BearerToken:        config.BearerToken,
		CertPEM:            config.CertPEM,
		KeyPEM:             config.KeyPEM,
		ApplicationKeyPair: keyPair,
		ApiKeys:            apiKeys,
		AppName:            "OpenBao - Securosys HSM KMS",
	})
	if err != nil {
		return nil, err
	}
	return &client.SecurosysClient{TSBClient: tsbClient}, nil
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

func validateOpenConfig(config *openConfig) error {
	if config == nil {
		return errors.New("config is required")
	}

	config.RestAPI = strings.TrimSpace(config.RestAPI)
	config.Auth = strings.TrimSpace(strings.ToUpper(config.Auth))
	config.BearerToken = strings.TrimSpace(config.BearerToken)
	config.CertPEM = strings.TrimSpace(config.CertPEM)
	config.KeyPEM = strings.TrimSpace(config.KeyPEM)

	if config.RestAPI == "" {
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
		if config.CertPEM == "" {
			return errors.New("cert_pem is required when auth is CERT")
		}
		if config.KeyPEM == "" {
			return errors.New("key_pem is required when auth is CERT")
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
