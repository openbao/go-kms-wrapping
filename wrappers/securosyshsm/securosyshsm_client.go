// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/hashicorp/go-hclog"
	securosyskms "github.com/openbao/go-kms-wrapping/kms/securosyshsm/v2"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

const (
	EnvAdditionalAuthenticationData = "SECUROSYSHSM_ADDITIONAL_AUTHENTICATION_DATA"
	EnvTagLength                    = "SECUROSYSHSM_TAG_LENGTH"
	EnvCipherAlgorithm              = "SECUROSYSHSM_CIPHER_ALGORITHM"
)

type securosysHSMClientEncryptor interface {
	Close()
	Encrypt(ctx context.Context, plaintext string) (data []byte, err error)
	Decrypt(ctx context.Context, ciphertext string, keyVersion string) (plaintext []byte, err error)
}

// SecurosysHSMClient adapts the Securosys KMS implementation to the
// go-kms-wrapping Wrapper interface.
//
// The wrapper uses the new kms.KMS/kms.Key API directly. The configured key is
// loaded once during SetConfig and then reused for seal Encrypt/Decrypt calls.
type SecurosysHSMClient struct {
	kms      kms.KMS
	key      kms.Key
	keyLabel string
	config   *Configurations
}

func (c *SecurosysHSMClient) Close() {
	if c == nil {
		return
	}
	if c.key != nil {
		if err := c.key.Close(context.Background()); err != nil {
			logger.Error(err.Error())
		}
	}
	if c.kms != nil {
		if err := c.kms.Close(context.Background()); err != nil {
			logger.Error(err.Error())
		}
	}
}

// newSecurosysHSMClient validates wrapper options, opens the Securosys KMS,
// and resolves the configured key label.
func newSecurosysHSMClient(ctx context.Context, logger hclog.Logger, opts *options) (*SecurosysHSMClient, *wrapping.WrapperConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	keyLabel := opts.withKeyLabel
	if keyLabel == "" {
		return nil, nil, fmt.Errorf("key_label is required")
	}

	auth := opts.withAuth
	if auth == "" {
		return nil, nil, fmt.Errorf("auth is required")
	}

	tsbAPIEndpoint := opts.withTSBApiEndpoint
	if tsbAPIEndpoint == "" {
		return nil, nil, fmt.Errorf("tsb_api_endpoint is required")
	}

	wrapperConfig, err := buildWrapperConfigurations(opts)
	if err != nil {
		return nil, nil, err
	}
	configuration = wrapperConfig

	if !wrapperConfig.checkConfigFile() {
		return nil, nil, fmt.Errorf("securosys hsm wrapper configuration is invalid")
	}

	provider := securosysKMSConfigMap(wrapperConfig)
	providerKMS := securosyskms.New()
	if err := providerKMS.Open(ctx, &kms.OpenOptions{Logger: logger, ConfigMap: provider}); err != nil {
		return nil, nil, err
	}

	key, err := providerKMS.GetKey(ctx, &kms.KeyOptions{
		ConfigMap: kms.ConfigMap{
			"name":     keyLabel,
			"password": opts.withKeyPassword,
		},
	})
	if err != nil {
		_ = providerKMS.Close(ctx)
		return nil, nil, err
	}

	client := &SecurosysHSMClient{
		kms:      providerKMS,
		key:      key,
		keyLabel: keyLabel,
		config:   wrapperConfig,
	}

	wrapConfig := &wrapping.WrapperConfig{
		Metadata: map[string]string{
			"tsb_api_endpoint": tsbAPIEndpoint,
			"check_every":      strconv.Itoa(wrapperConfig.Settings.CheckEvery),
			"key_label":        keyLabel,
			"auth":             auth,
			"approval_timeout": strconv.Itoa(wrapperConfig.Settings.ApprovalTimeout),
		},
	}

	return client, wrapConfig, nil
}

// buildWrapperConfigurations converts wrapper options into the legacy
// Configurations structure still used for validation and metadata.
func buildWrapperConfigurations(opts *options) (*Configurations, error) {
	wrapperConfig := new(Configurations)

	checkEvery := parsePositiveInt(opts.withCheckEvery, 5)
	approvalTimeout := parsePositiveInt(opts.withApprovalTimeout, 600)

	var keyPair KeyPair
	if opts.withApplicationKeyPair != "" {
		if err := json.Unmarshal([]byte(opts.withApplicationKeyPair), &keyPair); err != nil {
			return nil, fmt.Errorf("application_key_pair is invalid: %w", err)
		}
	}

	var apiKeys ApiKeyTypes
	if opts.withApiKeys != "" {
		if err := json.Unmarshal([]byte(opts.withApiKeys), &apiKeys); err != nil {
			return nil, fmt.Errorf("api_keys is invalid: %w", err)
		}
	}

	wrapperConfig.Settings.RestApi = opts.withTSBApiEndpoint
	wrapperConfig.Settings.Auth = opts.withAuth
	wrapperConfig.Settings.BearerToken = opts.withBearerToken
	wrapperConfig.Settings.CertPath = opts.withCertPath
	wrapperConfig.Settings.KeyPath = opts.withKeyPath
	wrapperConfig.Settings.CheckEvery = checkEvery
	wrapperConfig.Settings.ApprovalTimeout = approvalTimeout
	wrapperConfig.Settings.ApplicationKeyPair = keyPair
	wrapperConfig.Settings.ApiKeys = apiKeys
	wrapperConfig.Key.RSALabel = opts.withKeyLabel
	wrapperConfig.Key.RSAPassword = opts.withKeyPassword

	return wrapperConfig, nil
}

// parsePositiveInt returns defaultValue when value is empty, invalid, or not
// positive.
func parsePositiveInt(value string, defaultValue int) int {
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return defaultValue
	}
	return parsed
}

// securosysKMSConfigMap converts wrapper configuration into kms.OpenOptions
// data accepted by kms/securosyshsm.
func securosysKMSConfigMap(config *Configurations) kms.ConfigMap {
	applicationKeyPair, _ := json.Marshal(config.Settings.ApplicationKeyPair)
	apiKeys, _ := json.Marshal(config.Settings.ApiKeys)

	return kms.ConfigMap{
		"rest_api":             config.Settings.RestApi,
		"auth":                 config.Settings.Auth,
		"bearer_token":         config.Settings.BearerToken,
		"cert_path":            config.Settings.CertPath,
		"key_path":             config.Settings.KeyPath,
		"check_every":          config.Settings.CheckEvery,
		"approval_timeout":     config.Settings.ApprovalTimeout,
		"application_key_pair": string(applicationKeyPair),
		"api_keys":             string(apiKeys),
	}
}

// Encrypt encrypts a base64-encoded wrapper plaintext with the configured KMS
// key.
func (c *SecurosysHSMClient) Encrypt(ctx context.Context, plaintext string) ([]byte, error) {
	if c == nil || c.key == nil {
		return nil, fmt.Errorf("securosys hsm key is not configured")
	}

	opts := &kms.CipherOptions{Data: []byte(plaintext)}
	encrypted, err := c.key.Encrypt(ctx, opts)
	if err != nil {
		return nil, err
	}

	encryptedBase64 := base64.StdEncoding.EncodeToString(encrypted)
	nonceBase64 := base64.StdEncoding.EncodeToString(opts.Nonce)
	return []byte(fmt.Sprintf("securosys:%s:%s:%s", c.keyLabel, nonceBase64, encryptedBase64)), nil
}

// Decrypt decrypts the base64 ciphertext component produced by Encrypt.
func (c *SecurosysHSMClient) Decrypt(ctx context.Context, encryptedPayload string, keyVersion string) ([]byte, error) {
	if c == nil || c.key == nil {
		return nil, fmt.Errorf("securosys hsm key is not configured")
	}

	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedPayload)
	if err != nil {
		return nil, err
	}

	var nonce []byte
	if keyVersion != "" {
		nonce, err = base64.StdEncoding.DecodeString(keyVersion)
		if err != nil {
			return nil, err
		}
	}

	return c.key.Decrypt(ctx, &kms.CipherOptions{
		Data:  encryptedBytes,
		Nonce: nonce,
	})
}
