// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/hashicorp/go-hclog"
	securosyskms "github.com/openbao/go-kms-wrapping/kms/securosyshsm/v2"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/kms"
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

	provider := securosysKMSConfigMap(opts)
	providerKMS := securosyskms.New()
	if err := providerKMS.Open(ctx, &kms.OpenOptions{
		Logger:           logger,
		AllowEnvironment: !opts.WithDisallowEnvVars,
		ConfigMap:        provider,
	}); err != nil {
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
	}

	wrapConfig := &wrapping.WrapperConfig{
		Metadata: map[string]string{
			"tsb_api_endpoint": tsbAPIEndpoint,
			"check_every":      strconv.Itoa(parsePositiveInt(opts.withCheckEvery, 5)),
			"key_label":        keyLabel,
			"auth":             auth,
			"approval_timeout": strconv.Itoa(parsePositiveInt(opts.withApprovalTimeout, 600)),
		},
	}

	return client, wrapConfig, nil
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

// securosysKMSConfigMap routes wrapper configuration directly into
// kms/securosyshsm, applying only the wrapper-to-KMS key remaps.
func securosysKMSConfigMap(opts *options) kms.ConfigMap {
	provider := kms.ConfigMap{
		"rest_api": opts.withTSBApiEndpoint,
	}

	if opts.withAuth != "" {
		provider["auth"] = opts.withAuth
	}
	if opts.withBearerToken != "" {
		provider["bearer_token"] = opts.withBearerToken
	}
	if opts.withCertPath != "" {
		provider["cert_path"] = opts.withCertPath
	}
	if opts.withKeyPath != "" {
		provider["key_path"] = opts.withKeyPath
	}
	if opts.withCheckEvery != "" {
		provider["check_every"] = opts.withCheckEvery
	}
	if opts.withApprovalTimeout != "" {
		provider["approval_timeout"] = opts.withApprovalTimeout
	}
	if opts.withApplicationKeyPair != "" {
		provider["application_key_pair"] = opts.withApplicationKeyPair
	}
	if opts.withApiKeys != "" {
		provider["api_keys"] = opts.withApiKeys
	}

	return provider
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
