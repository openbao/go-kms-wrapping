// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package stackitkms

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/stackitcloud/stackit-sdk-go/core/config"
	"github.com/stackitcloud/stackit-sdk-go/services/kms/v1api"
)

// kmsClient is the subset of the STACKIT KMS API used by the Wrapper
type kmsClient interface {
	encrypt(ctx context.Context, keyId string, version int64, plaintext []byte) ([]byte, error)
	decrypt(ctx context.Context, keyId string, version int64, wrappedKey []byte) ([]byte, error)
	getKey(ctx context.Context, keyId string) (*v1api.Key, error)
	getVersion(ctx context.Context, keyId string, version int64) (*v1api.Version, error)
	listVersions(ctx context.Context, keyId string) ([]v1api.Version, error)
}

type clientConfig struct {
	projectId string
	region    string
	keyRingId string
	endpoint  string

	serviceAccountKey     string
	serviceAccountKeyPath string
	privateKey            string
	privateKeyPath        string
	token                 string
}

// sdkClient implements kmsClient on top of the official STACKIT Go SDK
type sdkClient struct {
	api       v1api.DefaultAPI
	projectId string
	region    string
	keyRingId string
}

var _ kmsClient = (*sdkClient)(nil)

// newSdkClient builds the API client. Credentials not set explicitly are
// resolved by the SDK's default chain (STACKIT_* env vars, credentials file).
func newSdkClient(cc clientConfig) (kmsClient, error) {
	var opts []config.ConfigurationOption
	if cc.endpoint != "" {
		opts = append(opts, config.WithEndpoint(cc.endpoint))
	}
	if cc.serviceAccountKey != "" {
		opts = append(opts, config.WithServiceAccountKey(cc.serviceAccountKey))
	}
	if cc.serviceAccountKeyPath != "" {
		opts = append(opts, config.WithServiceAccountKeyPath(cc.serviceAccountKeyPath))
	}
	if cc.privateKey != "" {
		opts = append(opts, config.WithPrivateKey(cc.privateKey))
	}
	if cc.privateKeyPath != "" {
		opts = append(opts, config.WithPrivateKeyPath(cc.privateKeyPath))
	}
	if cc.token != "" {
		opts = append(opts, config.WithToken(cc.token))
	}

	api, err := v1api.NewAPIClient(opts...)
	if err != nil {
		return nil, err
	}

	return &sdkClient{
		api:       api.DefaultAPI,
		projectId: cc.projectId,
		region:    cc.region,
		keyRingId: cc.keyRingId,
	}, nil
}

// encrypt returns the ciphertext in its base64 transport encoding, treated
// as opaque.
func (c *sdkClient) encrypt(ctx context.Context, keyId string, version int64, plaintext []byte) ([]byte, error) {
	payload := v1api.NewEncryptPayload(base64.StdEncoding.EncodeToString(plaintext))
	resp, err := c.api.Encrypt(ctx, c.projectId, c.region, c.keyRingId, keyId, version).
		EncryptPayload(*payload).Execute()
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("empty response from STACKIT KMS encrypt")
	}
	return []byte(resp.Data), nil
}

func (c *sdkClient) decrypt(ctx context.Context, keyId string, version int64, wrappedKey []byte) ([]byte, error) {
	payload := v1api.NewDecryptPayload(string(wrappedKey))
	resp, err := c.api.Decrypt(ctx, c.projectId, c.region, c.keyRingId, keyId, version).
		DecryptPayload(*payload).Execute()
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("empty response from STACKIT KMS decrypt")
	}
	plaintext, err := base64.StdEncoding.DecodeString(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode STACKIT KMS decrypt response: %w", err)
	}
	return plaintext, nil
}

func (c *sdkClient) getKey(ctx context.Context, keyId string) (*v1api.Key, error) {
	return c.api.GetKey(ctx, c.projectId, c.region, c.keyRingId, keyId).Execute()
}

func (c *sdkClient) getVersion(ctx context.Context, keyId string, version int64) (*v1api.Version, error) {
	return c.api.GetVersion(ctx, c.projectId, c.region, c.keyRingId, keyId, version).Execute()
}

func (c *sdkClient) listVersions(ctx context.Context, keyId string) ([]v1api.Version, error) {
	resp, err := c.api.ListVersions(ctx, c.projectId, c.region, c.keyRingId, keyId).Execute()
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("empty response from STACKIT KMS list versions")
	}
	return resp.Versions, nil
}
