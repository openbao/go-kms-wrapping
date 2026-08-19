// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package stackitkms

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/stackitcloud/stackit-sdk-go/core/clients"
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

	disallowEnvVars bool
}

// sdkClient implements kmsClient on top of the official STACKIT Go SDK
type sdkClient struct {
	api       v1api.DefaultAPI
	projectId string
	region    string
	keyRingId string
}

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

	if cc.disallowEnvVars {
		switch {
		case cc.serviceAccountKeyPath != "" || cc.privateKeyPath != "":
			return nil, fmt.Errorf("'service_account_key_path' and 'private_key_path' cannot be used when environment access is disallowed")
		case cc.serviceAccountKey != "":
			// KeyAuth/getPrivateKey in the SDK consult the environment and
			// the credentials file before the key embedded in the service
			// account key, so resolve the embedded key up front:
			// https://github.com/stackitcloud/stackit-sdk-go/blob/core/v0.26.0/core/auth/auth.go#L344-L385
			if cc.privateKey == "" {
				privateKey, err := embeddedPrivateKey(cc.serviceAccountKey)
				if err != nil {
					return nil, err
				}
				opts = append(opts, config.WithPrivateKey(privateKey))
			}
		case cc.token != "":
			// token flow, used as-is
		default:
			return nil, fmt.Errorf("'service_account_key' or 'token' must be configured explicitly when environment access is disallowed")
		}
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
		return nil, fmt.Errorf("empty response from encrypt")
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
		return nil, fmt.Errorf("empty response from decrypt")
	}
	plaintext, err := base64.StdEncoding.DecodeString(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode decrypt response: %w", err)
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
		return nil, fmt.Errorf("empty response from list versions")
	}
	return resp.Versions, nil
}

// embeddedPrivateKey returns the private key embedded in a service account
// key, mirroring the SDK's own last-resort extraction:
// https://github.com/stackitcloud/stackit-sdk-go/blob/core/v0.26.0/core/auth/auth.go#L193-L206
func embeddedPrivateKey(saKey string) (string, error) {
	var parsed clients.ServiceAccountKeyResponse
	if err := json.Unmarshal([]byte(saKey), &parsed); err != nil {
		return "", fmt.Errorf("failed to parse service account key: %w", err)
	}
	if parsed.Credentials == nil || parsed.Credentials.PrivateKey == nil || *parsed.Credentials.PrivateKey == "" {
		return "", fmt.Errorf("service account key contains no private key; configure 'private_key' explicitly when environment access is disallowed")
	}
	return *parsed.Credentials.PrivateKey, nil
}
