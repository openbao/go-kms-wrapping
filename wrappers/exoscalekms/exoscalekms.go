// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package exoscalekms

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"

	v3 "github.com/exoscale/egoscale/v3"
	"github.com/exoscale/egoscale/v3/credentials"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

const Type wrapping.WrapperType = "exoscalekms"

// These constants contain the accepted env vars
const (
	EnvExoscaleKmsKeyId    = "EXOSCALEKMS_KEY_ID"
	EnvExoscaleKmsZone     = "EXOSCALEKMS_ZONE"
	EnvExoscaleKmsEndpoint = "EXOSCALEKMS_ENDPOINT"
	EnvExoscaleApiKey      = "EXOSCALE_API_KEY"
	EnvExoscaleApiSecret   = "EXOSCALE_API_SECRET"
)

type kmsApi interface {
	Decrypt(ctx context.Context, id v3.UUID, req v3.DecryptRequest) (*v3.DecryptResponse, error)
	Encrypt(ctx context.Context, id v3.UUID, req v3.EncryptRequest) (*v3.EncryptResponse, error)
}

// Wrapper represents credentials and Key information for the KMS Key
type Wrapper struct {
	apiKey    string
	apiSecret string
	zone      string
	endpoint  string

	keyId        string
	currentKeyId *atomic.Value

	client kmsApi
}

var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new ExoscaleKms wrapper
func NewWrapper() *Wrapper {
	k := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	k.currentKeyId.Store("")
	return k
}

// Type returns the wrapping type for this particular Wrapper implementation
func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return Type, nil
}

// KeyId returns the last known key id
func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.currentKeyId.Load().(string), nil
}

func (k *Wrapper) SetConfig(ctx context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	k.keyId = envOrConfig(opts.WithDisallowEnvVars, EnvExoscaleKmsKeyId, opts.WithKeyId)
	if k.keyId == "" {
		return nil, fmt.Errorf("key id not found in env or config for exoscale kms wrapper configuration")
	}
	k.currentKeyId.Store(k.keyId)

	k.zone = envOrConfig(opts.WithDisallowEnvVars, EnvExoscaleKmsZone, opts.withZone)
	k.endpoint = envOrConfig(opts.WithDisallowEnvVars, EnvExoscaleKmsEndpoint, opts.withEndpoint)

	if k.zone == "" && k.endpoint == "" {
		return nil, fmt.Errorf("zone and endpoint not found in env or config for exoscale kms wrapper configuration")
	}

	k.apiKey = envOrConfig(opts.WithDisallowEnvVars, EnvExoscaleApiKey, opts.withApiKey)
	k.apiSecret = envOrConfig(opts.WithDisallowEnvVars, EnvExoscaleApiSecret, opts.withApiSecret)

	if k.apiKey == "" || k.apiSecret == "" {
		return nil, fmt.Errorf("api key or api secret not found in env or config for exoscale kms wrapper configuration")
	}

	if k.client == nil {
		creds := credentials.NewStaticCredentials(k.apiKey, k.apiSecret)
		o := []v3.ClientOpt{v3.ClientOptWithUserAgent("go-kms-wrapping-exoscalekms")}

		if k.endpoint != "" {
			o = append(o, v3.ClientOptWithEndpoint(v3.Endpoint(k.endpoint)))
		}

		client, err := v3.NewClient(creds, o...)
		if err != nil {
			return nil, fmt.Errorf("error initializing exoscale kms wrapping client: %w", err)
		}

		if k.endpoint == "" {
			ep, err := client.GetZoneAPIEndpoint(ctx, v3.ZoneName(k.zone))
			if err != nil {
				return nil, fmt.Errorf("resolving endpoint for zone %q for exoscale wrapper client: %w", k.zone, err)
			}
			client = client.WithEndpoint(ep)
		}

		_, err = client.GetKmsKey(ctx, v3.UUID(k.keyId))
		if err != nil {
			return nil, fmt.Errorf("fetching exoscale kms key %q: %w", k.keyId, err)
		}

		k.client = client
	}

	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["key_id"] = k.keyId
	if k.zone != "" {
		wrapConfig.Metadata["zone"] = k.zone
	}
	if k.endpoint != "" {
		wrapConfig.Metadata["endpoint"] = k.endpoint
	}

	return wrapConfig, nil
}

func (k *Wrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	if k.client == nil {
		return nil, fmt.Errorf("client is nil")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	encReq := v3.EncryptRequest{
		Plaintext: env.Key,
	}
	resp, err := k.client.Encrypt(ctx, v3.UUID(k.keyId), encReq)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	ret := &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			KeyId:      k.keyId,
			WrappedKey: resp.Ciphertext,
		},
	}

	return ret, nil
}

func (k *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil || in.KeyInfo == nil {
		return nil, fmt.Errorf("given input for decryption is nil")
	}

	if k.client == nil {
		return nil, fmt.Errorf("client is nil")
	}

	keyId := in.KeyInfo.KeyId
	if in.KeyInfo.KeyId == "" {
		keyId = k.keyId
	}

	decReq := v3.DecryptRequest{
		Ciphertext: in.KeyInfo.WrappedKey,
	}
	resp, err := k.client.Decrypt(ctx, v3.UUID(keyId), decReq)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data encryption key: %w", err)
	}

	envInfo := &wrapping.EnvelopeInfo{
		Key:        resp.Plaintext,
		Iv:         in.Iv,
		Ciphertext: in.Ciphertext,
	}
	plaintext, err := wrapping.EnvelopeDecrypt(envInfo, opt...)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return plaintext, nil
}

// envOrConfig returns the env var if it is allowed and set, otherwise the config value
func envOrConfig(disallowEnv bool, envVar, configValue string) string {
	if !disallowEnv {
		if v := os.Getenv(envVar); v != "" {
			return v
		}
	}
	return configValue
}
