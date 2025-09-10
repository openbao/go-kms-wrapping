// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package nhncloudskm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

const (
	// Environment variable names
	EnvNHNCloudSKMEndpoint            = "NHN_CLOUD_SKM_ENDPOINT"
	EnvNHNCloudSKMAppKey              = "NHN_CLOUD_SKM_APP_KEY"
	EnvNHNCloudSKMKeyID               = "NHN_CLOUD_SKM_KEY_ID"
	EnvNHNCloudSKMUserAccessKeyID     = "NHN_CLOUD_SKM_USER_ACCESS_KEY_ID"
	EnvNHNCloudSKMUserSecretAccessKey = "NHN_CLOUD_SKM_USER_SECRET_ACCESS_KEY"
	EnvNHNCloudSKMMACAddress          = "NHN_CLOUD_SKM_MAC_ADDRESS"

	// Default values
	DefaultNHNCloudSKMEndpoint = "https://api-keymanager.nhncloudservice.com"
	DefaultTimeout             = 30 * time.Second
)

const (
	// NHNCloudSKMEncrypt is used to directly encrypt the data with SKM
	NHNCloudSKMEncrypt = iota
	// NHNCloudSKMEnvelopeAesGcmEncrypt is when a data encryption key is generated and
	// the data is encrypted with AES-GCM and the key is encrypted with SKM
	NHNCloudSKMEnvelopeAesGcmEncrypt
)

// API request/response structures
type encryptRequest struct {
	Plaintext string `json:"plaintext"`
}

type encryptResponse struct {
	Header struct {
		ResultCode    int    `json:"resultCode"`
		ResultMessage string `json:"resultMessage"`
		IsSuccessful  bool   `json:"isSuccessful"`
	} `json:"header"`
	Body struct {
		Ciphertext string `json:"ciphertext"`
		KeyVersion int    `json:"keyVersion"`
	} `json:"body"`
}

type decryptRequest struct {
	Ciphertext string `json:"ciphertext"`
}

type decryptResponse struct {
	Header struct {
		ResultCode    int    `json:"resultCode"`
		ResultMessage string `json:"resultMessage"`
		IsSuccessful  bool   `json:"isSuccessful"`
	} `json:"header"`
	Body struct {
		Plaintext string `json:"plaintext"`
	} `json:"body"`
}

// Wrapper implements the go-kms-wrapping interface for NHN Cloud SKM seal/unseal operations
type Wrapper struct {
	// Configuration
	endpoint            string
	appKey              string
	keyID               string
	userAccessKeyID     string
	userSecretAccessKey string
	macAddress          string

	// Current key ID for rotation support
	currentKeyId *atomic.Value

	// HTTP client
	client *http.Client

	// Options
	disallowEnvVars bool
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new NHN Cloud SKM wrapper
func NewWrapper() *Wrapper {
	w := &Wrapper{
		currentKeyId: new(atomic.Value),
		client: &http.Client{
			Timeout: DefaultTimeout,
		},
	}
	w.currentKeyId.Store("")
	return w
}

// Type returns the wrapper type
func (w *Wrapper) Type(context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeNHNCloudSkm, nil
}

// KeyId returns the last known key id
func (w *Wrapper) KeyId(context.Context) (string, error) {
	keyId := w.currentKeyId.Load().(string)
	if keyId == "" {
		return "", fmt.Errorf("key ID not configured")
	}
	return keyId, nil
}

// SetConfig configures the wrapper
func (w *Wrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	w.disallowEnvVars = opts.WithDisallowEnvVars

	// Set from options first
	if opts.WithConfigMap != nil {
		if v, ok := opts.WithConfigMap["endpoint"]; ok {
			w.endpoint = v
		}
		if v, ok := opts.WithConfigMap["app_key"]; ok {
			w.appKey = v
		}
		if v, ok := opts.WithConfigMap["key_id"]; ok {
			w.keyID = v
		}
		if v, ok := opts.WithConfigMap["user_access_key_id"]; ok {
			w.userAccessKeyID = v
		}
		if v, ok := opts.WithConfigMap["user_secret_access_key"]; ok {
			w.userSecretAccessKey = v
		}
		if v, ok := opts.WithConfigMap["mac_address"]; ok {
			w.macAddress = v
		}
	}

	// Set from dedicated options
	if opts.withEndpoint != "" {
		w.endpoint = opts.withEndpoint
	}
	if opts.withAppKey != "" {
		w.appKey = opts.withAppKey
	}
	if opts.withUserAccessKeyID != "" {
		w.userAccessKeyID = opts.withUserAccessKeyID
	}
	if opts.withUserSecretAccessKey != "" {
		w.userSecretAccessKey = opts.withUserSecretAccessKey
	}
	if opts.withMACAddress != "" {
		w.macAddress = opts.withMACAddress
	}

	// Set key ID from generic option
	if opts.WithKeyId != "" {
		w.keyID = opts.WithKeyId
	}

	// Load from environment variables if not set and not disabled
	if !w.disallowEnvVars {
		w.loadFromEnv()
	}

	// Set defaults
	if w.endpoint == "" {
		w.endpoint = DefaultNHNCloudSKMEndpoint
	}

	// Store the current key id
	w.currentKeyId.Store(w.keyID)

	// Validate required fields
	if w.appKey == "" {
		return nil, fmt.Errorf("app key is required")
	}
	if w.keyID == "" {
		return nil, fmt.Errorf("key ID is required")
	}
	if w.userAccessKeyID == "" {
		return nil, fmt.Errorf("user access key ID is required")
	}
	if w.userSecretAccessKey == "" {
		return nil, fmt.Errorf("user secret access key is required")
	}

	// Parse paths for potential file references
	if err := wrapping.ParsePaths(&w.userSecretAccessKey); err != nil {
		return nil, fmt.Errorf("error parsing secret key path: %w", err)
	}

	return &wrapping.WrapperConfig{
		Metadata: map[string]string{
			"endpoint":               w.endpoint,
			"app_key":                w.appKey,
			"key_id":                 w.keyID,
			"user_access_key_id":     w.userAccessKeyID,
			"user_secret_access_key": w.userSecretAccessKey,
			"mac_address":            w.macAddress,
		},
	}, nil
}

// Encrypt encrypts the given data using NHN Cloud SKM
func (w *Wrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext is empty")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	req := encryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(env.Key),
	}

	// Call encrypt API
	resp, err := w.callEncryptAPI(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	if !resp.Header.IsSuccessful {
		return nil, fmt.Errorf("encryption API failed: %s (code: %d)", resp.Header.ResultMessage, resp.Header.ResultCode)
	}

	return &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			Mechanism:  NHNCloudSKMEnvelopeAesGcmEncrypt,
			KeyId:      w.keyID,
			WrappedKey: []byte(resp.Body.Ciphertext),
		},
	}, nil
}

// Decrypt decrypts the given data using NHN Cloud SKM
func (w *Wrapper) Decrypt(ctx context.Context, cipherInfo *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if cipherInfo == nil {
		return nil, fmt.Errorf("cipherInfo is nil")
	}

	// Default to mechanism used before key info was stored
	if cipherInfo.KeyInfo == nil {
		cipherInfo.KeyInfo = &wrapping.KeyInfo{
			Mechanism: NHNCloudSKMEncrypt,
		}
	}

	keyID := w.keyID

	var plaintext []byte
	switch cipherInfo.KeyInfo.Mechanism {
	case NHNCloudSKMEncrypt:
		// Direct decryption (legacy mode)
		if len(cipherInfo.Ciphertext) == 0 {
			return nil, fmt.Errorf("ciphertext is empty")
		}

		// Create request
		req := decryptRequest{
			Ciphertext: string(cipherInfo.Ciphertext),
		}

		// Call decrypt API
		resp, err := w.callDecryptAPI(ctx, keyID, req)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: %w", err)
		}

		if !resp.Header.IsSuccessful {
			return nil, fmt.Errorf("decryption API failed: %s (code: %d)", resp.Header.ResultMessage, resp.Header.ResultCode)
		}

		plaintext = []byte(resp.Body.Plaintext)

	case NHNCloudSKMEnvelopeAesGcmEncrypt:
		if len(cipherInfo.KeyInfo.WrappedKey) == 0 {
			return nil, fmt.Errorf("wrapped key is empty")
		}

		req := decryptRequest{
			Ciphertext: string(cipherInfo.KeyInfo.WrappedKey),
		}

		resp, err := w.callDecryptAPI(ctx, keyID, req)
		if err != nil {
			return nil, fmt.Errorf("key decryption failed: %w", err)
		}

		if !resp.Header.IsSuccessful {
			return nil, fmt.Errorf("key decryption API failed: %s (code: %d)", resp.Header.ResultMessage, resp.Header.ResultCode)
		}

		decryptedKey, err := base64.StdEncoding.DecodeString(resp.Body.Plaintext)

		if err != nil {
			return nil, fmt.Errorf("failed to decode decrypted key: %w", err)
		}

		envInfo := &wrapping.EnvelopeInfo{
			Key:        decryptedKey,
			Iv:         cipherInfo.Iv,
			Ciphertext: cipherInfo.Ciphertext,
		}
		plaintext, err = wrapping.EnvelopeDecrypt(envInfo, opt...)
		if err != nil {
			return nil, fmt.Errorf("error decrypting data: %w", err)
		}

	default:
		return nil, fmt.Errorf("invalid mechanism: %d", cipherInfo.KeyInfo.Mechanism)
	}

	return plaintext, nil
}

// loadFromEnv loads configuration from environment variables
func (w *Wrapper) loadFromEnv() {
	if w.endpoint == "" {
		w.endpoint = os.Getenv(EnvNHNCloudSKMEndpoint)
	}
	if w.appKey == "" {
		w.appKey = os.Getenv(EnvNHNCloudSKMAppKey)
	}
	if w.keyID == "" {
		w.keyID = os.Getenv(EnvNHNCloudSKMKeyID)
	}
	if w.userAccessKeyID == "" {
		w.userAccessKeyID = os.Getenv(EnvNHNCloudSKMUserAccessKeyID)
	}
	if w.userSecretAccessKey == "" {
		w.userSecretAccessKey = os.Getenv(EnvNHNCloudSKMUserSecretAccessKey)
	}
	if w.macAddress == "" {
		w.macAddress = os.Getenv(EnvNHNCloudSKMMACAddress)
	}
}

// callEncryptAPI calls the NHN Cloud SKM encrypt API
func (w *Wrapper) callEncryptAPI(ctx context.Context, req encryptRequest) (*encryptResponse, error) {
	url := fmt.Sprintf("%s/keymanager/v1.2/appkey/%s/symmetric-keys/%s/encrypt",
		strings.TrimSuffix(w.endpoint, "/"), w.appKey, w.keyID)

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-TC-AUTHENTICATION-ID", w.userAccessKeyID)
	httpReq.Header.Set("X-TC-AUTHENTICATION-SECRET", w.userSecretAccessKey)
	if w.macAddress != "" {
		httpReq.Header.Set("X-TOAST-CLIENT-MAC-ADDR", w.macAddress)
	}

	resp, err := w.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var encResp encryptResponse
	if err := json.Unmarshal(body, &encResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &encResp, nil
}

// callDecryptAPI calls the NHN Cloud SKM decrypt API
func (w *Wrapper) callDecryptAPI(ctx context.Context, keyID string, req decryptRequest) (*decryptResponse, error) {
	url := fmt.Sprintf("%s/keymanager/v1.2/appkey/%s/symmetric-keys/%s/decrypt",
		strings.TrimSuffix(w.endpoint, "/"), w.appKey, keyID)

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-TC-AUTHENTICATION-ID", w.userAccessKeyID)
	httpReq.Header.Set("X-TC-AUTHENTICATION-SECRET", w.userSecretAccessKey)
	if w.macAddress != "" {
		httpReq.Header.Set("X-TOAST-CLIENT-MAC-ADDR", w.macAddress)
	}

	resp, err := w.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var decResp decryptResponse
	if err := json.Unmarshal(body, &decResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &decResp, nil
}

// Init performs any necessary initialization
func (w *Wrapper) Init(context.Context, ...wrapping.Option) error {
	// No special initialization needed
	return nil
}

// Finalize performs cleanup
func (w *Wrapper) Finalize(context.Context, ...wrapping.Option) error {
	// No cleanup needed
	return nil
}
