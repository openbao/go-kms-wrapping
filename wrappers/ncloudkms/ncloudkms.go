// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package ncloudkms

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
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

const Type wrapping.WrapperType = "ncloudkms"

// ref. https://api.ncloud-docs.com/docs/en/security-kms
const defaultDomain = "kms.apigw.ntruss.com"

const (
	EnvNcloudKmsWrapperKeyTag = "NCLOUDKMS_WRAPPER_KEY_TAG"
	EnvNcpAccessKey           = "NCP_ACCESS_KEY"
	EnvNcpSecretKey           = "NCP_SECRET_KEY"
)

type Wrapper struct {
	domain        string
	keyTag        string
	currentKeyTag *atomic.Value
	client        *kmsClient
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new Ncloud Wrapper.
func NewWrapper() *Wrapper {
	k := &Wrapper{
		currentKeyTag: new(atomic.Value),
	}
	k.currentKeyTag.Store("")
	return k
}

// SetConfig sets the fields on the Wrapper object based on values from the
// config parameter.
//
// Order of precedence for Ncloud values:
// * Environment variable
// * Value from configuration file / config map
func (k *Wrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	// Check and set the key tag
	switch {
	case os.Getenv(EnvNcloudKmsWrapperKeyTag) != "" && !opts.Options.WithDisallowEnvVars:
		k.keyTag = os.Getenv(EnvNcloudKmsWrapperKeyTag)
	case opts.withKeyTag != "":
		k.keyTag = opts.withKeyTag
	default:
		return nil, fmt.Errorf("key tag not found (env or config) for ncloud kms wrapper configuration")
	}

	// A domain config is optional.
	domain := opts.withDomain
	if domain == "" {
		domain = defaultDomain
	}
	k.domain = domain

	// Resolve credentials: config takes precedence, then the standard NCP
	// account environment variables.
	accessKey := opts.withAccessKey
	secretKey := opts.withSecretKey
	if !opts.Options.WithDisallowEnvVars {
		if accessKey == "" {
			accessKey = os.Getenv(EnvNcpAccessKey)
		}
		if secretKey == "" {
			secretKey = os.Getenv(EnvNcpSecretKey)
		}
	}
	if accessKey == "" || secretKey == "" {
		return nil, fmt.Errorf("access key and secret key are required (env %s/%s or config) for ncloud kms wrapper configuration", EnvNcpAccessKey, EnvNcpSecretKey)
	}

	k.client = newKMSClient(domain, accessKey, secretKey)

	// Store the current key tag.
	k.currentKeyTag.Store(k.keyTag)

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["domain"] = k.domain
	wrapConfig.Metadata["key_tag"] = k.keyTag

	return wrapConfig, nil
}

// Type returns the type for this particular wrapper implementation.
func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return Type, nil
}

// KeyId returns the last known key tag. The method name is fixed by the
// wrapping.Wrapper interface; the value returned is the NCP KMS key tag.
func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.currentKeyTag.Load().(string), nil
}

// Encrypt is used to encrypt the master key using the Ncloud CMK. This returns
// the ciphertext, and/or any errors from this call. This should be called after
// the KMS client has been instantiated.
func (k *Wrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	ciphertext, err := k.client.encrypt(ctx, k.keyTag, base64.StdEncoding.EncodeToString(env.Key))
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	// Store the current key tag.
	k.currentKeyTag.Store(k.keyTag)

	return &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			KeyId:      k.keyTag,
			WrappedKey: []byte(ciphertext),
		},
	}, nil
}

// Decrypt is used to decrypt the ciphertext. This should be called after Init.
func (k *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, fmt.Errorf("given input for decryption is nil")
	}
	if in.KeyInfo == nil {
		return nil, fmt.Errorf("given input for decryption is missing key info")
	}

	// Prefer the key tag recorded at encryption time so the blob decrypts with
	// the key that wrapped it; fall back to the configured key tag for inputs
	// that don't carry one.
	keyTag := in.KeyInfo.KeyId
	if keyTag == "" {
		keyTag = k.keyTag
	}

	plaintextB64, err := k.client.decrypt(ctx, keyTag, string(in.KeyInfo.WrappedKey))
	if err != nil {
		return nil, fmt.Errorf("error decrypting data encryption key: %w", err)
	}

	keyBytes, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return nil, fmt.Errorf("error decoding decrypted data encryption key: %w", err)
	}

	envInfo := &wrapping.EnvelopeInfo{
		Key:        keyBytes,
		Iv:         in.Iv,
		Ciphertext: in.Ciphertext,
	}
	plaintext, err := wrapping.EnvelopeDecrypt(envInfo, opt...)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return plaintext, nil
}

// kmsClient talks to the Naver Cloud KMS API 1.0 endpoints
// ref. https://api.ncloud-docs.com/docs/en/security-kms
// (https://{domain}/keys/v2/{keyTag}/{encrypt,decrypt}) using the standard
// ncp-apigw-signature-v2 (HMAC-SHA256) request signing.
type kmsClient struct {
	httpClient *http.Client
	domain     string
	accessKey  string
	secretKey  string
}

func newKMSClient(domain, accessKey, secretKey string) *kmsClient {
	return &kmsClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		domain:     domain,
		accessKey:  accessKey,
		secretKey:  secretKey,
	}
}

type encryptResponse struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Ciphertext string `json:"ciphertext"`
	} `json:"data"`
	Error *struct {
		ErrorCode string `json:"errorCode"`
		Message   string `json:"message"`
		Details   string `json:"details"`
	} `json:"error"`
}

type decryptResponse struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Plaintext string `json:"plaintext"`
	} `json:"data"`
	Error *struct {
		ErrorCode string `json:"errorCode"`
		Message   string `json:"message"`
		Details   string `json:"details"`
	} `json:"error"`
}

func (c *kmsClient) encrypt(ctx context.Context, keyTag, plaintextB64 string) (string, error) {
	raw, status, err := c.doRequest(ctx, keyTag, "encrypt", map[string]string{"plaintext": plaintextB64})
	if err != nil {
		return "", err
	}

	var resp encryptResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", fmt.Errorf("error parsing ncloud kms encrypt response (status %d): %w; body: %s", status, err, snippet(raw))
	}
	if resp.Error != nil {
		return "", fmt.Errorf("ncloud kms encrypt error (status %d, code=%q): %s [errorCode=%s, details=%s]",
			status, resp.Code, resp.Error.Message, resp.Error.ErrorCode, resp.Error.Details)
	}
	if resp.Code != "SUCCESS" {
		return "", fmt.Errorf("ncloud kms encrypt error (status %d, code=%q, msg=%q); body: %s",
			status, resp.Code, resp.Msg, snippet(raw))
	}

	return resp.Data.Ciphertext, nil
}

func (c *kmsClient) decrypt(ctx context.Context, keyTag, ciphertext string) (string, error) {
	raw, status, err := c.doRequest(ctx, keyTag, "decrypt", map[string]string{"ciphertext": ciphertext})
	if err != nil {
		return "", err
	}

	var resp decryptResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", fmt.Errorf("error parsing ncloud kms decrypt response (status %d): %w; body: %s", status, err, snippet(raw))
	}
	if resp.Error != nil {
		return "", fmt.Errorf("ncloud kms decrypt error (status %d, code=%q): %s [errorCode=%s, details=%s]",
			status, resp.Code, resp.Error.Message, resp.Error.ErrorCode, resp.Error.Details)
	}
	if resp.Code != "SUCCESS" {
		return "", fmt.Errorf("ncloud kms decrypt error (status %d, code=%q, msg=%q); body: %s",
			status, resp.Code, resp.Msg, snippet(raw))
	}

	return resp.Data.Plaintext, nil
}

// doRequest performs a signed POST against the given KMS operation for keyTag and
// returns the raw response body together with the HTTP status code.
func (c *kmsClient) doRequest(ctx context.Context, keyTag, operation string, body map[string]string) ([]byte, int, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}

	// keyTag is NCP's identifier for the KMS key; it goes directly into the URL path.
	path := fmt.Sprintf("/keys/v2/%s/%s", keyTag, operation)
	reqURL := "https://" + c.domain + path

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, err
	}

	timestamp := time.Now()
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("x-ncp-apigw-timestamp", fmt.Sprint(timestamp.UnixMilli()))
	req.Header.Set("x-ncp-iam-access-key", c.accessKey)
	req.Header.Set("x-ncp-apigw-signature-v2", createNaverSignature(http.MethodPost, path, timestamp, c.accessKey, c.secretKey))

	httpResp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer httpResp.Body.Close()

	raw, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, httpResp.StatusCode, fmt.Errorf("error reading response body: %w", err)
	}

	return raw, httpResp.StatusCode, nil
}

// snippet returns a bounded, printable view of a response body for inclusion in
// error messages, so failures stay debuggable without dumping unbounded output.
func snippet(b []byte) string {
	const max = 512
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + "…(truncated)"
	}
	return s
}

// createNaverSignature builds the x-ncp-apigw-signature-v2 value
// ref. https://api.ncloud-docs.com/docs/en/common-ncpapi#request
func createNaverSignature(method, uri string, timestamp time.Time, accessKey, secretKey string) string {
	message := fmt.Sprintf("%s %s\n%d\n%s", method, uri, timestamp.UnixMilli(), accessKey)
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
