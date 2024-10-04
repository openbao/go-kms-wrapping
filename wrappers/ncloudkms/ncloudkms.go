// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ncloudkms

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	ncloudconst "github.com/NaverCloudPlatform/ncp-iam-authenticator/pkg/constants"
	ncloudcred "github.com/NaverCloudPlatform/ncp-iam-authenticator/pkg/credentials"

	"github.com/go-resty/resty/v2"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	context "golang.org/x/net/context"
)

// These constants contain the accepted env vars; the Vault one is for backwards compat
const (
	EnvNcloudKmsWrapperKeyId   = "NCLOUDKMS_WRAPPER_KEY_ID"
	EnvVaultNcloudKmsSealKeyId = "VAULT_NCLOUDKMS_SEAL_KEY_ID"
)

// Wrapper is a Wrapper that uses Ncloud's KMS
type Wrapper struct {
	domain       string
	keyId        string
	currentKeyId *atomic.Value
	client       kmsClient
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new Ncloud Wrapper
func NewWrapper() *Wrapper {
	k := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	k.currentKeyId.Store("")
	return k
}

// SetConfig sets the fields on the NcloudKMSWrapper object based on
// values from the config parameter.
//
// Order of precedence Ncloud values:
// * Environment variable
// * Value from Vault configuration file
// * Instance metadata role (access key and secret key)
func (k *Wrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	// Check and set KeyId
	switch {
	case os.Getenv(EnvNcloudKmsWrapperKeyId) != "" && !opts.Options.WithDisallowEnvVars:
		k.keyId = os.Getenv(EnvNcloudKmsWrapperKeyId)
	case os.Getenv(EnvVaultNcloudKmsSealKeyId) != "" && !opts.Options.WithDisallowEnvVars:
		k.keyId = os.Getenv(EnvVaultNcloudKmsSealKeyId)
	case opts.WithKeyId != "":
		k.keyId = opts.WithKeyId
	default:
		return nil, fmt.Errorf("key id not found (env or config) for ncloud kms wrapper configuration")
	}

	// A domain isn't required, but it can be used to override the endpoint
	// returned by the region. An example value for a domain would be:
	// "kms.apigw.ntruss.com".
	var apiGwUrl string
	domain := opts.withDomain
	if !opts.Options.WithDisallowEnvVars {
		apiGwUrl = os.Getenv(ncloudconst.ApiGwUrlEnv)
		if apiGwUrl != "" {
			u, err := url.Parse(apiGwUrl)
			if err != nil {
				return nil, fmt.Errorf("error parsing api gateway url: %w", err)
			}
			domain = u.Host
		}
	}
	if domain == "" {
		domain = "kms.apigw.ntruss.com"
	}

	apiGwUrl = "https://" + domain
	if !opts.Options.WithDisallowEnvVars {
		if apiGwUrl == "" {
			_apiGwUrl := os.Getenv(ncloudconst.ApiGwUrlEnv)
			if _apiGwUrl != "" {
				apiGwUrl = _apiGwUrl
			}
		}
		if apiGwUrl == "" {
			apiGwUrl = "https://kms.apigw.ntruss.com"
		}
	}

	var accessKey = opts.withAccessKey
	var secretKey = opts.withSecretKey
	// Check and set access key.
	if !opts.Options.WithDisallowEnvVars {
		os.Setenv(ncloudconst.ApiGwUrlEnv, apiGwUrl)
		cfg := ncloudcred.NewCredentialFromEnv()
		if cfg != nil && cfg.Valid() {
			if accessKey == "" {
				accessKey = cfg.AccessKey
			}
			if secretKey == "" {
				secretKey = cfg.SecretKey
			}
		}
	}

	if k.client == nil {
		client, err := newKMSClient(accessKey, secretKey, domain)
		if err != nil {
			return nil, err
		}
		k.client = client
	}

	// Store the current key id. If using a key alias, this will point to the actual
	// unique key that that was used for this encrypt operation.
	k.currentKeyId.Store(k.keyId)

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	if k.domain != "" {
		wrapConfig.Metadata["domain"] = k.domain
	}
	wrapConfig.Metadata["kms_key_id"] = k.keyId

	return wrapConfig, nil
}

// Type returns the type for this particular wrapper implementation
func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeNcloudKms, nil
}

// KeyId returns the last known key id
func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.currentKeyId.Load().(string), nil
}

// Encrypt is used to encrypt the master key using the the Ncloud CMK.
// This returns the ciphertext, and/or any errors from this
// call. This should be called after the KMS client has been instantiated.
func (k *Wrapper) Encrypt(_ context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	output, err := k.client.encrypt(k.keyId, base64.StdEncoding.EncodeToString(env.Key))
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	// Store the current key id.
	keyId := output.KeyId
	k.currentKeyId.Store(keyId)

	ret := &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			KeyId:      keyId,
			WrappedKey: []byte(output.Ciphertext),
		},
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext. This should be called after Init.
func (k *Wrapper) Decrypt(_ context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, fmt.Errorf("given input for decryption is nil")
	}

	plainText, err := k.client.decrypt(k.keyId, string(in.KeyInfo.WrappedKey))
	if err != nil {
		return nil, fmt.Errorf("error decrypting data encryption key: %w", err)
	}

	keyBytes, err := base64.StdEncoding.DecodeString(plainText)
	if err != nil {
		return nil, err
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

type encryptResponse struct {
	KeyId      string `json:"key_id"`
	Ciphertext string `json:"cipher_text"`
}

func newKMSClient(accessKey, secretKey, domain string) (kmsClient, error) {
	client := resty.New()

	client.OnBeforeRequest(func(c *resty.Client, r *resty.Request) error {
		reqURL, err := url.Parse(r.URL)
		if err != nil {
			return err
		}

		if len(c.QueryParam)+len(r.QueryParam) > 0 {
			for k, v := range c.QueryParam {
				if _, ok := r.QueryParam[k]; ok {
					continue
				}

				r.QueryParam[k] = v[:]
			}

			if len(r.QueryParam) > 0 {
				if strings.TrimSpace(reqURL.RawQuery) == "" {
					reqURL.RawQuery = r.QueryParam.Encode()
				} else {
					reqURL.RawQuery = reqURL.RawQuery + "&" + r.QueryParam.Encode()
				}
			}
		}

		now := time.Now()
		pathString := reqURL.EscapedPath()
		if reqURL.RawQuery != "" {
			pathString += "?" + reqURL.RawQuery
		}
		if accessKey != "" && secretKey != "" {
			setNcloudPlatformHeader(r, now, r.Method, pathString, accessKey, secretKey)
		}
		return nil
	})

	if domain == "" {
		domain = "ncloud.apigw.ntruss.com"
	}

	return &kmsClientImpl{
		client: client,
		domain: domain,
	}, nil
}

func setNcloudPlatformHeader(req *resty.Request, timestamp time.Time, reqType, path, accessKeyID, secretAccessKey string) *resty.Request {
	return req.SetHeader("x-ncp-apigw-timestamp", fmt.Sprint(timestamp.UnixMilli())).
		SetHeader("x-ncp-iam-access-key", accessKeyID).
		SetHeader("x-ncp-apigw-signature-v2", createNaverSignature(reqType, path, timestamp, accessKeyID, secretAccessKey))
}

func genHMAC256(ciphertext, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(ciphertext)
	hmacBytes := mac.Sum(nil)
	return hmacBytes
}

func createNaverSignature(method, uri string, timestamp time.Time, accessKey, secretKey string) string {
	timestampString := fmt.Sprint(timestamp.UnixMilli())
	message := fmt.Sprintf("%v %v\n%v\n%v", method, uri, timestampString, accessKey)
	signature := genHMAC256([]byte(message), []byte(secretKey))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)
	return signatureB64
}

type kmsClient interface {
	encrypt(keyID, plainText string) (encryptResponse, error)
	decrypt(keyID, cipherText string) (string, error)
}

type kmsClientImpl struct {
	client *resty.Client
	domain string
}

func (c *kmsClientImpl) encrypt(keyID, plainText string) (encryptResponse, error) {
	var err error
	type EncryptRequest struct {
		Plaintext string `json:"plaintext"`
		Context   string `json:"context,omitempty"`
	}
	type EncryptResponse struct {
		Ciphertext string `json:"ciphertext"`
	}
	type Response struct {
		Code  string          `json:"code"`
		Msg   string          `json:"msg"`
		Data  EncryptResponse `json:"data"`
		Error *struct {
			ErrorCode string `json:"errorCode"`
			Message   string `json:"message"`
			Details   string `json:"details"`
		} `json:"error"`
	}
	req := &EncryptRequest{
		Plaintext: plainText,
	}
	result := &Response{}
	resp := encryptResponse{}
	_, err = c.client.R().
		SetResult(result).
		SetBody(req).
		SetHeader("Content-Type", "application/json;charset=UTF-8").
		Post(fmt.Sprintf("https://%v/keys/v2/%v/encrypt", c.domain, keyID))
	if err != nil {
		return resp, fmt.Errorf("error encrypting data: %s", err)
	}
	if result.Error != nil {
		return resp, fmt.Errorf("error encrypting data: %s", err)
	}

	if result.Code != "SUCCESS" {
		return resp, fmt.Errorf("error encrypting data: %s", result.Msg)
	}

	resp.Ciphertext = result.Data.Ciphertext
	resp.KeyId = keyID

	return resp, nil
}

func (c *kmsClientImpl) decrypt(keyID, cipherText string) (string, error) {
	var err error
	type DecryptRequest struct {
		Ciphertext string `json:"ciphertext"`
		Context    string `json:"context,omitempty"`
	}
	type DecrytptResponse struct {
		Plaintext string `json:"plaintext"`
	}
	type Response struct {
		Code  string           `json:"code"`
		Msg   string           `json:"msg"`
		Data  DecrytptResponse `json:"data"`
		Error *struct {
			ErrorCode string `json:"errorCode"`
			Message   string `json:"message"`
			Details   string `json:"details"`
		} `json:"error"`
	}
	req := &DecryptRequest{
		Ciphertext: cipherText,
	}

	result := &Response{}
	_, err = c.client.R().
		SetResult(result).
		SetBody(req).
		SetHeader("Content-Type", "application/json;charset=UTF-8").
		Post(fmt.Sprintf("https://%v/keys/v2/%v/decrypt", c.domain, keyID))
	if err != nil {
		return "", fmt.Errorf("failed to decrypt sops data key with Ncloud KMS key: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("failed to decrypt sops data key with Ncloud KMS key: %v", result.Error.Message)
	}
	if result.Code != "SUCCESS" {
		return "", fmt.Errorf("failed to decrypt sops data key with Ncloud KMS key: %v", result.Msg)
	}

	return result.Data.Plaintext, nil
}
