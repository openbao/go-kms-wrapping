// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ovhkms

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/google/uuid"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/ovh/okms-sdk-go"
)

// These constants contain the accepted env vars; the Vault one is for backwards compat
const (
	EnvOkmsWrapperKeyId   = "BAO_OKMS_WRAPPER_KEY_ID"
	EnvVaultOkmsSealKeyId = "VAULT_OKMS_SEAL_KEY_ID"
	EnvOkmsEndpoint       = "BAO_OKMS_ENDPOINT"
	EnvOkmsId             = "BAO_OKMS_ID"
	EnvOkmsClientCert     = "BAO_OKMS_CLIENT_CERT"
	EnvOkmsClientKey      = "BAO_OKMS_CLIENT_KEY"
)

// Wrapper is a wrapper that uses the OVHcloud Service Key API
type Wrapper struct {
	// ovh sdk client
	client *okms.Client
	// service key id used for encrypt/decrypt operations
	keyId        uuid.UUID
	currentKeyId *atomic.Value
	// your kms id
	okmsId uuid.UUID
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

func NewWrapper() *Wrapper {
	ow := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	ow.currentKeyId.Store("")

	return ow
}

func (ow *Wrapper) Type(ctx context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeOvhKms, nil
}

func (ow *Wrapper) KeyId(ctx context.Context) (string, error) {
	return ow.currentKeyId.Load().(string), nil
}

// SetConfig sets the fields on the OvhKmsWrapper object based on
// values from the config parameter.
//
// Order of precedence OvhKms values:
// * Environment variable
// * Value from Vault configuration file
// * Instance metadata role (access key and secret key)
func (ow *Wrapper) SetConfig(ctx context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	// Check and set KeyId
	switch {
	case os.Getenv(EnvOkmsWrapperKeyId) != "" && !opts.Options.WithDisallowEnvVars:
		ow.keyId, err = uuid.Parse(os.Getenv(EnvOkmsWrapperKeyId))
	case os.Getenv(EnvVaultOkmsSealKeyId) != "" && !opts.Options.WithDisallowEnvVars:
		ow.keyId, err = uuid.Parse(os.Getenv(EnvVaultOkmsSealKeyId))
	case opts.WithKeyId != "":
		ow.keyId, err = uuid.Parse(opts.WithKeyId)
	default:
		return nil, fmt.Errorf("key id not found (env or config) for ovhkms wrapper configuration")
	}
	if err != nil {
		return nil, err
	}

	ow.currentKeyId.Store(ow.keyId.String())

	// set kms endpoint
	endpoint := ""
	if !opts.Options.WithDisallowEnvVars {
		endpoint = os.Getenv(EnvOkmsEndpoint)
	}
	if endpoint == "" {
		endpoint = opts.withEndpoint
	}

	// set kms okmsId
	if !opts.Options.WithDisallowEnvVars {
		okmsId := os.Getenv(EnvOkmsId)
		if okmsId != "" {
			ow.okmsId, err = uuid.Parse(okmsId)
			if err != nil {
				return nil, err
			}
		}
	}
	if ow.okmsId.String() == "" {
		ow.okmsId = opts.withOkmsId
	}

	// configure TLS
	clientCertFile := ""
	if !opts.Options.WithDisallowEnvVars {
		clientCertFile = os.Getenv(EnvOkmsClientCert)
	}
	if clientCertFile == "" {
		clientCertFile = opts.withClientCert
	}

	clientKeyFile := ""
	if !opts.Options.WithDisallowEnvVars {
		clientKeyFile = os.Getenv(EnvOkmsClientKey)
	}
	if clientKeyFile == "" {
		clientKeyFile = opts.withClientKey
	}

	if !(clientKeyFile != "" && clientCertFile != "") {
		return nil, fmt.Errorf("missing client certificate/key")
	}
	clientCfg, err := getTLSconfig(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, err
	}

	// Request new OKMS client
	ow.client, err = okms.NewRestAPIClient(endpoint, clientCfg)
	if err != nil {
		return nil, err
	}

	// Validate Service Key operations (expected: encrypt,decrypt)
	resp, err := ow.client.GetServiceKey(context.Background(), ow.okmsId, ow.keyId, nil)
	if err != nil {
		return nil, err
	}
	encryptOp := false
	decryptOp := false
	for _, op := range *resp.Operations {
		switch op {
		case "encrypt":
			encryptOp = true
		case "decrypt":
			decryptOp = true
		}
	}
	if !encryptOp || !decryptOp {
		return nil, fmt.Errorf("missing encrypt,decrypt operations on provided service key")
	}

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["kms_key_id"] = ow.keyId.String()
	wrapConfig.Metadata["endpoint"] = endpoint
	wrapConfig.Metadata["okmsId"] = ow.okmsId.String()

	return wrapConfig, nil
}

func getTLSconfig(clientCertFile, clientKeyFile string) (okms.ClientConfig, error) {
	clientCertBytes, err := os.ReadFile(clientCertFile)
	if err != nil {
		return okms.ClientConfig{}, err
	}
	clientKeyBytes, err := os.ReadFile(clientKeyFile)
	if err != nil {
		return okms.ClientConfig{}, err
	}
	tlsCert, err := tls.X509KeyPair(clientCertBytes, clientKeyBytes)
	if err != nil {
		return okms.ClientConfig{}, err
	}

	clientConfig := okms.ClientConfig{
		TlsCfg: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		},
	}

	// Uncomment this line to enable tracing of HTTP requests and responses
	// clientConfig.Middleware = okms.DebugTransport(os.Stderr)

	return clientConfig, nil
}

// Encrypt is used to encrypt the master key using the OVHcloud CMK.
// This returns the ciphertext, and/or any errors from this
// call. This should be called after the KMS client has been instantiated.
func (ow *Wrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	if ow.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	encryptedDEK, err := ow.client.Encrypt(context.Background(), ow.okmsId, ow.keyId, "", env.Key)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	ow.currentKeyId.Store(encryptedDEK)

	return &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		KeyInfo: &wrapping.KeyInfo{
			KeyId:      ow.keyId.String(),
			WrappedKey: []byte(encryptedDEK),
		},
	}, nil
}

// Decrypt is used to decrypt the ciphertext. This should be called after Init.
func (ow *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, fmt.Errorf("given input for decryption is nil")
	}

	if ow.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	decryptedDEK, err := ow.client.Decrypt(context.Background(), ow.okmsId, ow.keyId, "", string(in.KeyInfo.WrappedKey))
	if err != nil {
		return nil, fmt.Errorf("error decrypting data encryption key: %w", err)
	}

	envInfo := &wrapping.EnvelopeInfo{
		Key:        decryptedDEK,
		Iv:         in.Iv,
		Ciphertext: in.Ciphertext,
	}
	plaintext, err := wrapping.EnvelopeDecrypt(envInfo, opt...)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return plaintext, nil
}
