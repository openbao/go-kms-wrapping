// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package ovhcloudkms

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/google/uuid"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/ovh/okms-sdk-go"
)

const Type wrapping.WrapperType = "ovhcloudkms"

const (
	EnvOkmsKeyId      = "OVHCLOUDKMS_KEY_ID"
	EnvOkmsEndpoint   = "OVHCLOUDKMS_ENDPOINT"
	EnvOkmsId         = "OVHCLOUDKMS_ID"
	EnvOkmsClientCert = "OVHCLOUDKMS_CLIENT_CERT"
	EnvOkmsClientKey  = "OVHCLOUDKMS_CLIENT_KEY"
	EnvOkmsCaCert     = "OVHCLOUDKMS_CA_CERT"
	EnvOkmsToken      = "OVHCLOUDKMS_TOKEN"
)

// Wrapper is a wrapper that uses the OVHcloud Service Key API
type Wrapper struct {
	// ovh sdk client
	client *okms.Client
	// service key id used for encrypt/decrypt operations
	keyId        uuid.UUID
	currentKeyId *atomic.Value
	// your kms id
	kmsId uuid.UUID
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

func (ow *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return Type, nil
}

func (ow *Wrapper) KeyId(_ context.Context) (string, error) {
	return ow.currentKeyId.Load().(string), nil
}

// SetConfig sets the fields on the OkmsWrapper object based on
// values from the config parameter.
//
// Order of precedence for Okms values:
// * Environment variables (if WithDisallowEnvVars not provided)
// * Value from OpenBao/Vault configuration file
// * Instance metadata role (access key and secret key)
func (ow *Wrapper) SetConfig(ctx context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	// Check and set KeyId
	switch {
	case !opts.Options.WithDisallowEnvVars && os.Getenv(EnvOkmsKeyId) != "":
		ow.keyId, err = uuid.Parse(os.Getenv(EnvOkmsKeyId))
	case opts.WithKeyId != "":
		ow.keyId, err = uuid.Parse(opts.WithKeyId)
	default:
		return nil, fmt.Errorf("key id not found (env or config) for kms configuration")
	}
	if err != nil {
		return nil, err
	}

	ow.currentKeyId.Store(ow.keyId.String())

	// set okms endpoint
	endpoint := ""
	if !opts.Options.WithDisallowEnvVars {
		endpoint = os.Getenv(EnvOkmsEndpoint)
	}
	if endpoint == "" {
		endpoint = opts.withEndpoint
	}

	// set okms ID
	if !opts.Options.WithDisallowEnvVars {
		kmsId := os.Getenv(EnvOkmsId)
		if kmsId != "" {
			ow.kmsId, err = uuid.Parse(kmsId)
			if err != nil {
				return nil, err
			}
		}
	}
	if ow.kmsId == uuid.Nil {
		ow.kmsId = opts.withKmsId
	}

	// configure token
	token := ""
	if !opts.Options.WithDisallowEnvVars {
		token = os.Getenv(EnvOkmsToken)
	}
	if token == "" {
		token = opts.withToken
	}

	// File-provided mTLS setup.
	var clientCertBytes []byte
	if !opts.Options.WithDisallowEnvVars {
		clientCertFile := os.Getenv(EnvOkmsClientCert)
		if clientCertFile == "" {
			clientCertFile = opts.withClientCert
		}

		if clientCertFile != "" {
			clientCertBytes, err = os.ReadFile(clientCertFile)
			if err != nil {
				return nil, err
			}
		}
	}

	var clientKeyBytes []byte
	if !opts.Options.WithDisallowEnvVars {
		clientKeyFile := os.Getenv(EnvOkmsClientKey)
		if clientKeyFile == "" {
			clientKeyFile = opts.withClientKey
		}

		if clientKeyFile != "" {
			clientKeyBytes, err = os.ReadFile(clientKeyFile)
			if err != nil {
				return nil, err
			}
		}
	}

	var caCertBytes []byte
	if !opts.Options.WithDisallowEnvVars {
		caCertFile := os.Getenv(EnvOkmsCaCert)
		if caCertFile == "" {
			caCertFile = opts.withCACert
		}

		if caCertFile != "" {
			caCertBytes, err = os.ReadFile(caCertFile)
			if err != nil {
				return nil, err
			}
		}
	}

	// In-memory mTLS setup.
	if len(clientCertBytes) == 0 {
		clientCertBytes = []byte(opts.withClientCertBytes)
	}

	if len(clientKeyBytes) == 0 {
		clientKeyBytes = []byte(opts.withClientKeyBytes)
	}

	if len(caCertBytes) == 0 {
		caCertBytes = []byte(opts.withCACertBytes)
	}

	// One authentication method must be provided: mTLS or token.
	hasMTLS := len(clientCertBytes) > 0 || len(clientKeyBytes) > 0
	hasToken := token != ""
	switch {
	case hasMTLS && hasToken:
		return nil, errors.New("ambiguous authentication: provide either mTLS (client_cert/client_key) or token (token/kms_id), not both")
	case hasMTLS:
		if len(clientCertBytes) == 0 || len(clientKeyBytes) == 0 {
			return nil, errors.New("missing client certificate/key for mTLS authentication")
		}
		clientCfg, err := getMTLSConfig(clientCertBytes, clientKeyBytes, caCertBytes)
		if err != nil {
			return nil, err
		}
		ow.client, err = okms.NewRestAPIClient(endpoint, clientCfg)
		if err != nil {
			return nil, err
		}
	case hasToken:
		clientCfg := okms.ClientConfig{}
		if len(caCertBytes) > 0 {
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCertBytes)
			clientCfg.TlsCfg = &tls.Config{
				RootCAs: caCertPool,
			}
		}

		ow.client, err = okms.NewRestAPIClient(endpoint, clientCfg)
		if err != nil {
			return nil, err
		}
		ow.client.WithCustomHeader("Authorization", "Bearer "+token)
	default:
		return nil, fmt.Errorf("missing authentication: provide either mTLS (client_cert/client_key) or token (token/kms_id)")
	}

	// Validate Service Key operations (expected: encrypt,decrypt)
	resp, err := ow.client.GetServiceKey(ctx, ow.kmsId, ow.keyId, nil)
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
	wrapConfig.Metadata["key_id"] = ow.keyId.String()
	wrapConfig.Metadata["endpoint"] = endpoint
	wrapConfig.Metadata["kms_id"] = ow.kmsId.String()

	return wrapConfig, nil
}

func getMTLSConfig(clientCert, clientKey, caCert []byte) (okms.ClientConfig, error) {
	tlsCert, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return okms.ClientConfig{}, err
	}

	clientConfig := okms.ClientConfig{
		TlsCfg: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		},
	}

	if len(caCert) > 0 {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		clientConfig.TlsCfg.RootCAs = caCertPool
	}

	// Uncomment this line to enable tracing of HTTP requests and responses
	// clientConfig.Middleware = okms.DebugTransport(os.Stderr)

	return clientConfig, nil
}

// Encrypt is used to encrypt the master key using the OVHcloud CMK.
// This returns the ciphertext, and/or any errors from this
// call. This should be called after the OKMS client has been instantiated.
func (ow *Wrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	encryptedDEK, err := ow.client.Encrypt(ctx, ow.kmsId, ow.keyId, "", env.Key)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	ow.currentKeyId.Store(ow.keyId.String())

	return &wrapping.BlobInfo{
		Iv:         env.Iv,
		Ciphertext: env.Ciphertext,
		KeyInfo: &wrapping.KeyInfo{
			KeyId:      ow.keyId.String(),
			WrappedKey: []byte(encryptedDEK),
		},
	}, nil
}

// Decrypt is used to decrypt the ciphertext. This should be called after Init.
func (ow *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	decryptedDEK, err := ow.client.Decrypt(ctx, ow.kmsId, ow.keyId, "", string(in.KeyInfo.WrappedKey))
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
