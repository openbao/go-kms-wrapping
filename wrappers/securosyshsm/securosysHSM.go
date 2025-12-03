// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package securosyshsm

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync/atomic"

	"github.com/hashicorp/go-hclog"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// Wrapper is a wrapper that leverages Vault's SecurosysHSM secret
// engine
type Wrapper struct {
	logger       hclog.Logger
	client       securosysHSMClientEncryptor
	currentKeyId *atomic.Value
	hsmClient    *SecurosysHSMClient
}
type CustomWrapperType string

const (
	WrapperTypeSecurosysHSM CustomWrapperType = "securosys-hsm"
)

var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new securosysHSM wrapper
func NewWrapper() *Wrapper {
	s := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	s.currentKeyId.Store("")
	return s
}

// SetConfig processes the config info from the server config
func (s *Wrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	s.logger = opts.withLogger

	client, wrapConfig, err := newSecurosysHSMClient(s.logger, opts)
	if err != nil {
		return nil, err
	}
	s.hsmClient = client

	return wrapConfig, nil
}

// Init is called during core.Initialize
func (s *Wrapper) Init(_ context.Context) error {
	return nil
}

// Finalize is called during shutdown
func (s *Wrapper) Finalize(_ context.Context) error {
	s.client.Close()
	return nil
}

// Type returns the type for this particular Wrapper implementation
func (s *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeSecurosysHsm, nil
}

// KeyId returns the last known key id
func (s *Wrapper) KeyId(_ context.Context) (string, error) {
	return s.currentKeyId.Load().(string), nil
}

// Encrypt is used to encrypt using Vault's SecurosysHSM engine
func (s *Wrapper) Encrypt(_ context.Context, plaintext []byte, _ ...wrapping.Option) (*wrapping.BlobInfo, error) {
	data, err := s.hsmClient.Encrypt(base64.StdEncoding.EncodeToString(plaintext))
	if err != nil {
		return nil, err
	}

	payload := data
	splitKey := strings.Split(string(payload), ":")
	if len(splitKey) != 4 {
		return nil, errors.New("invalid ciphertext returned")
	}
	keyId := splitKey[1]
	s.currentKeyId.Store(keyId)

	ret := &wrapping.BlobInfo{
		Ciphertext: payload,
		KeyInfo: &wrapping.KeyInfo{
			KeyId: keyId,
		},
	}
	return ret, nil
}

// Decrypt is used to decrypt the ciphertext
func (s *Wrapper) Decrypt(_ context.Context, in *wrapping.BlobInfo, _ ...wrapping.Option) ([]byte, error) {
	splitKey := strings.Split(string(in.Ciphertext), ":")
	if len(splitKey) != 4 {
		return nil, errors.New("invalid ciphertext returned")
	}
	keyId := splitKey[1]

	plaintext, err := s.hsmClient.Decrypt(splitKey[2], keyId, splitKey[3])
	if err != nil {
		return nil, err
	}
	bytes, err := base64.StdEncoding.DecodeString(string(plaintext))
	bytes, err = base64.StdEncoding.DecodeString(string(bytes))
	return bytes, nil
}

// GetClient returns the securosysHSM Wrapper's securosysHSMClientEncryptor
func (s *Wrapper) GetClient() securosysHSMClientEncryptor {
	return s.client
}
