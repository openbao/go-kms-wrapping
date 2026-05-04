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

// Wrapper encrypts and decrypts go-kms-wrapping blobs with a Securosys HSM key.
//
// It delegates cryptographic operations to kms/securosyshsm via the new
// kms.KMS/kms.Key interfaces. Blob ciphertext is stored as
// "securosys:<key-label>:<base64 nonce>:<base64 ciphertext>".
type Wrapper struct {
	logger       hclog.Logger
	client       securosysHSMClientEncryptor
	currentKeyId *atomic.Value
	hsmClient    securosysHSMClientEncryptor
}

const Type wrapping.WrapperType = "securosys-hsm"

var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new Securosys HSM wrapper.
func NewWrapper() *Wrapper {
	s := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	s.currentKeyId.Store("")
	return s
}

// SetConfig processes wrapper configuration and opens the Securosys KMS client.
//
// Required config keys are tsb_api_endpoint, auth, and key_label. For TOKEN
// auth, bearer_token is also required.
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
	s.client = client
	s.hsmClient = client

	return wrapConfig, nil
}

// Init is called during core.Initialize
func (s *Wrapper) Init(_ context.Context) error {
	return nil
}

// Finalize is called during shutdown
func (s *Wrapper) Finalize(_ context.Context) error {
	if s.client != nil {
		s.client.Close()
	}
	return nil
}

// Type returns the type for this particular Wrapper implementation
func (s *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return Type, nil
}

// KeyId returns the last key label used for encryption.
func (s *Wrapper) KeyId(_ context.Context) (string, error) {
	return s.currentKeyId.Load().(string), nil
}

// Encrypt base64-encodes plaintext and encrypts it with the configured
// Securosys KMS key.
func (s *Wrapper) Encrypt(_ context.Context, plaintext []byte, _ ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if s.hsmClient == nil {
		return nil, errors.New("securosys hsm client is not configured")
	}
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

// Decrypt parses the wrapper ciphertext format, restores the nonce, and
// decrypts using the configured Securosys KMS key.
func (s *Wrapper) Decrypt(_ context.Context, in *wrapping.BlobInfo, _ ...wrapping.Option) ([]byte, error) {
	if s.hsmClient == nil {
		return nil, errors.New("securosys hsm client is not configured")
	}
	if in == nil {
		return nil, errors.New("missing blob info")
	}
	splitKey := strings.Split(string(in.Ciphertext), ":")
	if len(splitKey) != 4 {
		return nil, errors.New("invalid ciphertext returned")
	}
	nonce := splitKey[2]

	plaintext, err := s.hsmClient.Decrypt(splitKey[3], nonce)
	if err != nil {
		return nil, err
	}
	bytes, err := base64.StdEncoding.DecodeString(string(plaintext))
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// GetClient returns the securosysHSM Wrapper's securosysHSMClientEncryptor
func (s *Wrapper) GetClient() securosysHSMClientEncryptor {
	return s.client
}
