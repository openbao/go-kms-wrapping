// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package securosyshsm

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/hashicorp/go-hclog"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// Wrapper encrypts and decrypts go-kms-wrapping blobs with a Securosys HSM key.
type Wrapper struct {
	logger       hclog.Logger
	client       securosysHSMClientEncryptor
	currentKeyId *atomic.Value
	hsmClient    securosysHSMClientEncryptor
}

const Type wrapping.WrapperType = "securosys-hsm"
const (
	ciphertextPrefix    = "securosys"
	ciphertextPartCount = 4
)

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
func (s *Wrapper) SetConfig(ctx context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	s.logger = opts.withLogger

	client, wrapConfig, err := newSecurosysHSMClient(ctx, s.logger, opts)
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
func (s *Wrapper) Encrypt(ctx context.Context, plaintext []byte, _ ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if s.hsmClient == nil {
		return nil, errors.New("securosys hsm client is not configured")
	}
	data, err := s.hsmClient.Encrypt(ctx, base64.StdEncoding.EncodeToString(plaintext))
	if err != nil {
		return nil, err
	}

	parsed, err := parseCiphertext(data)
	if err != nil {
		return nil, err
	}
	s.currentKeyId.Store(parsed.keyID)

	ret := &wrapping.BlobInfo{
		Ciphertext: data,
		KeyInfo: &wrapping.KeyInfo{
			KeyId: parsed.keyID,
		},
	}
	return ret, nil
}

// Decrypt parses the wrapper ciphertext format, restores the nonce, and
// decrypts using the configured Securosys KMS key.
func (s *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, _ ...wrapping.Option) ([]byte, error) {
	if s.hsmClient == nil {
		return nil, errors.New("securosys hsm client is not configured")
	}
	if in == nil {
		return nil, errors.New("missing blob info")
	}
	parsed, err := parseCiphertext(in.Ciphertext)
	if err != nil {
		return nil, err
	}

	plaintext, err := s.hsmClient.Decrypt(ctx, parsed.ciphertext, parsed.nonce)
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

type parsedCiphertext struct {
	keyID      string
	nonce      string
	ciphertext string
}

func parseCiphertext(ciphertext []byte) (*parsedCiphertext, error) {
	parts := strings.Split(string(ciphertext), ":")
	if len(parts) != ciphertextPartCount {
		return nil, errors.New("invalid ciphertext format")
	}
	if parts[0] != ciphertextPrefix {
		return nil, fmt.Errorf("invalid ciphertext prefix %q", parts[0])
	}
	if parts[1] == "" {
		return nil, errors.New("missing key id in ciphertext")
	}
	if parts[3] == "" {
		return nil, errors.New("missing payload in ciphertext")
	}
	return &parsedCiphertext{
		keyID:      parts[1],
		nonce:      parts[2],
		ciphertext: parts[3],
	}, nil
}
