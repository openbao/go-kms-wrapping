// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package scwkms

import (
	"encoding/base64"
	"fmt"

	key_manager "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
)

const scwTestKeyId = "00000000-0000-0000-0000-000000000001"

// NewScwKmsTestWrapper creates a wrapper pre-configured with a mock client for unit tests.
func NewScwKmsTestWrapper() *Wrapper {
	s := NewWrapper()
	s.client = &mockClient{keyId: scwTestKeyId}
	s.keyId = scwTestKeyId
	s.region = "fr-par"
	s.currentKeyId.Store(scwTestKeyId)
	return s
}

// mockClient is a mock implementation of scwKmsClient that uses base64 encoding
// to simulate KMS encrypt/decrypt without making real API calls.
type mockClient struct {
	keyId string
}

// Encrypt is a mocked call that returns a base64 encoded string.
func (m *mockClient) Encrypt(req *key_manager.EncryptRequest, _ ...scw.RequestOption) (*key_manager.EncryptResponse, error) {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(req.Plaintext)))
	base64.StdEncoding.Encode(encoded, req.Plaintext)
	return &key_manager.EncryptResponse{
		KeyID:      m.keyId,
		Ciphertext: encoded,
	}, nil
}

// Decrypt is a mocked call that returns a decoded base64 string.
func (m *mockClient) Decrypt(req *key_manager.DecryptRequest, _ ...scw.RequestOption) (*key_manager.DecryptResponse, error) {
	decLen := base64.StdEncoding.DecodedLen(len(req.Ciphertext))
	decoded := make([]byte, decLen)
	n, err := base64.StdEncoding.Decode(decoded, req.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("mock decrypt error: %w", err)
	}
	return &key_manager.DecryptResponse{
		KeyID:     m.keyId,
		Plaintext: decoded[:n],
	}, nil
}

// GetKey is a mocked call that returns the key ID.
func (m *mockClient) GetKey(req *key_manager.GetKeyRequest, _ ...scw.RequestOption) (*key_manager.Key, error) {
	if req.KeyID == "" {
		return nil, fmt.Errorf("key not found")
	}
	return &key_manager.Key{
		ID:     req.KeyID,
		Region: req.Region,
	}, nil
}
