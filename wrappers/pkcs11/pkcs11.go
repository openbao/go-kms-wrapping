// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"fmt"
	"sync/atomic"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// These constants contain the accepted env vars; the Vault one is for backwards compat
const (
	EnvPkcs11WrapperKeyId   = "PKCS11_WRAPPER_KEY_ID"
	EnvVaultPkcs11SealKeyId = "VAULT_PKCS11_SEAL_KEY_ID"
)

// Wrapper is a Wrapper that uses PKCS11
type Wrapper struct {
	client       pkcs11ClientEncryptor
	keyId        string
	currentKeyId *atomic.Value
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new PKCS11 Wrapper
func NewWrapper() *Wrapper {
	k := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	k.currentKeyId.Store("")
	return k
}

// Init is called during core.Initialize
func (k *Wrapper) Init(_ context.Context) error {
	return nil
}

// Finalize is called during shutdown
func (k *Wrapper) Finalize(_ context.Context) error {
	k.client.Close()
	return nil
}

// SetConfig processes the config info from the server config
func (k *Wrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	client, wrapConfig, err := newPkcs11Client(opts)
	if err != nil {
		return nil, err
	}
	k.client = client
	k.keyId = client.GetCurrentKey().String()

	// Send a value to test the wrapper and to set the current key id
	if _, err := k.Encrypt(context.Background(), []byte("a")); err != nil {
		client.Close()
		return nil, err
	}

	return wrapConfig, nil
}

// Type returns the type for this particular wrapper implementation
func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypePkcs11, nil
}

// KeyId returns the last known key id
func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.currentKeyId.Load().(string), nil
}

// Encrypt is used to encrypt data using the the PKCS11 key.
// This returns the ciphertext, and/or any errors from this
// call. This should be called after the KMS client has been instantiated.
func (k *Wrapper) Encrypt(_ context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	ciphertext, key, err := k.client.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	
	keyId := key.String()
	k.currentKeyId.Store(keyId)

	ret := &wrapping.BlobInfo{
		Ciphertext: ciphertext,
		KeyInfo: &wrapping.KeyInfo{
			KeyId: keyId,
		},
	}
	return ret, nil
}

// Decrypt is used to decrypt the ciphertext. This should be called after Init.
func (k *Wrapper) Decrypt(_ context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, fmt.Errorf("given input for decryption is nil")
	}

	if in.KeyInfo == nil {
		in.KeyInfo = &wrapping.KeyInfo{
			KeyId: k.keyId,
		}
	}
	keyId, err := newPkcs11Key(in.KeyInfo.KeyId)
	if err != nil {
		return nil, err
	}
	plaintext, err := k.client.Decrypt(in.Ciphertext, keyId)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// GetClient returns the pkcs11 Wrapper's pkcs11ClientEncryptor
func (k *Wrapper) GetClient() pkcs11ClientEncryptor {
	return k.client
}