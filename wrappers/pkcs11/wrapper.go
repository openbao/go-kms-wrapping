// Copyright The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"fmt"
	"strconv"

	"github.com/miekg/pkcs11"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// Wrapper is a wrapping.Wrapper that uses PKCS#11.
type Wrapper struct {
	// PKCS#11 client
	client *Client
	// Key that the wrapper is bound to
	key *Key
}

var (
	// Ensure that we implement both Wrapper and InitFinalizer correctly
	_ wrapping.Wrapper       = (*Wrapper)(nil)
	_ wrapping.InitFinalizer = (*Wrapper)(nil)
)

// NewWrapper returns a new uninitialized and unconfigured Wrapper.
func NewWrapper() *Wrapper {
	return &Wrapper{}
}

// Init initializes the Wrapper. It is currently a no-op.
func (k *Wrapper) Init(_ context.Context, _ ...wrapping.Option) error {
	return nil
}

// Finalize finalizes the Wrapper and closes its client.
func (k *Wrapper) Finalize(_ context.Context, _ ...wrapping.Option) error {
	k.client.Close()
	return nil
}

// Type returns the type of the wrapper.
func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypePkcs11, nil
}

// KeyId gets a human-readable identifier of key the wrapper uses.
func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.key.String(), nil
}

// SetConfig configures the client and key used by the Wrapper.
func (k *Wrapper) SetConfig(_ context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getWrapperOpts(options)
	if err != nil {
		return nil, err
	}

	key, err := NewKey(opts.keyId, opts.keyLabel, opts.mechanism, opts.hash)
	if err != nil {
		return nil, err
	}
	switch key.mechanism {
	// Only allow RSA-OAEP and AES-GCM for sealing/unsealing.
	case pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.CKM_AES_GCM:
	default:
		return nil, fmt.Errorf("mechanism not allowed: %s", MechanismToString(key.mechanism))
	}

	client, err := NewClient(opts.lib, opts.slotNumber, opts.tokenLabel, opts.pin, opts.maxSessions)
	if err != nil {
		return nil, err
	}

	k.key = key
	k.client = client

	metadata := make(map[string]string)
	metadata["lib"] = client.module.path
	// Resolved slot number, even if we only set tokenLabel
	metadata["slot"] = strconv.FormatUint(uint64(client.pool.slot), 10)
	if opts.tokenLabel != "" {
		metadata["token_label"] = string(opts.tokenLabel)
	}
	key.CollectMetadata(metadata)
	return &wrapping.WrapperConfig{Metadata: metadata}, nil
}

// Encrypt encrypts plaintext using keys in an HSM. The supported mechanisms are RSA-OAEP and AES-GCM.
func (k *Wrapper) Encrypt(ctx context.Context, plaintext []byte, _ ...wrapping.Option) (*wrapping.BlobInfo, error) {
	var ret wrapping.BlobInfo
	err := k.client.WithSession(ctx, func(session *Session) error {
		obj, err := session.FindEncryptionKey(k.key)
		if err != nil {
			return err
		}
		switch k.key.mechanism {
		case pkcs11.CKM_RSA_PKCS_OAEP:
			ret.Ciphertext, err = session.EncryptRSAOAEP(obj, plaintext, k.key.hash)
		case pkcs11.CKM_AES_GCM:
			ret.Ciphertext, ret.Iv, err = session.EncryptAESGCM(obj, plaintext)
		default:
			err = fmt.Errorf("unsupported mechanism: %s", MechanismToString(k.key.mechanism))
		}
		return err
	})
	return &ret, err
}

// Decrypt decrypts ciphertext using keys in an HSM. The supported mechanisms are RSA-OAEP and AES-GCM.
func (k *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, _ ...wrapping.Option) ([]byte, error) {
	var plaintext []byte
	err := k.client.WithSession(ctx, func(session *Session) error {
		obj, err := session.FindDecryptionKey(k.key)
		if err != nil {
			return err
		}
		switch k.key.mechanism {
		case pkcs11.CKM_RSA_PKCS_OAEP:
			plaintext, err = session.DecryptRSAOAEP(obj, in.Ciphertext, k.key.hash)
		case pkcs11.CKM_AES_GCM:
			plaintext, err = session.DecryptAESGcm(obj, in.Ciphertext, in.Iv)
		default:
			err = fmt.Errorf("unsupported mechanism: %s", MechanismToString(k.key.mechanism))
		}
		return err
	})
	return plaintext, err
}
