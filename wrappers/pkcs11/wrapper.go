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
	// Key ID and label
	id, label string
	// Encryption/decryption mechanism, hash for RSA-OAEP
	mechanism, hash uint
	// Handle to the encryption/decryption key(s),
	// equal for symmetric keys
	encryptor, decryptor pkcs11.ObjectHandle
}

var (
	// Ensure that we implement both Wrapper and InitFinalizer correctly
	_ wrapping.Wrapper       = (*Wrapper)(nil)
	_ wrapping.InitFinalizer = (*Wrapper)(nil)
)

const DefaultRSAOAEPHash = pkcs11.CKM_SHA256

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
	return fmt.Sprintf("%s:%s", k.id, k.label), nil
}

// SetConfig configures the client and key used by the Wrapper.
func (k *Wrapper) SetConfig(ctx context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getWrapperOpts(options)
	if err != nil {
		return nil, err
	}
	id, label, err := parseIDLabel(opts.keyId, opts.keyLabel)
	if err != nil {
		return nil, err
	}

	// Parse mechanism/key type, may be unset for now and automatically
	// determined after fetching the key(s):
	var mechanism, keytype *uint
	if opts.mechanism != "" {
		// This only parses mechanisms supported by Wrapper.
		m, t, err := mechanismFromString(opts.mechanism)
		if err != nil {
			return nil, err
		}
		mechanism = &m
		keytype = &t
	}

	// Parse hash mechanism:
	k.hash = DefaultRSAOAEPHash
	if opts.hash != "" {
		k.hash, err = hashMechanismFromString(opts.hash)
		if err != nil {
			return nil, err
		}
	}

	k.client, err = NewClient(opts.lib, opts.slotNumber, opts.tokenLabel, opts.pin, opts.maxSessions)
	if err != nil {
		return nil, err
	}

	// Find our key(s).
	if err := k.client.WithSession(ctx, func(session *Session) error {
		var err error
		// Try to find an initial key capable of decryption.
		// This one may be the final (symmetric key) or the private half
		// of an asymmetric keypair.
		k.decryptor, err = session.FindDecryptionKey(id, label, keytype)
		if err != nil {
			return err
		}
		// Now check the key type to figure out if it's symmetric or asymmetric.
		t, err := session.GetKeyType(k.decryptor)
		if err != nil {
			return err
		}
		// Sanity check!
		if keytype != nil && *keytype != t {
			return fmt.Errorf("expected key type %d, but found %d", *keytype, t)
		}
		// Key type was unknown before, now it is certain.
		keytype = &t
		switch t {
		case pkcs11.CKK_RSA:
			// Fallthrough and fetch the other key half, too.
		case pkcs11.CKK_AES:
			// We're done.
			k.encryptor = k.decryptor
			return nil
		default:
			return fmt.Errorf("unsupported key type: %d", *keytype)
		}
		// Fetch the public key half.
		k.encryptor, err = session.FindEncryptionKey(id, label, keytype)
		return err
	}); err != nil {
		return nil, err
	}

	// Next, resolve the mechanism if not explicitly set.
	if mechanism == nil {
		// Choose the "best available" mechanism for the key.
		k.mechanism = bestAvailableMechanism(*keytype)
	} else {
		k.mechanism = *mechanism
	}

	// Finally, collect all the metadata for WrapperConfig.
	metadata := make(map[string]string)
	metadata["lib"] = k.client.module.path
	metadata["slot"] = strconv.FormatUint(uint64(k.client.pool.slot), 10)
	if opts.tokenLabel != "" {
		metadata["token_label"] = string(opts.tokenLabel)
	}
	if opts.keyId != "" {
		k.id = opts.keyId
		metadata["key_id"] = opts.keyId
	}
	if opts.keyLabel != "" {
		k.label = opts.keyLabel
		metadata["key_label"] = opts.keyLabel
	}
	metadata["mechanism"] = mechanismToString(k.mechanism)
	if k.mechanism == pkcs11.CKM_RSA_PKCS_OAEP {
		metadata["rsa_oaep_hash"] = hashMechanismToString(k.hash)
	}
	return &wrapping.WrapperConfig{Metadata: metadata}, nil
}

// Encrypt encrypts plaintext via PKCS#11. The supported mechanisms are RSA-OAEP and AES-GCM.
func (k *Wrapper) Encrypt(ctx context.Context, plaintext []byte, _ ...wrapping.Option) (*wrapping.BlobInfo, error) {
	var ret wrapping.BlobInfo
	err := k.client.WithSession(ctx, func(session *Session) error {
		var err error
		switch k.mechanism {
		case pkcs11.CKM_RSA_PKCS_OAEP:
			ret.Ciphertext, err = session.EncryptRSAOAEP(k.encryptor, plaintext, k.hash)
		case pkcs11.CKM_AES_GCM:
			ret.Ciphertext, ret.Iv, err = session.EncryptAESGCM(k.encryptor, plaintext)
		default:
			panic("internal error: unknown mechanism")
		}
		return err
	})
	return &ret, err
}

// Decrypt decrypts ciphertext via PKCS#11. The supported mechanisms are RSA-OAEP and AES-GCM.
func (k *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, _ ...wrapping.Option) ([]byte, error) {
	var plaintext []byte
	err := k.client.WithSession(ctx, func(session *Session) error {
		var err error
		switch k.mechanism {
		case pkcs11.CKM_RSA_PKCS_OAEP:
			plaintext, err = session.DecryptRSAOAEP(k.decryptor, in.Ciphertext, k.hash)
		case pkcs11.CKM_AES_GCM:
			plaintext, err = session.DecryptAESGCM(k.decryptor, in.Ciphertext, in.Iv)
		default:
			panic("internal error: unknown mechanism")
		}
		return err
	})
	return plaintext, err
}
