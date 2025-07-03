// Copyright The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strconv"

	"github.com/miekg/pkcs11"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// Wrapper is a [wrapping.Wrapper] that uses PKCS#11.
type Wrapper struct {
	client          *client
	key             *key
	pubkey          crypto.PublicKey
	mechanism, hash uint
	keyID           string
}

var (
	_ wrapping.Wrapper       = (*Wrapper)(nil)
	_ wrapping.InitFinalizer = (*Wrapper)(nil)
)

// NewWrapper returns a new uninitialized and unconfigured Wrapper.
func NewWrapper() *Wrapper {
	return &Wrapper{}
}

// Init initializes the Wrapper. It is currently a no-op.
func (w *Wrapper) Init(_ context.Context, _ ...wrapping.Option) error {
	return nil
}

// Finalize finalizes the Wrapper and closes its client.
func (w *Wrapper) Finalize(_ context.Context, _ ...wrapping.Option) error {
	return w.client.close()
}

// Type returns the type of the wrapper.
func (w *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypePkcs11, nil
}

// KeyId is a string representation of the wrapper's key ID + label.
func (w *Wrapper) KeyId(_ context.Context) (string, error) {
	return w.keyID, nil
}

// SetConfig configures & initializes the client used by the Wrapper and
// retrieves the encryption/decryption key (pair) to use.
func (w *Wrapper) SetConfig(ctx context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getWrapperOpts(options)
	if err != nil {
		return nil, err
	}

	id, label, err := parseIDLabel(opts.keyId, opts.keyLabel)
	if err != nil {
		return nil, err
	}
	w.keyID = fmt.Sprintf("%s:%s", opts.keyId, opts.keyLabel)

	// Optionally user-specified mechanism and the required key type to use that
	// mechanism. If set, we later compare this against the key we find via ID &
	// label.
	mechanism, keytype, err := maybeMechanismFromString(opts.mechanism)
	if err != nil {
		return nil, err
	}

	// Only relevant for RSA-OAEP.
	w.hash, err = hashMechanismFromStringOrDefault(opts.hash)
	if err != nil {
		return nil, err
	}

	w.client, err = newClient(opts.clientOptions)
	if err != nil {
		return nil, err
	}

	// Find the key (pair) we'll be using:
	if err := w.client.do(ctx, func(s *session) error {
		k, err := s.find(id, label)
		if err != nil {
			return err
		}
		// Ensure that the key (pair) supports encryption and decryption:
		switch k.class {
		case pkcs11.CKO_SECRET_KEY:
			if !k.encrypt {
				return fmt.Errorf("secret key is not an encryption key")
			}
			if !k.decrypt {
				return fmt.Errorf("secret key is not a decryption key")
			}
		case pkcs11.CKO_PRIVATE_KEY:
			if !k.decrypt {
				return fmt.Errorf("private key is not a decryption key")
			}
			if k.public == nil {
				return fmt.Errorf("private key is missing a public key half")
			}
			// With software encryption, we don't care about the CKA_ENCRYPT bit.
			if !opts.soft && !k.public.encrypt {
				return fmt.Errorf("public key is not an encryption key")
			}
		default:
			return fmt.Errorf("unknown key object type")
		}

		// Check that the key type required by the optionally user-specified mechanism
		// fits the key type of our key.
		if keytype != nil && *keytype != k.keytype {
			return fmt.Errorf("want to use mechanism %s, but key has type %d",
				mechanismToString(*mechanism), k.keytype)
		}

		// Ensure that we support the key type and choose a mechanism:
		switch k.keytype {
		case pkcs11.CKK_AES:
			if mechanism == nil {
				w.mechanism = pkcs11.CKM_AES_GCM
			} else {
				w.mechanism = *mechanism
			}
		case pkcs11.CKK_RSA:
			if mechanism == nil {
				w.mechanism = pkcs11.CKM_RSA_PKCS_OAEP
			} else {
				w.mechanism = *mechanism
			}
			if opts.soft {
				// Encrypt(...) will check for a non-nil pubkey and use it for software
				// encryption, else fall back to hardware encryption.
				w.pubkey, err = s.exportRSAPublicKey(k.public)
				if err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unsupported key type: %d", k.keytype)
		}

		w.key = k
		return nil
	}); err != nil {
		return nil, err
	}

	// Finally, collect all the metadata for WrapperConfig.
	metadata := w.collectMetadata(opts)
	return &wrapping.WrapperConfig{Metadata: metadata}, nil
}

// collectMetadata collects a metadata map for wrapping.WrapperConfig.
func (w *Wrapper) collectMetadata(opts *wrapperOptions) map[string]string {
	metadata := make(map[string]string)
	metadata["lib"] = w.client.module.path
	// pkcs11-tool shows the slot number in hex, this makes it easy to compare:
	metadata["slot"] = "0x" + strconv.FormatUint(uint64(w.client.pool.slot), 16)
	if opts.tokenLabel != "" {
		metadata["token_label"] = string(opts.tokenLabel)
	}
	if opts.keyId != "" {
		metadata["key_id"] = opts.keyId
	}
	if opts.keyLabel != "" {
		metadata["key_label"] = opts.keyLabel
	}
	metadata["mechanism"] = mechanismToString(w.mechanism)
	if w.mechanism == pkcs11.CKM_RSA_PKCS_OAEP {
		metadata["rsa_oaep_hash"] = hashMechanismToString(w.hash)
	}
	return metadata
}

// Encrypt encrypts plaintext via PKCS#11.
func (w *Wrapper) Encrypt(ctx context.Context, plaintext []byte, _ ...wrapping.Option) (*wrapping.BlobInfo, error) {
	var ret wrapping.BlobInfo
	err := w.client.do(ctx, func(s *session) error {
		var err error
		switch w.mechanism {
		case pkcs11.CKM_RSA_PKCS_OAEP:
			if pub, ok := w.pubkey.(*rsa.PublicKey); ok && pub != nil {
				h := hashMechanismToCrypto(w.hash).New()
				ret.Ciphertext, err = rsa.EncryptOAEP(h, rand.Reader, pub, plaintext, nil)
			} else {
				ret.Ciphertext, err = s.encryptRSAOAEP(w.key.public, plaintext, w.hash)
			}
		case pkcs11.CKM_AES_GCM:
			ret.Ciphertext, ret.Iv, err = s.encryptAESGCM(w.key, plaintext)
		default:
			panic("internal error: unknown mechanism")
		}
		return err
	})
	return &ret, err
}

// Decrypt decrypts ciphertext via PKCS#11.
func (w *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, _ ...wrapping.Option) ([]byte, error) {
	var plaintext []byte
	err := w.client.do(ctx, func(s *session) error {
		var err error
		switch w.mechanism {
		case pkcs11.CKM_RSA_PKCS_OAEP:
			plaintext, err = s.decryptRSAOAEP(w.key, in.Ciphertext, w.hash)
		case pkcs11.CKM_AES_GCM:
			plaintext, err = s.decryptAESGCM(w.key, in.Ciphertext, in.Iv)
		default:
			panic("internal error: unknown mechanism")
		}
		return err
	})
	return plaintext, err
}
