// Copyright The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"fmt"

	"github.com/miekg/pkcs11"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// Hub is a wrapping.Hub that uses PKCS#11.
type Hub struct {
	client *Client
}

var (
	// Ensure that we implement both Hub and InitFinalizer correctly
	_ wrapping.Hub           = (*Hub)(nil)
	_ wrapping.InitFinalizer = (*Hub)(nil)
)

// NewHub returns a new uninitialized and unconfigured Hub.
func NewHub() *Hub {
	return &Hub{}
}

// Init initializes the Hub. It is currently a no-op.
func (k *Hub) Init(_ context.Context, _ ...wrapping.Option) error {
	return nil
}

// Finalize finalizes the Hub and closes its client.
func (k *Hub) Finalize(_ context.Context, _ ...wrapping.Option) error {
	return k.client.Close()
}

// SetConfig configures the client used by the Hub.
func (k *Hub) SetConfig(_ context.Context, options ...wrapping.Option) error {
	opts, err := getHubOpts(options)
	if err != nil {
		return err
	}
	client, err := NewClient(opts.lib, opts.slotNumber, opts.tokenLabel, opts.pin, opts.maxSessions)
	if err != nil {
		return err
	}
	k.client = client
	return nil
}

// GetKey returns an opaque key backed by PKCS#11.
// This key may be a crypto.Signer and/or a crypto.Decrypter.
// Currently supported key types are ECDSA and RSA.
func (k *Hub) GetKey(ctx context.Context, options ...wrapping.Option) (wrapping.ExternalKey, error) {
	opts, err := getSignerDecrypterOpts(options)
	if err != nil {
		return nil, err
	}
	id, label, err := parseIDLabel(opts.keyId, opts.keyLabel)
	if err != nil {
		return nil, err
	}

	var ret wrapping.ExternalKey
	err = k.client.WithSession(ctx, func(session *Session) error {
		priv, pub, err := session.FindKeyPair(id, label)
		if err != nil {
			return err
		}
		keytype, err := session.GetKeyType(priv)
		if err != nil {
			return err
		}

		base := baseExternalKey{ctx: ctx, client: k.client, obj: priv}
		switch keytype {
		case pkcs11.CKK_EC:
			public, err := session.ExportECDSAPublicKey(pub)
			if err != nil {
				return fmt.Errorf("failed to export ECDSA public key: %w", err)
			}
			ret = &ecdsaSigner{baseExternalKey: base, public: public}
		case pkcs11.CKK_RSA:
			public, err := session.ExportRSAPublicKey(pub)
			if err != nil {
				return fmt.Errorf("failed to export RSA public key: %w", err)
			}
			ret = &rsaSignerDecrypter{baseExternalKey: base, public: public}
		default:
			return fmt.Errorf("unsupported key type: %d", keytype)
		}
		return nil
	})

	return ret, err
}
