// Copyright The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"fmt"

	"github.com/miekg/pkcs11"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// Provider is a wrapping.CryptoProvider that uses PKCS#11.
type Provider struct {
	client *Client
}

var (
	// Ensure that we implement both Provider and InitFinalizer correctly
	_ wrapping.CryptoProvider = (*Provider)(nil)
	_ wrapping.InitFinalizer  = (*Provider)(nil)
)

// NewProvider returns a new uninitialized and unconfigured Provider.
func NewProvider() *Provider {
	return &Provider{}
}

// Init initializes the Provider. It is currently a no-op.
func (p *Provider) Init(_ context.Context, _ ...wrapping.Option) error {
	return nil
}

// Finalize finalizes the Provider and closes its client.
func (p *Provider) Finalize(_ context.Context, _ ...wrapping.Option) error {
	return p.client.Close()
}

// SetConfig configures the client used by the Provider.
func (p *Provider) SetConfig(_ context.Context, options ...wrapping.Option) error {
	opts, err := getProviderOpts(options)
	if err != nil {
		return err
	}
	client, err := NewClient(opts.lib, opts.slotNumber, opts.tokenLabel, opts.pin, opts.maxParallel)
	if err != nil {
		return err
	}
	p.client = client
	return nil
}

// GetKey returns an opaque key backed by PKCS#11. This key may be a
// crypto.Signer and/or a crypto.Decrypter. Currently supported key types are
// ECDSA and RSA.
func (p *Provider) GetKey(ctx context.Context, options ...wrapping.Option) (wrapping.ExternalKey, error) {
	opts, err := getSignerDecrypterOpts(options)
	if err != nil {
		return nil, err
	}
	id, label, err := parseIDLabel(opts.keyId, opts.keyLabel)
	if err != nil {
		return nil, err
	}

	var ret wrapping.ExternalKey
	err = p.client.WithSession(ctx, func(session *Session) error {
		priv, pub, err := session.FindKeyPair(id, label)
		if err != nil {
			return err
		}
		keytype, err := session.GetKeyType(priv)
		if err != nil {
			return err
		}

		base := baseKey{ctx: ctx, client: p.client, obj: priv}
		switch keytype {
		case pkcs11.CKK_EC:
			public, err := session.ExportECDSAPublicKey(pub)
			if err != nil {
				return fmt.Errorf("failed to export ECDSA public key: %w", err)
			}
			ret = &ecdsaSigner{baseKey: base, public: public}
		case pkcs11.CKK_RSA:
			public, err := session.ExportRSAPublicKey(pub)
			if err != nil {
				return fmt.Errorf("failed to export RSA public key: %w", err)
			}
			ret = &rsaSignerDecrypter{baseKey: base, public: public}
		default:
			return fmt.Errorf("unsupported key type: %d", keytype)
		}
		return nil
	})

	return ret, err
}
