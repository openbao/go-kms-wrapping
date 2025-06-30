// Copyright The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// Provider is a [[wrapping.CryptoProvider]] that uses PKCS#11.
type Provider struct {
	client *client
}

var (
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
	return p.client.close()
}

// SetConfig configures & initializes the client used by the Provider.
func (p *Provider) SetConfig(_ context.Context, options ...wrapping.Option) error {
	opts, err := getProviderOpts(options)
	if err != nil {
		return err
	}
	p.client, err = newClient(opts)
	return err
}

// GetKey returns a [[wrapping.ExternalKey]] backed by PKCS#11.
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
	err = p.client.do(ctx, func(s *session) error {
		k, err := s.find(id, label)
		if err != nil {
			return err
		}
		ret, err = newExternalKey(ctx, p.client, s, k)
		return err
	})

	return ret, err
}
