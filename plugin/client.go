// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"context"
	"errors"

	"github.com/openbao/go-kms-wrapping/plugin/v2/pb"
	"github.com/openbao/go-kms-wrapping/v2"
)

var (
	_ wrapping.Wrapper       = (*gRPCWrapperClient)(nil)
	_ wrapping.InitFinalizer = (*gRPCWrapperClient)(nil)
)

type gRPCWrapperClient struct {
	id     string
	client pb.WrapperClient
}

func (wc *gRPCWrapperClient) SetConfig(ctx context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	if wc.id != "" {
		// While the API of wrapping.Wrapper theoretically allows wrappers to
		// be reconfigured, in practice most wrappers expect to be configured
		// exactly once and would not correctly handle reconfiguration or
		// function at all without being configured first. For the plugin
		// implementation, SetConfig effectively becomes the constructor. This
		// also means that Finalize must AND should only be called if SetConfig
		// succeeds.
		return nil, errors.New("already configured")
	}
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return nil, err
	}
	resp, err := wc.client.SetConfig(ctx, &pb.SetConfigRequest{Options: opts})
	if err != nil {
		return nil, err
	}
	wc.id = resp.WrapperId
	return resp.WrapperConfig, nil
}

func (wc *gRPCWrapperClient) Type(ctx context.Context) (wrapping.WrapperType, error) {
	resp, err := wc.client.Type(ctx, &pb.TypeRequest{WrapperId: wc.id})
	if err != nil {
		return wrapping.WrapperTypeUnknown, err
	}
	return wrapping.WrapperType(resp.Type), nil
}

func (wc *gRPCWrapperClient) KeyId(ctx context.Context) (string, error) {
	resp, err := wc.client.KeyId(ctx, &pb.KeyIdRequest{WrapperId: wc.id})
	if err != nil {
		return "", err
	}
	return resp.KeyId, nil
}

func (wc *gRPCWrapperClient) Encrypt(ctx context.Context, pt []byte, options ...wrapping.Option) (*wrapping.BlobInfo, error) {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return nil, err
	}
	resp, err := wc.client.Encrypt(ctx, &pb.EncryptRequest{
		Plaintext: pt,
		Options:   opts,
		WrapperId: wc.id,
	})
	if err != nil {
		return nil, err
	}
	return resp.Ciphertext, nil
}

func (wc *gRPCWrapperClient) Decrypt(ctx context.Context, ct *wrapping.BlobInfo, options ...wrapping.Option) ([]byte, error) {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return nil, err
	}
	resp, err := wc.client.Decrypt(ctx, &pb.DecryptRequest{
		Ciphertext: ct,
		Options:    opts,
		WrapperId:  wc.id,
	})
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}

func (wc *gRPCWrapperClient) Init(ctx context.Context, options ...wrapping.Option) error {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return err
	}
	_, err = wc.client.Init(ctx, &pb.InitRequest{
		Options:   opts,
		WrapperId: wc.id,
	})
	return err
}

func (wc *gRPCWrapperClient) Finalize(ctx context.Context, options ...wrapping.Option) error {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return err
	}
	_, err = wc.client.Finalize(ctx, &pb.FinalizeRequest{
		Options:   opts,
		WrapperId: wc.id,
	})
	return err
}
