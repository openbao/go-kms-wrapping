// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"context"

	"github.com/openbao/go-kms-wrapping/plugin/v2/pb"
	"github.com/openbao/go-kms-wrapping/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	_ wrapping.Wrapper       = (*gRPCWrapperClient)(nil)
	_ wrapping.InitFinalizer = (*gRPCWrapperClient)(nil)
	_ wrapping.KeyExporter   = (*gRPCWrapperClient)(nil)
)

type gRPCWrapperClient struct {
	impl pb.WrapperClient
}

func (wc *gRPCWrapperClient) Type(ctx context.Context) (wrapping.WrapperType, error) {
	resp, err := wc.impl.Type(ctx, new(pb.TypeRequest))
	if err != nil {
		return wrapping.WrapperTypeUnknown, err
	}
	return wrapping.WrapperType(resp.Type), nil
}

func (wc *gRPCWrapperClient) KeyId(ctx context.Context) (string, error) {
	resp, err := wc.impl.KeyId(ctx, new(pb.KeyIdRequest))
	if err != nil {
		return "", err
	}
	return resp.KeyId, nil
}

func (wc *gRPCWrapperClient) SetConfig(ctx context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return nil, err
	}
	resp, err := wc.impl.SetConfig(ctx, &pb.SetConfigRequest{
		Options: opts,
	})
	if err != nil {
		return nil, err
	}
	return resp.WrapperConfig, nil
}

func (wc *gRPCWrapperClient) Encrypt(ctx context.Context, pt []byte, options ...wrapping.Option) (*wrapping.BlobInfo, error) {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return nil, err
	}
	resp, err := wc.impl.Encrypt(ctx, &pb.EncryptRequest{
		Plaintext: pt,
		Options:   opts,
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
	resp, err := wc.impl.Decrypt(ctx, &pb.DecryptRequest{
		Ciphertext: ct,
		Options:    opts,
	})
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}

func (ifc *gRPCWrapperClient) Init(ctx context.Context, options ...wrapping.Option) error {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return err
	}
	_, err = ifc.impl.Init(ctx, &pb.InitRequest{
		Options: opts,
	})
	return err
}

func (wc *gRPCWrapperClient) Finalize(ctx context.Context, options ...wrapping.Option) error {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return err
	}
	_, err = wc.impl.Finalize(ctx, &pb.FinalizeRequest{
		Options: opts,
	})
	return err
}

func (wc *gRPCWrapperClient) KeyBytes(ctx context.Context) ([]byte, error) {
	resp, err := wc.impl.KeyBytes(ctx, new(pb.KeyBytesRequest))
	switch {
	case err == nil:
	case status.Code(err) == codes.Unimplemented:
		return nil, wrapping.ErrFunctionNotImplemented
	default:
		return nil, err
	}
	return resp.KeyBytes, nil
}
