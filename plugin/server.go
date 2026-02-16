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

type gRPCWrapperServer struct {
	pb.UnimplementedWrapperServer
	impl wrapping.Wrapper
}

func (ws *gRPCWrapperServer) Type(ctx context.Context, req *pb.TypeRequest) (*pb.TypeResponse, error) {
	typ, err := ws.impl.Type(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.TypeResponse{Type: typ.String()}, nil
}

func (ws *gRPCWrapperServer) KeyId(ctx context.Context, req *pb.KeyIdRequest) (*pb.KeyIdResponse, error) {
	keyId, err := ws.impl.KeyId(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.KeyIdResponse{KeyId: keyId}, nil
}

func (ws *gRPCWrapperServer) SetConfig(ctx context.Context, req *pb.SetConfigRequest) (*pb.SetConfigResponse, error) {
	opts := req.Options
	if opts == nil {
		opts = new(wrapping.Options)
	}
	wc, err := ws.impl.SetConfig(
		ctx,
		wrapping.WithKeyId(opts.WithKeyId),
		wrapping.WithConfigMap(opts.WithConfigMap),
	)
	if err != nil {
		return nil, err
	}
	return &pb.SetConfigResponse{WrapperConfig: wc}, nil
}

func (ws *gRPCWrapperServer) Encrypt(ctx context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	opts := req.Options
	if opts == nil {
		opts = new(wrapping.Options)
	}
	ct, err := ws.impl.Encrypt(
		ctx,
		req.Plaintext,
		wrapping.WithAad(opts.WithAad),
		wrapping.WithKeyId(opts.WithKeyId),
		wrapping.WithConfigMap(opts.WithConfigMap),
	)
	if err != nil {
		return nil, err
	}
	return &pb.EncryptResponse{Ciphertext: ct}, nil
}

func (ws *gRPCWrapperServer) Decrypt(ctx context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	opts := req.Options
	if opts == nil {
		opts = new(wrapping.Options)
	}
	pt, err := ws.impl.Decrypt(
		ctx,
		req.Ciphertext,
		wrapping.WithAad(opts.WithAad),
		wrapping.WithKeyId(opts.WithKeyId),
		wrapping.WithConfigMap(opts.WithConfigMap),
	)
	if err != nil {
		return nil, err
	}
	return &pb.DecryptResponse{Plaintext: pt}, nil
}

func (ws *gRPCWrapperServer) Init(ctx context.Context, req *pb.InitRequest) (*pb.InitResponse, error) {
	initFinalizer, ok := ws.impl.(wrapping.InitFinalizer)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "this Wrapper does not implement InitFinalizer")
	}
	opts := req.Options
	if opts == nil {
		opts = new(wrapping.Options)
	}
	if err := initFinalizer.Init(
		ctx,
		wrapping.WithConfigMap(opts.WithConfigMap),
	); err != nil {
		return nil, err
	}
	return &pb.InitResponse{}, nil
}

func (ws *gRPCWrapperServer) Finalize(ctx context.Context, req *pb.FinalizeRequest) (*pb.FinalizeResponse, error) {
	initFinalizer, ok := ws.impl.(wrapping.InitFinalizer)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "this Wrapper does not implement InitFinalizer")
	}
	if err := initFinalizer.Finalize(
		ctx,
	); err != nil {
		return nil, err
	}
	return &pb.FinalizeResponse{}, nil
}

func (ws *gRPCWrapperServer) KeyBytes(ctx context.Context, req *pb.KeyBytesRequest) (*pb.KeyBytesResponse, error) {
	keyExporter, ok := ws.impl.(wrapping.KeyExporter)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "this Wrapper does not implement KeyExporter")
	}
	keyBytes, err := keyExporter.KeyBytes(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.KeyBytesResponse{KeyBytes: keyBytes}, nil
}
