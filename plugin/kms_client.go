// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"context"
	"crypto"
	"errors"

	"github.com/hashicorp/go-plugin"
	pb "github.com/openbao/go-kms-wrapping/plugin/v2/pb/kms"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

type gRPCKMSClient struct {
	kms.UnimplementedKMS

	id     string
	ctx    context.Context
	client pb.KMSClient
}

func (kp *gRPCKMSPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return &gRPCKMSClient{
		ctx:    ctx,
		client: pb.NewKMSClient(c),
	}, nil
}

func (c *gRPCKMSClient) handleError(err error) error {
	if c.ctx.Err() != nil {
		return ErrPluginShutdown
	}
	return err
}

func (c *gRPCKMSClient) Open(ctx context.Context, opts *kms.OpenOptions) error {
	if c.id != "" {
		return errors.New("already opened")
	}

	cm, err := structpb.NewStruct(opts.ConfigMap)
	if err != nil {
		return err
	}

	resp, err := c.client.Open(ctx, &pb.OpenRequest{
		AllowEnvironment: opts.AllowEnvironment,
		ConfigMap:        cm,
	})
	if err != nil {
		return c.handleError(err)
	}

	c.id = resp.KmsId
	return nil
}

func (c *gRPCKMSClient) Close(ctx context.Context) error {
	_, err := c.client.Close(ctx, &pb.CloseRequest{
		KmsId: c.id,
	})
	return c.handleError(err)
}

func (c *gRPCKMSClient) GetKey(ctx context.Context, opts *kms.KeyOptions) (kms.Key, error) {
	cm, err := structpb.NewStruct(opts.ConfigMap)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.GetKey(ctx, &pb.GetKeyRequest{
		KmsId:     c.id,
		ConfigMap: cm,
	})
	if err != nil {
		return nil, c.handleError(err)
	}

	return &gRPCKeyClient{
		id:  resp.KeyId,
		kms: c,
	}, nil
}

type gRPCKeyClient struct {
	kms.UnimplementedKey

	id  string
	kms *gRPCKMSClient
}

func (c *gRPCKeyClient) Encrypt(ctx context.Context, opts *kms.CipherOptions) ([]byte, error) {
	return nil, kms.ErrNotImplemented
}

func (c *gRPCKeyClient) Decrypt(ctx context.Context, opts *kms.CipherOptions) ([]byte, error) {
	return nil, kms.ErrNotImplemented
}

func (c *gRPCKeyClient) Sign(ctx context.Context, opts *kms.SignOptions) ([]byte, error) {
	return nil, kms.ErrNotImplemented
}

func (c *gRPCKeyClient) Verify(ctx context.Context, opts *kms.VerifyOptions) error {
	return kms.ErrNotImplemented
}

func (c *gRPCKeyClient) ExportPublic(ctx context.Context) (crypto.PublicKey, error) {
	return nil, kms.ErrNotImplemented
}

func (c *gRPCKeyClient) Close(ctx context.Context) error {
	_, err := c.kms.client.CloseKey(ctx, &pb.CloseKeyRequest{
		KeyId: c.id,
	})
	return c.kms.handleError(err)
}
