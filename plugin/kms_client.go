// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/hashicorp/go-plugin"
	pb "github.com/openbao/go-kms-wrapping/plugin/v2/pb/kms"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func (c *gRPCKMSClient) handleRPCError(err error) error {
	code := status.Code(err)
	switch {
	case code == codes.Unimplemented:
		return kms.ErrNotImplemented
	case code == codes.NotFound:
		return ErrNoInstance
	case c.ctx.Err() != nil:
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
		return c.handleRPCError(err)
	}
	c.id = resp.KmsId
	return nil
}

func (c *gRPCKMSClient) Close(ctx context.Context) error {
	_, err := c.client.Close(ctx, &pb.CloseRequest{
		KmsId: c.id,
	})
	return c.handleRPCError(err)
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
		return nil, c.handleRPCError(err)
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
	resp, err := c.kms.client.Encrypt(ctx, &pb.EncryptRequest{
		KeyId: c.id,
		Data:  opts.Data,
		Aad:   opts.AAD,
	})
	if err != nil {
		return nil, c.kms.handleRPCError(err)
	}
	opts.Nonce = resp.Nonce
	opts.KeyVersion = resp.KeyVersion
	return resp.Ciphertext, nil
}

func (c *gRPCKeyClient) Decrypt(ctx context.Context, opts *kms.CipherOptions) ([]byte, error) {
	resp, err := c.kms.client.Decrypt(ctx, &pb.DecryptRequest{
		KeyId:      c.id,
		Data:       opts.Data,
		Aad:        opts.AAD,
		Nonce:      opts.Nonce,
		KeyVersion: opts.KeyVersion,
	})
	if err != nil {
		return nil, c.kms.handleRPCError(err)
	}
	return resp.Plaintext, nil
}

func signerOptsToProto(opts crypto.SignerOpts) (*pb.SignerOpts, error) {
	switch opts := opts.(type) {
	case crypto.Hash:
		// If we're only given a hash, just leave it empty.
		return nil, nil
	case *rsa.PSSOptions:
		return &pb.SignerOpts{
			Type: &pb.SignerOpts_Pss{
				Pss: &pb.SignerOptsPSS{
					SaltLength: int32(opts.SaltLength),
				},
			},
		}, nil
	case *ed25519.Options:
		return &pb.SignerOpts{
			Type: &pb.SignerOpts_Ed25519{
				Ed25519: &pb.SignerOptsEd25519{
					Context: opts.Context,
				},
			},
		}, nil
	}
	return nil, fmt.Errorf("unsupported crypto.SignerOpts type: %T", opts)
}

func (c *gRPCKeyClient) Sign(ctx context.Context, opts *kms.SignOptions) ([]byte, error) {
	var (
		hash       int32
		signerOpts *pb.SignerOpts
		err        error
	)
	if opts.SignerOpts != nil {
		hash = int32(opts.HashFunc())
		if signerOpts, err = signerOptsToProto(opts.SignerOpts); err != nil {
			return nil, err
		}
	}
	resp, err := c.kms.client.Sign(ctx, &pb.SignRequest{
		KeyId:     c.id,
		Data:      opts.Data,
		Prehashed: opts.Prehashed,
		Hash:      hash,
		Opts:      signerOpts,
	})
	if err != nil {
		return nil, c.kms.handleRPCError(err)
	}
	opts.KeyVersion = resp.KeyVersion
	return resp.Signature, nil
}

func (c *gRPCKeyClient) Verify(ctx context.Context, opts *kms.VerifyOptions) error {
	var (
		hash       int32
		signerOpts *pb.SignerOpts
		err        error
	)
	if opts.SignerOpts != nil {
		hash = int32(opts.HashFunc())
		if signerOpts, err = signerOptsToProto(opts.SignerOpts); err != nil {
			return err
		}
	}
	_, err = c.kms.client.Verify(ctx, &pb.VerifyRequest{
		KeyId:      c.id,
		Data:       opts.Data,
		Prehashed:  opts.Prehashed,
		Hash:       hash,
		Opts:       signerOpts,
		Signature:  opts.Signature,
		KeyVersion: opts.KeyVersion,
	})
	switch {
	case status.Code(err) == codes.InvalidArgument:
		return kms.ErrInvalidSignature
	case err != nil:
		return c.kms.handleRPCError(err)
	}
	return nil
}

func (c *gRPCKeyClient) ExportPublic(ctx context.Context) (crypto.PublicKey, error) {
	resp, err := c.kms.client.ExportPublic(ctx, &pb.ExportPublicRequest{
		KeyId: c.id,
	})
	if err != nil {
		return nil, c.kms.handleRPCError(err)
	}
	pub, err := x509.ParsePKIXPublicKey(resp.PkixAsn1Der)
	if err != nil {
		return nil, err
	}
	return crypto.PublicKey(pub), nil
}

func (c *gRPCKeyClient) Close(ctx context.Context) error {
	_, err := c.kms.client.CloseKey(ctx, &pb.CloseKeyRequest{
		KeyId: c.id,
	})
	return c.kms.handleRPCError(err)
}
