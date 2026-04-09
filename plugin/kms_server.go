// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"context"
	"sync"

	"github.com/hashicorp/go-plugin"
	pb "github.com/openbao/go-kms-wrapping/plugin/v2/pb/kms"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type gRPCKMSServer struct {
	pb.UnimplementedKMSServer

	services map[string]kms.KMS
	keys     map[string]kms.Key

	lock sync.Mutex

	factory func() kms.KMS
}

func (kp *gRPCKMSPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterKMSServer(s, &gRPCKMSServer{
		factory:  kp.factory,
		services: make(map[string]kms.KMS),
		keys:     make(map[string]kms.Key),
	})
	return nil
}

func (s *gRPCKMSServer) Open(ctx context.Context, req *pb.OpenRequest) (*pb.OpenResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method Open not implemented")
}

func (s *gRPCKMSServer) Close(ctx context.Context, req *pb.CloseRequest) (*pb.CloseResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method Close not implemented")
}

func (s *gRPCKMSServer) GetKey(ctx context.Context, req *pb.GetKeyRequest) (*pb.GetKeyResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method GetKey not implemented")
}

func (s *gRPCKMSServer) CloseKey(ctx context.Context, req *pb.CloseKeyRequest) (*pb.CloseKeyResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method CloseKey not implemented")
}

func (s *gRPCKMSServer) Encrypt(ctx context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method Encrypt not implemented")
}

func (s *gRPCKMSServer) Decrypt(ctx context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method Decrypt not implemented")
}

func (s *gRPCKMSServer) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method Sign not implemented")
}

func (s *gRPCKMSServer) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method Verify not implemented")
}

func (s *gRPCKMSServer) ExportPublic(ctx context.Context, req *pb.ExportPublicRequest) (*pb.ExportPublicResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method ExportPublic not implemented")
}
