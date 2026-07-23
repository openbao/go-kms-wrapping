// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"context"

	"github.com/hashicorp/go-plugin"
	pb "github.com/openbao/go-kms-wrapping/plugin/v2/pb/metadata"
	"google.golang.org/grpc"
)

type gRPCMetadataServer struct {
	pb.UnimplementedMetadataServer

	resp *pb.MetadataResponse
}

func (mp *gRPCMetadataPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterMetadataServer(s, &gRPCMetadataServer{
		resp: &pb.MetadataResponse{
			SensitiveKmsFields: mp.metadata.SensitiveKMSFields,
			SensitiveKeyFields: mp.metadata.SensitiveKeyFields,
		},
	})
	return nil
}

func (s *gRPCMetadataServer) Get(context.Context, *pb.Empty) (*pb.MetadataResponse, error) {
	return s.resp, nil
}
