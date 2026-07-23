// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"context"

	"github.com/hashicorp/go-plugin"
	pb "github.com/openbao/go-kms-wrapping/plugin/v2/pb/metadata"
	"google.golang.org/grpc"
)

func (mp *gRPCMetadataPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	resp, err := pb.NewMetadataClient(c).Get(ctx, &pb.Empty{})
	if err != nil {
		switch {
		case ctx.Err() != nil:
			return nil, ErrPluginShutdown
		default:
			return nil, err
		}
	}

	return Metadata{
		SensitiveKMSFields: resp.SensitiveKmsFields,
		SensitiveKeyFields: resp.SensitiveKeyFields,
	}, nil
}
