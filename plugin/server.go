// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"context"
	"errors"
	"sync"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/go-kms-wrapping/plugin/v2/pb"
	"github.com/openbao/go-kms-wrapping/v2"
)

// ErrNoInstance is returned when an RPC is called on a remote object that
// doesn't exist.
var ErrNoInstance = errors.New("instance not found")

type gRPCWrapperServer struct {
	pb.UnimplementedWrapperServer

	instances     map[string]wrapping.Wrapper
	instancesLock sync.Mutex

	factory func() wrapping.Wrapper
}

func (ws *gRPCWrapperServer) get(id string) (wrapping.Wrapper, error) {
	ws.instancesLock.Lock()
	defer ws.instancesLock.Unlock()

	if wrapper, ok := ws.instances[id]; ok {
		return wrapper, nil
	}

	return nil, ErrNoInstance
}

func (ws *gRPCWrapperServer) SetConfig(ctx context.Context, req *pb.SetConfigRequest) (*pb.SetConfigResponse, error) {
	id, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	opts := req.Options
	if opts == nil {
		opts = new(wrapping.Options)
	}

	// SetConfig drives initial wrapper construction.
	// Also see comment in client.go.
	wrapper := ws.factory()
	wc, err := wrapper.SetConfig(
		ctx,
		wrapping.WithKeyId(opts.WithKeyId),
		wrapping.WithConfigMap(opts.WithConfigMap),
	)
	if err != nil {
		return nil, err
	}

	ws.instancesLock.Lock()
	ws.instances[id] = wrapper
	ws.instancesLock.Unlock()

	return &pb.SetConfigResponse{WrapperConfig: wc, WrapperId: id}, nil
}

func (ws *gRPCWrapperServer) Type(ctx context.Context, req *pb.TypeRequest) (*pb.TypeResponse, error) {
	wrapper, err := ws.get(req.WrapperId)
	if err != nil {
		return nil, err
	}
	typ, err := wrapper.Type(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.TypeResponse{Type: typ.String()}, nil
}

func (ws *gRPCWrapperServer) KeyId(ctx context.Context, req *pb.KeyIdRequest) (*pb.KeyIdResponse, error) {
	wrapper, err := ws.get(req.WrapperId)
	if err != nil {
		return nil, err
	}
	keyId, err := wrapper.KeyId(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.KeyIdResponse{KeyId: keyId}, nil
}

func (ws *gRPCWrapperServer) Encrypt(ctx context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	wrapper, err := ws.get(req.WrapperId)
	if err != nil {
		return nil, err
	}
	opts := req.Options
	if opts == nil {
		opts = new(wrapping.Options)
	}
	ct, err := wrapper.Encrypt(
		ctx,
		req.Plaintext,
		wrapping.WithAad(opts.WithAad),
		wrapping.WithKeyId(opts.WithKeyId),
	)
	if err != nil {
		return nil, err
	}
	return &pb.EncryptResponse{Ciphertext: ct}, nil
}

func (ws *gRPCWrapperServer) Decrypt(ctx context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	wrapper, err := ws.get(req.WrapperId)
	if err != nil {
		return nil, err
	}
	opts := req.Options
	if opts == nil {
		opts = new(wrapping.Options)
	}
	pt, err := wrapper.Decrypt(
		ctx,
		req.Ciphertext,
		wrapping.WithAad(opts.WithAad),
		wrapping.WithKeyId(opts.WithKeyId),
	)
	if err != nil {
		return nil, err
	}
	return &pb.DecryptResponse{Plaintext: pt}, nil
}

func (ws *gRPCWrapperServer) Init(ctx context.Context, req *pb.InitRequest) (*pb.InitResponse, error) {
	wrapper, err := ws.get(req.WrapperId)
	if err != nil {
		return nil, err
	}
	initFinalizer, ok := wrapper.(wrapping.InitFinalizer)
	if !ok {
		return &pb.InitResponse{}, nil
	}
	if err := initFinalizer.Init(ctx); err != nil {
		return nil, err
	}
	return &pb.InitResponse{}, nil
}

func (ws *gRPCWrapperServer) Finalize(ctx context.Context, req *pb.FinalizeRequest) (*pb.FinalizeResponse, error) {
	wrapper, err := ws.get(req.WrapperId)
	if err != nil {
		return nil, err
	}

	// Call Finalize if the underlying implementation has it.
	if initFinalizer, ok := wrapper.(wrapping.InitFinalizer); ok {
		if err := initFinalizer.Finalize(ctx); err != nil {
			return nil, err
		}
	}

	// Then remove the instance:
	ws.instancesLock.Lock()
	delete(ws.instances, req.WrapperId)
	ws.instancesLock.Unlock()

	return &pb.FinalizeResponse{}, nil
}
