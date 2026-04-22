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
	"sync"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/go-uuid"
	pb "github.com/openbao/go-kms-wrapping/plugin/v2/pb/kms"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type gRPCKMSServer struct {
	pb.UnimplementedKMSServer

	logger log.Logger

	services     map[string]kms.KMS
	servicesLock sync.Mutex

	keys     map[string]kms.Key
	keysLock sync.Mutex

	factory func() kms.KMS
}

func (kp *gRPCKMSPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterKMSServer(s, &gRPCKMSServer{
		logger:   kp.logger,
		factory:  kp.factory,
		services: make(map[string]kms.KMS),
		keys:     make(map[string]kms.Key),
	})
	return nil
}

func (s *gRPCKMSServer) service(id string) (kms.KMS, error) {
	s.servicesLock.Lock()
	defer s.servicesLock.Unlock()

	if service, ok := s.services[id]; ok {
		return service, nil
	}

	return nil, status.Error(codes.NotFound, ErrNoInstance.Error())
}

func (s *gRPCKMSServer) key(id string) (kms.Key, error) {
	s.keysLock.Lock()
	defer s.keysLock.Unlock()

	if key, ok := s.keys[id]; ok {
		return key, nil
	}

	return nil, status.Error(codes.NotFound, ErrNoInstance.Error())
}

func (s *gRPCKMSServer) handleKMSError(err error) error {
	switch {
	case errors.Is(err, kms.ErrNotImplemented):
		return status.Error(codes.Unimplemented, err.Error())
	}
	return err
}

func (s *gRPCKMSServer) Open(ctx context.Context, req *pb.OpenRequest) (*pb.OpenResponse, error) {
	service := s.factory()
	if err := service.Open(ctx, &kms.OpenOptions{
		Logger:           s.logger,
		AllowEnvironment: req.AllowEnvironment,
		ConfigMap:        req.ConfigMap.AsMap(),
	}); err != nil {
		return nil, s.handleKMSError(err)
	}

	id, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	s.servicesLock.Lock()
	s.services[id] = service
	s.servicesLock.Unlock()

	return &pb.OpenResponse{KmsId: id}, nil
}

func (s *gRPCKMSServer) Close(ctx context.Context, req *pb.CloseRequest) (*pb.CloseResponse, error) {
	s.servicesLock.Lock()
	service, ok := s.services[req.KmsId]
	if !ok {
		s.servicesLock.Unlock()
		return nil, status.Error(codes.NotFound, ErrNoInstance.Error())
	}

	delete(s.services, req.KmsId)
	s.servicesLock.Unlock()

	if err := service.Close(ctx); err != nil {
		return nil, s.handleKMSError(err)
	}

	return &pb.CloseResponse{}, nil
}

func (s *gRPCKMSServer) GetKey(ctx context.Context, req *pb.GetKeyRequest) (*pb.GetKeyResponse, error) {
	service, err := s.service(req.KmsId)
	if err != nil {
		return nil, err
	}

	key, err := service.GetKey(ctx, &kms.KeyOptions{
		ConfigMap: req.ConfigMap.AsMap(),
	})
	if err != nil {
		return nil, s.handleKMSError(err)
	}

	id, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	s.keysLock.Lock()
	s.keys[id] = key
	s.keysLock.Unlock()

	return &pb.GetKeyResponse{KeyId: id}, nil
}

func (s *gRPCKMSServer) CloseKey(ctx context.Context, req *pb.CloseKeyRequest) (*pb.CloseKeyResponse, error) {
	s.keysLock.Lock()
	key, ok := s.keys[req.KeyId]
	if !ok {
		s.keysLock.Unlock()
		return nil, status.Error(codes.NotFound, ErrNoInstance.Error())
	}

	delete(s.keys, req.KeyId)
	s.keysLock.Unlock()

	if err := key.Close(ctx); err != nil {
		return nil, s.handleKMSError(err)
	}

	return &pb.CloseKeyResponse{}, nil
}

func (s *gRPCKMSServer) Encrypt(ctx context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	key, err := s.key(req.KeyId)
	if err != nil {
		return nil, err
	}

	opts := &kms.CipherOptions{
		Data: req.Data, AAD: req.Aad,
	}

	ciphertext, err := key.Encrypt(ctx, opts)
	if err != nil {
		return nil, s.handleKMSError(err)
	}

	return &pb.EncryptResponse{
		Ciphertext: ciphertext,
		Nonce:      opts.Nonce,
		KeyVersion: opts.KeyVersion,
	}, nil
}

func (s *gRPCKMSServer) Decrypt(ctx context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	key, err := s.key(req.KeyId)
	if err != nil {
		return nil, err
	}

	plaintext, err := key.Decrypt(ctx, &kms.CipherOptions{
		Data:       req.Data,
		AAD:        req.Aad,
		Nonce:      req.Nonce,
		KeyVersion: req.KeyVersion,
	})
	if err != nil {
		return nil, s.handleKMSError(err)
	}

	return &pb.DecryptResponse{Plaintext: plaintext}, nil
}

func protoToSignerOpts(hash int32, opts *pb.SignerOpts) (crypto.SignerOpts, error) {
	if opts == nil {
		return crypto.Hash(hash), nil
	}
	if opts := opts.GetPss(); opts != nil {
		return &rsa.PSSOptions{
			SaltLength: int(opts.SaltLength),
			Hash:       crypto.Hash(hash),
		}, nil
	}
	if opts := opts.GetEd25519(); opts != nil {
		return &ed25519.Options{
			Context: opts.Context,
			Hash:    crypto.Hash(hash),
		}, nil
	}
	return nil, fmt.Errorf("unsupported SignerOpts variant: %T", opts)
}

func (s *gRPCKMSServer) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	key, err := s.key(req.KeyId)
	if err != nil {
		return nil, err
	}

	signerOpts, err := protoToSignerOpts(req.Hash, req.Opts)
	if err != nil {
		return nil, err
	}

	opts := &kms.SignOptions{
		Data:       req.Data,
		Prehashed:  req.Prehashed,
		SignerOpts: signerOpts,
	}
	signature, err := key.Sign(ctx, opts)
	if err != nil {
		return nil, s.handleKMSError(err)
	}

	return &pb.SignResponse{
		Signature:  signature,
		KeyVersion: opts.KeyVersion,
	}, nil
}

func (s *gRPCKMSServer) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	key, err := s.key(req.KeyId)
	if err != nil {
		return nil, err
	}

	signerOpts, err := protoToSignerOpts(req.Hash, req.Opts)
	if err != nil {
		return nil, err
	}

	err = key.Verify(ctx, &kms.VerifyOptions{
		Signature:  req.Signature,
		Data:       req.Data,
		Prehashed:  req.Prehashed,
		SignerOpts: signerOpts,
		KeyVersion: req.KeyVersion,
	})
	switch {
	case errors.Is(err, kms.ErrInvalidSignature):
		return nil, status.Error(codes.InvalidArgument, err.Error())
	case err != nil:
		return nil, s.handleKMSError(err)
	}

	return &pb.VerifyResponse{}, nil
}

func (s *gRPCKMSServer) ExportPublic(ctx context.Context, req *pb.ExportPublicRequest) (*pb.ExportPublicResponse, error) {
	key, err := s.key(req.KeyId)
	if err != nil {
		return nil, err
	}

	pub, err := key.ExportPublic(ctx)
	if err != nil {
		return nil, s.handleKMSError(err)
	}

	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	return &pb.ExportPublicResponse{PkixAsn1Der: b}, nil
}
