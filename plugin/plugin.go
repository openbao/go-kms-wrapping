// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/hashicorp/go-plugin"
	"github.com/openbao/go-kms-wrapping/plugin/v2/pb"
	"github.com/openbao/go-kms-wrapping/v2"
	"google.golang.org/grpc"
)

// HandshakeConfig is a shared config that can be used regardless of wrapper, to
// avoid having to know type-specific things about each plugin
var HandshakeConfig = plugin.HandshakeConfig{
	MagicCookieKey:   "HASHICORP_GKW_PLUGIN",
	MagicCookieValue: "wrapper",
}

// wrapper embeds Plugin and is used as the top-level
type wrapper struct {
	// Embeding this will disable the netRPC protocol
	plugin.NetRPCUnsupportedPlugin

	impl wrapping.Wrapper
}

// ServePlugin is a generic function to start serving a wrapper as a plugin
func ServePlugin(wrapper wrapping.Wrapper, opt ...Option) error {
	opts, err := getOpts(opt...)
	if err != nil {
		return err
	}

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGHUP)
	go func() {
		for {
			<-signalCh
		}
	}()

	wrapServer, err := NewWrapperPluginServer(wrapper)
	if err != nil {
		return err
	}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		VersionedPlugins: map[int]plugin.PluginSet{
			1: {"wrapping": wrapServer},
		},
		Logger:     opts.withLogger,
		GRPCServer: plugin.DefaultGRPCServer,
	})
	return nil
}

func NewWrapperPluginServer(impl wrapping.Wrapper) (*wrapper, error) {
	if impl == nil {
		return nil, fmt.Errorf("empty underlying wrapper passed in")
	}

	return &wrapper{
		impl: impl,
	}, nil
}

func NewWrapperPluginClient(pluginPath string, opt ...Option) (*plugin.Client, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	return plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: HandshakeConfig,
		VersionedPlugins: map[int]plugin.PluginSet{
			1: {"wrapping": &wrapper{}},
		},
		Cmd:              exec.Command(pluginPath),
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		Logger:           opts.withLogger,
		AutoMTLS:         true,
		SecureConfig:     opts.withSecureConfig,
	}), nil
}

func (w *wrapper) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterWrapperServer(s, &gRPCWrapperServer{impl: w.impl})
	return nil
}

func (w *wrapper) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return &gRPCWrapperClient{impl: pb.NewWrapperClient(c)}, nil
}
