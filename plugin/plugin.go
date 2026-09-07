// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"errors"
	"os"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

var (
	// ErrPluginShutdown is returned when a plugin client fails because the
	// backing plugin server/process has shut down. Catching this error can be
	// used to respawn plugin processes and retry the call if desired.
	ErrPluginShutdown = errors.New("plugin is shut down")

	// ErrNoInstance is returned when an RPC is called on a remote object that
	// doesn't exist.
	ErrNoInstance = errors.New("instance not found")
)

// ServeOpts configures a KMS plugin server.
type ServeOpts struct {
	// KMSFactoryFunc equips this plugin with a KMS implementation. This is
	// optional and enables External Keys functionality over this plugin in
	// OpenBao.
	KMSFactoryFunc func() kms.KMS

	// WrapperFactoryFunc equips this plugin with a Wrapper implementation. This
	// is optional and enables Auto-Unseal functionality over this plugin in
	// OpenBao.
	WrapperFactoryFunc func() wrapping.Wrapper

	// Metadata registers static metadata for this plugin, available over the
	// metadata protocol.
	Metadata Metadata

	// Logger is optional and automatically initialized with settings compatible
	// with go-plugin clients if not set.
	Logger log.Logger
}

// Metadata holds static metadata for a plugin.
type Metadata struct {
	// SensitiveKMSFields are [kms.ConfigMap] fields taken by [kms.KMS.Open]
	// that are sensitive and should be censored when the config is presented
	// for display.
	SensitiveKMSFields []string

	// SensitiveKeyFields are [kms.ConfigMap] fields taken by [kms.KMS.GetKey]
	// that are sensitive and should be censored when the config is presented
	// for display.
	SensitiveKeyFields []string
}

// Serve is used to serve a KMS plugin. This is typically called in the plugin's
// main function.
func Serve(opts *ServeOpts) {
	logger := opts.Logger
	if logger == nil {
		logger = log.New(&log.LoggerOptions{
			Level:      log.Trace,
			Output:     os.Stderr,
			JSONFormat: true,
		})
	}

	v1 := map[string]plugin.Plugin{
		"metadata": &gRPCMetadataPlugin{
			metadata: &opts.Metadata,
		},
	}

	if opts.KMSFactoryFunc != nil {
		v1["kms"] = &gRPCKMSPlugin{
			factory: opts.KMSFactoryFunc,
			logger:  logger,
		}
	}
	if opts.WrapperFactoryFunc != nil {
		v1["wrapper"] = &gRPCWrapperPlugin{
			factory: opts.WrapperFactoryFunc,
			logger:  logger,
		}
	}

	plugins := map[int]plugin.PluginSet{1: v1}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig:  HandshakeConfig,
		VersionedPlugins: plugins,
		Logger:           logger,
		GRPCServer:       plugin.DefaultGRPCServer,
	})
}

// HandshakeConfig is the handshake config to use with plugins compiled against
// this package.
var HandshakeConfig = plugin.HandshakeConfig{
	MagicCookieKey:   "OPENBAO_KMS_PLUGIN",
	MagicCookieValue: "39704a18-7da7-4bda-9a2d-f7c488d70328",
}

// PluginSets are the versioned plugin sets to use on the client side.
var PluginSets = map[int]plugin.PluginSet{
	1: {
		"kms":      &gRPCKMSPlugin{},
		"wrapper":  &gRPCWrapperPlugin{},
		"metadata": &gRPCMetadataPlugin{},
	},
}

type gRPCWrapperPlugin struct {
	factory func() wrapping.Wrapper
	logger  log.Logger

	// Embedding this will disable the netRPC protocol.
	plugin.NetRPCUnsupportedPlugin
}

type gRPCKMSPlugin struct {
	factory func() kms.KMS
	logger  log.Logger

	// Embedding this will disable the netRPC protocol.
	plugin.NetRPCUnsupportedPlugin
}

type gRPCMetadataPlugin struct {
	metadata *Metadata

	// Embedding this will disable the netRPC protocol.
	plugin.NetRPCUnsupportedPlugin
}
