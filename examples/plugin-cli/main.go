// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	kmsplugin "github.com/openbao/go-kms-wrapping/plugin/v2"
	"github.com/openbao/go-kms-wrapping/v2"
)

func main() {
	input := flag.String("plaintext", "default plaintext secret",
		"plaintext you'd like to use for encrypt/decrypt using the transit wrapper plugin")
	flag.Parse()

	ctx := context.Background()

	fmt.Println("initializing the transit plugin wrapper...")
	wrapper, cleanup, err := setup(ctx)
	switch {
	case err != nil:
		fmt.Fprintf(os.Stderr, "unable to initialize transit wrapper plugin: %s\n", err)
		os.Exit(1)
	default:
		defer cleanup()
	}

	fmt.Println("encrypting the plaintext...")
	blob, err := wrapper.Encrypt(ctx, []byte(*input))
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to encrypt plaintext: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("decrypting the ciphertext...")
	plaintext, err := wrapper.Decrypt(ctx, blob)
	switch {
	case err != nil:
		fmt.Fprintf(os.Stderr, "unable to encrypt plaintext: %s\n", err)
		os.Exit(1)
	case string(plaintext) != *input:
		fmt.Fprintf(os.Stderr, "%q does not equal %q\n", string(plaintext), *input)
		os.Exit(1)
	}

	fmt.Printf("successfully encrypted/decrypted %q using the transit plugin!\n", *input)

	if finalizer, ok := wrapper.(wrapping.InitFinalizer); ok {
		if err := finalizer.Finalize(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "failed to finalize transit wrapper: %s\n", err)
			os.Exit(1)
		}
	}
}

func setup(ctx context.Context) (wrapping.Wrapper, func(), error) {
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = "transit"

	plug := plugin.NewClient(&plugin.ClientConfig{
		Cmd:              cmd,
		VersionedPlugins: kmsplugin.PluginSets,
		HandshakeConfig:  kmsplugin.HandshakeConfig,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		AutoMTLS:         true,
		Logger:           hclog.NewNullLogger(), // Keep quiet.
	})

	client, err := plug.Client()
	if err != nil {
		plug.Kill()
		return nil, nil, err
	}

	raw, err := client.Dispense("wrapper")
	if err != nil {
		plug.Kill()
		return nil, nil, err
	}

	wrapper := raw.(wrapping.Wrapper)

	if _, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
		"address":    "http://localhost:8200",
		"token":      "root",
		"key_name":   "example",
		"mount_path": "transit",
	})); err != nil {
		return nil, nil, err
	}

	return wrapper, plug.Kill, err
}
