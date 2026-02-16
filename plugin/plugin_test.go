// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/hashicorp/go-plugin"
	"github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/aead"
	"github.com/stretchr/testify/require"
)

// client is a test helper that spawns a plugin server by re-executing the
// test binary into one of the TestServer_* tests below and returns a client
// connected to it.
func client(t *testing.T, test string) plugin.ClientProtocol {
	cmd := exec.Command(os.Args[0], fmt.Sprintf("--test.run=TestServer_%s", test))
	cmd.Env = append(cmd.Env, "OPENBAO_TEST_SERVER=1")

	plug := plugin.NewClient(&plugin.ClientConfig{
		Cmd:              cmd,
		VersionedPlugins: PluginSets,
		HandshakeConfig:  HandshakeConfig,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		AutoMTLS:         true,
	})

	t.Cleanup(func() {
		plug.Kill()
	})

	client, err := plug.Client()
	require.NoError(t, err)

	return client
}

func TestServer_TestWrapper(t *testing.T) {
	if _, ok := os.LookupEnv("OPENBAO_TEST_SERVER"); !ok {
		t.Skip()
	}
	Serve(&ServeOpts{
		WrapperFactoryFunc: func() wrapping.Wrapper {
			return wrapping.NewTestInitFinalizer([]byte("test"))
		},
	})
}

func TestServer_AeadWrapper(t *testing.T) {
	if _, ok := os.LookupEnv("OPENBAO_TEST_SERVER"); !ok {
		t.Skip()
	}
	Serve(&ServeOpts{
		WrapperFactoryFunc: func() wrapping.Wrapper {
			return aead.NewWrapper()
		},
	})
}

func TestWrapper(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	tests := []struct {
		server string // See client().
		opts   *wrapping.Options
	}{
		{
			server: "TestWrapper",
			opts: &wrapping.Options{
				WithKeyId: "test",
			},
		},
		{
			server: "AeadWrapper",
			opts: &wrapping.Options{
				WithKeyId: "root",
				WithConfigMap: map[string]string{
					"key": base64.StdEncoding.EncodeToString(key),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.server, func(t *testing.T) {
			raw, err := client(t, tt.server).Dispense("wrapper")
			require.NoError(t, err)

			ctx := t.Context()

			wrapper, ok := raw.(interface {
				wrapping.Wrapper
				wrapping.InitFinalizer
			})
			require.True(t, ok)

			_, err = wrapper.SetConfig(
				ctx,
				wrapping.WithKeyId(tt.opts.WithKeyId),
				wrapping.WithConfigMap(tt.opts.WithConfigMap),
			)
			require.NoError(t, err)

			t.Run("Init", func(t *testing.T) {
				require.NoError(t, wrapper.Init(ctx))
			})

			t.Run("Encrypt+Decrypt", func(t *testing.T) {
				input := "foobar"
				blob, err := wrapper.Encrypt(ctx, []byte(input))
				require.NoError(t, err)

				plaintext, err := wrapper.Decrypt(ctx, blob)
				require.NoError(t, err)
				require.Equal(t, input, string(plaintext))
			})

			t.Run("KeyId", func(t *testing.T) {
				id, err := wrapper.KeyId(ctx)
				require.NoError(t, err)
				require.Equal(t, tt.opts.WithKeyId, id)
			})

			t.Run("Finalize", func(t *testing.T) {
				require.NoError(t, wrapper.Finalize(ctx))
				require.ErrorContains(t, wrapper.Finalize(ctx), ErrNoInstance.Error())
			})
		})
	}
}
