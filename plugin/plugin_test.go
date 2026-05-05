// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin_test

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/openbao/go-kms-wrapping/plugin/v2"
	"github.com/openbao/go-kms-wrapping/plugin/v2/plugintest"
	"github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/aead"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/stretchr/testify/require"
)

func TestServer_TestWrapper(t *testing.T) {
	plugintest.Server(t, &plugin.ServeOpts{
		WrapperFactoryFunc: func() wrapping.Wrapper {
			return wrapping.NewTestInitFinalizer([]byte("test"))
		},
	})
}

func TestServer_AeadWrapper(t *testing.T) {
	plugintest.Server(t, &plugin.ServeOpts{
		WrapperFactoryFunc: func() wrapping.Wrapper {
			return aead.NewWrapper()
		},
	})
}

func TestWrapper(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	tests := []struct {
		server string
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
			server := fmt.Sprintf("TestServer_%s", tt.server)
			raw, err := plugintest.Client(t, server).Dispense("wrapper")
			require.NoError(t, err)

			wrapper, ok := raw.(interface {
				wrapping.Wrapper
				wrapping.InitFinalizer
			})
			require.True(t, ok)

			ctx := t.Context()

			t.Run("NoConfig", func(t *testing.T) {
				_, err := wrapper.KeyId(ctx)
				require.ErrorIs(t, err, plugin.ErrNoInstance)
			})

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
				require.ErrorIs(t, wrapper.Finalize(ctx), plugin.ErrNoInstance)
			})
		})
	}
}

func TestServer_UnimplementedKMS(t *testing.T) {
	plugintest.Server(t, &plugin.ServeOpts{
		KMSFactoryFunc: func() kms.KMS {
			return kms.UnimplementedKMS{}
		},
	})
}

// This test really just ensures that we dispense the right type, and that some
// sentinel errors are passed over the wire as expected. Tests against real KMS
// implementations should live with the implementations themselves, running the
// same test suite against both remote and local instances. This should ensure
// better coverage than picking any particular implementation to test against in
// this package, or creating a mock implementation.
func TestKMS(t *testing.T) {
	raw, err := plugintest.Client(t, "TestServer_UnimplementedKMS").Dispense("kms")
	require.NoError(t, err)

	service, ok := raw.(kms.KMS)
	require.True(t, ok)

	ctx := t.Context()
	_, err = service.GetKey(ctx, &kms.KeyOptions{})
	require.ErrorIs(t, err, plugin.ErrNoInstance)
	require.ErrorIs(t, service.Close(ctx), plugin.ErrNoInstance)
	require.ErrorIs(t, service.Open(ctx, &kms.OpenOptions{}), kms.ErrNotImplemented)
}
