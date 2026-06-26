// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package openstackbarbican

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

func TestNormalizeSecretRef(t *testing.T) {
	tests := map[string]string{
		"a1b2c3d4-e5f6-47aa-8bbb-123456789abc":                                                  "a1b2c3d4-e5f6-47aa-8bbb-123456789abc",
		"https://barbican.example/v1/secrets/a1b2c3d4-e5f6-47aa-8bbb-123456789abc":              "a1b2c3d4-e5f6-47aa-8bbb-123456789abc",
		"https://barbican.example:9311/v1/secrets/a1b2c3d4-e5f6-47aa-8bbb-123456789abc/payload": "a1b2c3d4-e5f6-47aa-8bbb-123456789abc",
	}

	for input, expected := range tests {
		t.Run(input, func(t *testing.T) {
			actual, err := normalizeSecretRef(input)
			require.NoError(t, err)
			require.Equal(t, expected, actual)
		})
	}
}

func TestNormalizeSecretRefRejectsInvalidValues(t *testing.T) {
	for _, input := range []string{
		"",
		"not a uuid",
		"https://barbican.example/v1/orders/a1b2",
		"https://barbican.example/v1/secrets/a1b2c3d4-e5f6-47aa-8bbb-123456789abc/metadata",
	} {
		t.Run(input, func(t *testing.T) {
			_, err := normalizeSecretRef(input)
			require.Error(t, err)
			require.Contains(t, err.Error(), "openstackbarbican:")
		})
	}
}

func TestSetConfigRejectsPlaintextEndpoint(t *testing.T) {
	w := NewWrapper()
	w.newClient = func(context.Context, *options) (barbicanClient, error) {
		t.Fatal("client should not be created for an insecure endpoint")
		return nil, nil
	}

	_, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		configSecretRef: "a1b2c3d4-e5f6-47aa-8bbb-123456789abc",
		configEndpoint:  "http://barbican.example/v1",
	}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "endpoint must use https")
}

func TestNormalizeEndpointRequiresHTTPS(t *testing.T) {
	endpoint, err := normalizeEndpoint("https://barbican.example/v1/")
	require.NoError(t, err)
	require.Equal(t, "https://barbican.example/v1", endpoint)

	_, err = normalizeEndpoint("http://barbican.example/v1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "endpoint must use https")
}

func TestSetConfigFetchesPayloadAndEncryptsLocally(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x42}, 32)
	w := NewWrapper()
	w.newClient = fakeClientFactory(&fakeBarbicanClient{
		secret: &barbicanSecret{
			SecretType:   string(secretTypeSymmetric),
			ContentTypes: map[string]string{"default": contentTypeOctetStream},
		},
		payload: key,
	})

	config, err := w.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
		configSecretRef: "https://barbican.example/v1/secrets/a1b2c3d4-e5f6-47aa-8bbb-123456789abc",
		configEndpoint:  "https://barbican.internal:9311/v1",
	}))
	require.NoError(t, err)
	require.Equal(t, "a1b2c3d4-e5f6-47aa-8bbb-123456789abc", config.Metadata[configSecretID])
	require.Equal(t, "https://barbican.internal:9311/v1", config.Metadata[configEndpoint])

	keyID, err := w.KeyId(ctx)
	require.NoError(t, err)
	require.Contains(t, keyID, "a1b2c3d4-e5f6-47aa-8bbb-123456789abc:")

	blob, err := w.Encrypt(ctx, []byte("root key material"), wrapping.WithAad([]byte("aad")))
	require.NoError(t, err)
	require.NotNil(t, blob.KeyInfo)
	require.Equal(t, keyID, blob.KeyInfo.KeyId)

	plaintext, err := w.Decrypt(ctx, blob, wrapping.WithAad([]byte("aad")))
	require.NoError(t, err)
	require.Equal(t, []byte("root key material"), plaintext)
}

func TestSetConfigValidatesPayload(t *testing.T) {
	for name, tc := range map[string]struct {
		secret  *barbicanSecret
		payload []byte
	}{
		"wrong secret type": {
			secret:  &barbicanSecret{SecretType: "opaque", ContentTypes: map[string]string{"default": contentTypeOctetStream}},
			payload: bytes.Repeat([]byte{0x42}, 32),
		},
		"wrong content type": {
			secret:  &barbicanSecret{SecretType: string(secretTypeSymmetric), ContentTypes: map[string]string{"default": "text/plain"}},
			payload: bytes.Repeat([]byte{0x42}, 32),
		},
		"missing content type": {
			secret:  &barbicanSecret{SecretType: string(secretTypeSymmetric), ContentTypes: map[string]string{}},
			payload: bytes.Repeat([]byte{0x42}, 32),
		},
		"short payload": {
			secret:  &barbicanSecret{SecretType: string(secretTypeSymmetric), ContentTypes: map[string]string{"default": contentTypeOctetStream}},
			payload: bytes.Repeat([]byte{0x42}, 31),
		},
		"long payload": {
			secret:  &barbicanSecret{SecretType: string(secretTypeSymmetric), ContentTypes: map[string]string{"default": contentTypeOctetStream}},
			payload: bytes.Repeat([]byte{0x42}, 33),
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := NewWrapper()
			w.newClient = fakeClientFactory(&fakeBarbicanClient{secret: tc.secret, payload: tc.payload})

			_, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
				configSecretRef: "a1b2c3d4-e5f6-47aa-8bbb-123456789abc",
				configEndpoint:  "https://barbican.example/v1",
			}))
			require.Error(t, err)
			require.Contains(t, err.Error(), "openstackbarbican:")
		})
	}
}

func TestKeyIDDifferentiatesEndpointForSameSecretUUID(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x42}, 32)
	secretRef := "a1b2c3d4-e5f6-47aa-8bbb-123456789abc"
	first := configuredTestWrapper(t, key, secretRef, "https://barbican-a.example/v1")
	second := configuredTestWrapper(t, key, secretRef, "https://barbican-b.example/v1")

	firstID, err := first.KeyId(ctx)
	require.NoError(t, err)
	secondID, err := second.KeyId(ctx)
	require.NoError(t, err)

	require.Contains(t, firstID, secretRef+":")
	require.Contains(t, secondID, secretRef+":")
	require.NotEqual(t, firstID, secondID)
}

func TestSetConfigRetriesTransientInitialFetchFailures(t *testing.T) {
	ctx := context.Background()
	client := &fakeBarbicanClient{
		secret: &barbicanSecret{
			SecretType:   string(secretTypeSymmetric),
			ContentTypes: map[string]string{"default": contentTypeOctetStream},
		},
		payload:      bytes.Repeat([]byte{0x42}, 32),
		metadataErrs: []error{transientStatusError(http.StatusServiceUnavailable), transientStatusError(http.StatusTooManyRequests)},
	}

	w := NewWrapper()
	w.newClient = fakeClientFactory(client)
	w.sleep = func(context.Context, int) error { return nil }

	_, err := w.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
		configSecretRef: "a1b2c3d4-e5f6-47aa-8bbb-123456789abc",
		configEndpoint:  "https://barbican.example/v1",
	}))
	require.NoError(t, err)
	require.Equal(t, 3, client.metadataCalls)
	require.Equal(t, 1, client.payloadCalls)
}

func TestSetConfigDoesNotRetryPermanentInitialFetchFailures(t *testing.T) {
	client := &fakeBarbicanClient{
		metadataErrs: []error{transientStatusError(http.StatusForbidden)},
	}
	w := NewWrapper()
	w.newClient = fakeClientFactory(client)
	w.sleep = func(context.Context, int) error { return nil }

	_, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		configSecretRef: "a1b2c3d4-e5f6-47aa-8bbb-123456789abc",
		configEndpoint:  "https://barbican.example/v1",
	}))
	require.Error(t, err)
	require.Equal(t, 1, client.metadataCalls)
}

func configuredTestWrapper(t *testing.T, key []byte, secretRef string, endpoint string) *Wrapper {
	t.Helper()
	w := NewWrapper()
	w.newClient = fakeClientFactory(&fakeBarbicanClient{
		secret: &barbicanSecret{
			SecretType:   string(secretTypeSymmetric),
			ContentTypes: map[string]string{"default": contentTypeOctetStream},
		},
		payload: key,
	})
	_, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		configSecretRef: secretRef,
		configEndpoint:  endpoint,
	}))
	require.NoError(t, err)
	return w
}

func fakeClientFactory(client *fakeBarbicanClient) func(context.Context, *options) (barbicanClient, error) {
	return func(_ context.Context, opts *options) (barbicanClient, error) {
		if client.identity == "" {
			client.identity = opts.withEndpoint
		}
		return client, nil
	}
}

type fakeBarbicanClient struct {
	secret   *barbicanSecret
	payload  []byte
	identity string

	metadataErrs []error
	payloadErrs  []error

	metadataCalls int
	payloadCalls  int
}

func (f *fakeBarbicanClient) GetSecret(_ context.Context, _ string) (*barbicanSecret, error) {
	f.metadataCalls++
	if len(f.metadataErrs) > 0 {
		err := f.metadataErrs[0]
		f.metadataErrs = f.metadataErrs[1:]
		return nil, err
	}
	if f.secret == nil {
		return nil, errors.New("missing fake secret")
	}
	return f.secret, nil
}

func (f *fakeBarbicanClient) GetPayload(_ context.Context, _ string, _ string) ([]byte, error) {
	f.payloadCalls++
	if len(f.payloadErrs) > 0 {
		err := f.payloadErrs[0]
		f.payloadErrs = f.payloadErrs[1:]
		return nil, err
	}
	return f.payload, nil
}

func (f *fakeBarbicanClient) Identity() string {
	return f.identity
}

type statusError struct {
	status int
}

func transientStatusError(status int) error {
	return statusError{status: status}
}

func (e statusError) Error() string {
	return fmt.Sprintf("status %d", e.status)
}

func (e statusError) GetStatusCode() int {
	return e.status
}
