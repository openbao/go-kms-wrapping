// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package stackitkms

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEmbeddedPrivateKey(t *testing.T) {
	const key = "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n"
	saKey := fmt.Sprintf(`{"credentials": {"privateKey": %q}}`, key)

	got, err := embeddedPrivateKey(saKey, "")
	require.NoError(t, err)
	require.Equal(t, key, got)

	path := filepath.Join(t.TempDir(), "sa_key.json")
	require.NoError(t, os.WriteFile(path, []byte(saKey), 0o600))
	got, err = embeddedPrivateKey("", path)
	require.NoError(t, err)
	require.Equal(t, key, got)

	_, err = embeddedPrivateKey(`{"credentials": {}}`, "")
	require.ErrorContains(t, err, "no private key")

	_, err = embeddedPrivateKey("not json", "")
	require.ErrorContains(t, err, "parse")

	_, err = embeddedPrivateKey("", filepath.Join(t.TempDir(), "missing.json"))
	require.ErrorContains(t, err, "read")
}

func TestNewSdkClientDisallowEnvVars(t *testing.T) {
	base := clientConfig{
		projectId:       testProjectId,
		region:          testRegion,
		keyRingId:       testKeyRingId,
		disallowEnvVars: true,
	}

	_, err := newSdkClient(base)
	require.ErrorContains(t, err, "explicitly")

	// a private key alone still leaves the SDK searching for the service
	// account key itself
	cc := base
	cc.privateKey = "some-key"
	_, err = newSdkClient(cc)
	require.ErrorContains(t, err, "explicitly")

	cc = base
	cc.serviceAccountKey = `{"credentials": {}}`
	_, err = newSdkClient(cc)
	require.ErrorContains(t, err, "no private key")

	cc = base
	cc.token = "some-token"
	client, err := newSdkClient(cc)
	require.NoError(t, err)
	require.NotNil(t, client)
}
