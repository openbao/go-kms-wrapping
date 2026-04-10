// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// package plugintest provides test helpers to launch plugin servers in tests.
package plugintest

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	gp "github.com/hashicorp/go-plugin"
	"github.com/openbao/go-kms-wrapping/plugin/v2"
	"github.com/stretchr/testify/require"
)

const env = "GKW_PLUGIN_TEST_RUN_SERVER"

// Server is used to define a test that will run a plugin server accessible by
// other tests in the same package. The defined test is skipped unless requested
// by [Client].
//
// For example:
//
//	func TestServer_TransitKMS(t *testing.T) {
//		plugintest.Server(t, &plugin.ServeOpts{
//			KMSFactoryFunc: transit.New(),
//		})
//	}
func Server(t *testing.T, opts *plugin.ServeOpts) {
	t.Helper()
	if _, ok := os.LookupEnv(env); !ok {
		t.Skip()
	}
	plugin.Serve(opts)
}

// Client is used to consume a plugin server defined via [Server]. This takes
// the name of the test, spawns the plugin process and returns the corresponding
// [gp.ClientProtocol]. The server is automatically shut down when the test
// completes.
func Client(t *testing.T, test string) gp.ClientProtocol {
	t.Helper()

	cmd := exec.Command(os.Args[0], fmt.Sprintf("--test.run=%s", test))
	cmd.Env = append(cmd.Env, env+"=1")

	client := gp.NewClient(&gp.ClientConfig{
		Cmd:              cmd,
		VersionedPlugins: plugin.PluginSets,
		HandshakeConfig:  plugin.HandshakeConfig,
		AllowedProtocols: []gp.Protocol{gp.ProtocolGRPC},
		AutoMTLS:         true,
	})

	t.Cleanup(func() {
		client.Kill()
	})

	conn, err := client.Client()
	require.NoError(t, err)

	return conn
}
