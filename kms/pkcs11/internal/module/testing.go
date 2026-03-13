// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package module

import (
	"crypto/rand"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
)

const (
	EnvPathSoftHSM  = "SOFTHSM_PATH"
	EnvPathKryoptic = "KRYOPTIC_PATH"

	TestPin = "abcdef-123456"
)

// TestPath is set by TestSetup and holds the module path to test against.
var TestPath string

func TestSetup(m *testing.M) {
	var exit int

	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}

	// A temp directory for config files:
	configdir, err := os.MkdirTemp("", "")
	must(err)
	defer os.RemoveAll(configdir)

	// A temp directory for token storage:
	tokendir, err := os.MkdirTemp("", "")
	must(err)
	defer os.RemoveAll(tokendir)

	// Set up and test SoftHSM:
	if env := os.Getenv(EnvPathSoftHSM); env != "" {
		fmt.Println("=== Test SoftHSM ===")

		config := strings.Join([]string{
			"log.level = INFO",
			"directories.tokendir = " + tokendir,
		}, "\n")

		configpath := path.Join(configdir, "softhsm2.conf")
		os.Setenv("SOFTHSM2_CONF", configpath)
		must(os.WriteFile(configpath, []byte(config), 0o644))

		TestPath = env
		exit = max(exit, m.Run())
	}

	// Set up and test Kryoptic:
	if env := os.Getenv(EnvPathKryoptic); env != "" {
		fmt.Println("=== Test Kryoptic ===")

		// Increase this if more slots are ever needed; unfortunately Kryoptic
		// does not allow for dynamic slot allocation like SoftHSM does.
		var config []string
		for slot := range 5 {
			config = append(config,
				"[[slots]]",
				fmt.Sprintf("slot = %d", slot),
				`dbtype = "sqlite"`,
				fmt.Sprintf(`dbargs = "%s-%d.sql"`, tokendir, slot),
			)
		}

		configpath := path.Join(configdir, "kryoptic.conf")
		os.Setenv("KRYOPTIC_CONF", configpath)
		must(os.WriteFile(configpath, []byte(strings.Join(config, "\n")), 0o644))

		TestPath = env
		exit = max(exit, m.Run())
	}

	os.Exit(exit)
}

// TestOpen is a test helper that opens and automatically drops a module on test
// completion, handling all errors.
func TestOpen(t *testing.T) *Ref {
	t.Helper()

	mod, err := Open(TestPath)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, mod.Drop())
	})

	return mod
}

func TestTokens(t *testing.T, n uint) (*Ref, []*Token) {
	t.Helper()

	mod := TestOpen(t)
	var tokens []*Token

	for slot := range n {
		func() {
			// Initialize the token and set the Security Officer's PIN.
			require.NoError(t, mod.InitToken(slot, TestPin, rand.Text()))

			// Open a session as Security Officer.
			session, err := mod.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
			require.NoError(t, err)
			defer func() {
				require.NoError(t, mod.CloseSession(session))
			}()

			// Log in.
			require.NoError(t, mod.Login(session, pkcs11.CKU_SO, TestPin))
			defer func() {
				require.NoError(t, mod.Logout(session))
			}()

			// Set the User's PIN.
			require.NoError(t, mod.InitPIN(session, TestPin))
		}()

		info, err := mod.GetTokenInfo(slot)
		require.NoError(t, err)

		tokens = append(tokens, &Token{
			ID: slot, Info: info,
		})

		// Force SoftHSM to refresh the token list.
		_, err = mod.GetSlotList(true)
		require.NoError(t, err)
	}

	return mod, tokens
}
