// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// package softhsm provides helpers to test PKCS#11 code with SoftHSM.
package softhsm

import (
	"crypto/rand"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// SoftHSM is a test helper that allows arbitrary initialization of tokens.
type SoftHSM struct {
	Path  string // Path is the dynamic library path to use.
	slots int    // slots must be incremented with each `softhsm2-util --init-token` command.

	t *testing.T
}

// New creates a new SoftHSM test.
func New(t *testing.T) *SoftHSM {
	t.Helper()

	if yes, err := strconv.ParseBool(os.Getenv("SOFTHSM_TESTS")); err != nil || !yes {
		t.Skip("Skipping SoftHSM test, set SOFTHSM_TESTS=1 to run")
	}

	tokendir, configdir := t.TempDir(), t.TempDir()

	// Create a SoftHSM configuration file that'll point storage at the
	// temporary directory. This gets us a fresh "instance" that'll be cleaned
	// up automatically.
	config := strings.Join([]string{
		"log.level = INFO",
		"directories.tokendir = " + tokendir,
	}, "\n")

	// Write the config file and point the SoftHSM library at it by setting the
	// SOFTHSM2_CONF environment variable.
	configPath := path.Join(configdir, "softhsm2.conf")
	t.Setenv("SOFTHSM2_CONF", configPath)
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o644))

	path := "/usr/lib/softhsm/libsofthsm2.so"
	if env := os.Getenv("SOFTHSM_LIBRARY_PATH"); env != "" {
		path = env
	}

	return &SoftHSM{Path: path, t: t}
}

// InitToken initializes a new token for testing.
func (s *SoftHSM) InitToken() (label, pin string) {
	label, pin = rand.Text(), rand.Text()

	// We can't do this via PKCS#11.
	cmd := exec.Command(
		"softhsm2-util", "--init-token",
		"--slot", strconv.Itoa(s.slots), "--label", label,
		"--pin", pin, "--so-pin", pin,
	)

	cmd.Stderr = os.Stderr
	require.NoError(s.t, cmd.Run())

	s.slots++

	return label, pin
}
