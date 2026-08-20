// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tpm

import (
	"net"
	"os"
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

const (
	swTPMPath = "127.0.0.1:2321"
)

const (
	// These values are defaults for an initial swtpm
	testInitialPCR       = "15:0000000000000000000000000000000000000000000000000000000000000000,23:0000000000000000000000000000000000000000000000000000000000000000"
	defaultUserAuth      = ""
	defaultHierarchyAuth = ""
)

// TestDisableEnv makes sure that we properly get all our settings from a configuration
// map instead of the environment variables
func TestDisableEnv(t *testing.T) {
	// Now test for cases where CKMS values are provided
	checkAndSetEnvVars(t)

	configMap := map[string]string{
		"tpm_path": swTPMPath,
	}

	// Reset the env values to validate we are using the config map ones
	t.Setenv(EnvTPMPath, "bad_tpm_path")

	s := NewWrapper()
	_, err := s.SetConfig(t.Context(), wrapping.WithConfigMap(configMap), wrapping.WithDisallowEnvVars(true))
	require.NoError(t, err)

	// Make sure we can use the key properly.
	input := []byte("foo")
	swi, err := s.Encrypt(t.Context(), input)
	require.NoError(t, err)

	pt, err := s.Decrypt(t.Context(), swi)
	require.NoError(t, err)

	require.True(t, reflect.DeepEqual(input, pt), "expected %s, got %s", input, pt)
}

// Tests base configuration for the TPM
func TestTPMSeal(t *testing.T) {
	t.Setenv(EnvTPMPath, "") // Make sure at least one required value is not set.

	// Do an error check before env vars are set
	s := NewWrapper()
	_, err := s.SetConfig(t.Context())
	require.Error(t, err)

	// Now test for cases where CKMS values are provided
	checkAndSetEnvVars(t)

	configCases := map[string]map[string]string{
		"config": {
			"tpm_path": os.Getenv("TPM_PATH"),
		},
	}

	for name, config := range configCases {
		t.Run(name, func(t *testing.T) {
			s := NewWrapper()
			_, err := s.SetConfig(t.Context(), wrapping.WithConfigMap(config))
			require.NoError(t, err)
		})
	}
}

// Tests end-to-end seal/unseal
func TestTPMSeal_Lifecycle(t *testing.T) {
	checkAndSetEnvVars(t)

	s := NewWrapper()
	_, err := s.SetConfig(t.Context())
	require.NoError(t, err)

	input := []byte("foo")
	swi, err := s.Encrypt(t.Context(), input)
	require.NoError(t, err)

	pt, err := s.Decrypt(t.Context(), swi)
	require.NoError(t, err)

	require.True(t, reflect.DeepEqual(input, pt), "expected %s, got %s", input, pt)
}

// Tests the Encrypt/Decrypt cycle with AAD
func TestTPMSeal_Lifecycle_AAD(t *testing.T) {
	checkAndSetEnvVars(t)

	s := NewWrapper()
	_, err := s.SetConfig(t.Context())
	require.NoError(t, err)

	input := []byte("foo")
	swi, err := s.Encrypt(t.Context(), input, wrapping.WithAad([]byte("myaad")))
	require.NoError(t, err)

	pt, err := s.Decrypt(t.Context(), swi, wrapping.WithAad([]byte("myaad")))
	require.NoError(t, err)

	require.True(t, reflect.DeepEqual(input, pt), "expected %s, got %s", input, pt)
}

// Tests the Encrypt/Decrypt cycle with userAuth
func TestTPMSeal_Lifecycle_UserAuth_Pass(t *testing.T) {
	checkAndSetEnvVars(t)

	os.Setenv(EnvUserAuth, defaultUserAuth)

	s := NewWrapper()
	_, err := s.SetConfig(t.Context())
	require.NoError(t, err)

	input := []byte("foo")
	swi, err := s.Encrypt(t.Context(), input)
	require.NoError(t, err)

	os.Setenv(EnvUserAuth, defaultUserAuth)

	_, err = s.Decrypt(t.Context(), swi)
	require.NoError(t, err)
}

// Tests the Encrypt/Decrypt cycle with incorrect userAuth
func TestTPMSeal_Lifecycle_UserAuth_Fail(t *testing.T) {
	checkAndSetEnvVars(t)

	os.Setenv(EnvUserAuth, defaultUserAuth)

	s := NewWrapper()

	_, err := s.SetConfig(t.Context())
	require.NoError(t, err)

	input := []byte("foo")
	swi, err := s.Encrypt(t.Context(), input)
	require.NoError(t, err)

	os.Setenv(EnvUserAuth, "badpassword")

	_, err = s.Decrypt(t.Context(), swi)
	require.NoError(t, err)
}

// Tests the Encrypt/Decrypt cycle with PCR value
func TestTPMSeal_Lifecycle_PCR_Pass(t *testing.T) {
	checkAndSetEnvVars(t)

	os.Setenv(EnvPCRValues, testInitialPCR)

	s := NewWrapper()
	_, err := s.SetConfig(t.Context())
	require.NoError(t, err)

	// Test Encrypt and Decrypt calls
	input := []byte("foo")
	swi, err := s.Encrypt(t.Context(), input)
	require.NoError(t, err)

	os.Setenv(EnvPCRValues, testInitialPCR)

	_, err = s.Decrypt(t.Context(), swi)
	require.NoError(t, err)
}

// Tests the Encrypt/Decrypt cycle with PCR values altered
func TestTPMSeal_Lifecycle_PCR_Fail(t *testing.T) {
	checkAndSetEnvVars(t)

	os.Setenv(EnvPCRValues, testInitialPCR)

	s := NewWrapper()
	_, err := s.SetConfig(t.Context())
	require.NoError(t, err)

	// Test Encrypt and Decrypt calls
	input := []byte("foo")
	swi, err := s.Encrypt(t.Context(), input)
	require.NoError(t, err)

	// export TPM2TOOLS_TCTI="swtpm:port=2321"
	// $ tpm2_pcrread sha256:23
	// sha256:
	// 	23: 0x0000000000000000000000000000000000000000000000000000000000000000

	// use pcr23
	os.Setenv(EnvPCRValues, "23:0000000000000000000000000000000000000000000000000000000000000000")
	pcr := uint(23)

	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)

	defer tpmDevice.Close()
	rwr := transport.FromReadWriter(tpmDevice)

	// read it just to be sure
	pcrReadRsp, err := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcr),
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	// then extend it
	_, err = tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(uint32(pcr)),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: tpm2.TPMAlgSHA256,
					Digest:  pcrReadRsp.PCRValues.Digests[0].Buffer,
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	tpmDevice.Close()

	// decryption should fail (eg err should not be nil)
	_, err = s.Decrypt(t.Context(), swi)
	require.Error(t, err)
}

// checkAndSetEnvVars check and sets the required env vars. It will skip tests that are
// not ran as acceptance tests since they require calling to external APIs.
func checkAndSetEnvVars(t *testing.T) {
	t.Helper()

	// Skip tests if we are not running acceptance tests
	if os.Getenv("TPM_ACC_TESTS") == "" {
		t.SkipNow()
	}

	if os.Getenv(EnvTPMPath) == "" {
		os.Setenv(EnvTPMPath, swTPMPath)
	}

}
