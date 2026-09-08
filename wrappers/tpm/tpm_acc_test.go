// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package tpm

import (
	"bytes"
	"net"
	"os"
	"reflect"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
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
	testInitialPCR = "15:0000000000000000000000000000000000000000000000000000000000000000,23:0000000000000000000000000000000000000000000000000000000000000000"
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

// Tests end-to-end seal/unseal
func TestTPMSeal_LifecycleExternalKey(t *testing.T) {
	checkAndSetEnvVars(t)

	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)

	defer tpmDevice.Close()
	rwr := transport.FromReadWriter(tpmDevice)

	pcrString := "23:0000000000000000000000000000000000000000000000000000000000000000"
	t.Setenv(EnvPCRValues, pcrString)

	userAuthPassword := "bar"
	t.Setenv(EnvUserAuth, userAuthPassword)

	// get the specified pcrs
	_, pcrList, pcrHash, err := getPCRMap(tpm2.TPMAlgSHA256, pcrString)
	require.NoError(t, err)

	// create an H2 primary; this is just for convenience. you could create any primary with auth as long as you're consistent
	cPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Name:   tpm2.HandleName(tpm2.TPMRHOwner),
			Auth:   tpm2.PasswordAuth([]byte(nil)),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, err = flush.Execute(rwr)
	}()

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
			},
		},
	}

	sessTrialPolicy, sessTrialPolicycleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial()}...)
	require.NoError(t, err)
	defer sessTrialPolicycleanup()

	_, err = tpm2.PolicyPCR{
		PolicySession: sessTrialPolicy.Handle(),
		PcrDigest: tpm2.TPM2BDigest{
			Buffer: pcrHash,
		},
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
	}.Execute(rwr)
	require.NoError(t, err)

	_, err = tpm2.PolicyAuthValue{
		PolicySession: sessTrialPolicy.Handle(),
	}.Execute(rwr)
	require.NoError(t, err)

	// now that we have the pcr's set, get its digest
	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sessTrialPolicy.Handle(),
	}.Execute(rwr)
	require.NoError(t, err)

	// create the TPM AES key with the policies
	aCreate, err := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgSymCipher,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				UserWithAuth:        false,
				SensitiveDataOrigin: true,
				Decrypt:             true,
				SignEncrypt:         true,
			},
			AuthPolicy: pgd.PolicyDigest, // set the pcr auth policy
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgSymCipher,
				&tpm2.TPMSSymCipherParms{
					Sym: tpm2.TPMTSymDefObject{
						Algorithm: tpm2.TPMAlgAES,
						Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCTR),
						KeyBits: tpm2.NewTPMUSymKeyBits(
							tpm2.TPMAlgAES,
							tpm2.TPMKeyBits(256),
						),
					},
				},
			),
		}),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(userAuthPassword), // set the userAuth password for the AES Key
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	aesPrivate := aCreate.OutPrivate
	aesPublic := aCreate.OutPublic

	// now load the key
	aesKey, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPrivate: aesPrivate,
		InPublic:  aesPublic,
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: aesKey.ObjectHandle,
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	// create a keyfile representation (eg, a PEM format for the TPM based sealing key)
	tkf := keyfile.NewTPMKey(
		keyfile.OIDLoadableKey,
		aesPublic,
		aesPrivate,
		keyfile.WithParent(tpm2.TPMHandle(tpm2.TPMRHOwner)),
		keyfile.WithUserAuth([]byte(userAuthPassword)),
	)

	// get the keyfiles PEM bytes
	kfb := new(bytes.Buffer)
	err = keyfile.Encode(kfb, tkf)
	require.NoError(t, err)

	// cleanup
	err = sessTrialPolicycleanup()
	require.NoError(t, err)

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: aesKey.ObjectHandle,
	}
	_, err = flushContextCmd.Execute(rwr)
	require.NoError(t, err)

	flush := tpm2.FlushContext{
		FlushHandle: cPrimary.ObjectHandle,
	}
	_, err = flush.Execute(rwr)
	require.NoError(t, err)

	tpmDevice.Close()

	t.Setenv(EnvKey, string(kfb.Bytes()))

	//********************************

	s := NewWrapper()
	_, err = s.SetConfig(t.Context())
	require.NoError(t, err)

	input := []byte("foo")
	swi, err := s.Encrypt(t.Context(), input)
	require.NoError(t, err)

	pt, err := s.Decrypt(t.Context(), swi)
	require.NoError(t, err)

	require.True(t, reflect.DeepEqual(input, pt), "expected %s, got %s", input, pt)
}

// Tests the Encrypt/Decrypt cycle with userAuth
func TestTPMSeal_Lifecycle_UserAuth_Pass(t *testing.T) {
	checkAndSetEnvVars(t)

	t.Setenv(EnvUserAuth, "mypassword")

	s := NewWrapper()
	_, err := s.SetConfig(t.Context())
	require.NoError(t, err)

	input := []byte("foo")
	swi, err := s.Encrypt(t.Context(), input)
	require.NoError(t, err)

	t.Setenv(EnvUserAuth, "mypassword")

	_, err = s.Decrypt(t.Context(), swi)
	require.NoError(t, err)
}

// Tests the Encrypt/Decrypt cycle with incorrect userAuth
func TestTPMSeal_Lifecycle_UserAuth_Fail(t *testing.T) {
	checkAndSetEnvVars(t)

	t.Setenv(EnvUserAuth, "mypassword")

	s := NewWrapper()

	_, err := s.SetConfig(t.Context())
	require.NoError(t, err)

	input := []byte("foo")
	swi, err := s.Encrypt(t.Context(), input)
	require.NoError(t, err)

	t.Setenv(EnvUserAuth, "badpassword")

	pt, err := s.Decrypt(t.Context(), swi)
	require.NoError(t, err)

	require.True(t, reflect.DeepEqual(input, pt), "expected %s, got %s", input, pt)
}

// Tests the Encrypt/Decrypt cycle with PCR value
func TestTPMSeal_Lifecycle_PCR_Pass(t *testing.T) {
	checkAndSetEnvVars(t)

	t.Setenv(EnvPCRValues, testInitialPCR)

	s := NewWrapper()
	_, err := s.SetConfig(t.Context())
	require.NoError(t, err)

	// Test Encrypt and Decrypt calls
	input := []byte("foo")
	swi, err := s.Encrypt(t.Context(), input)
	require.NoError(t, err)

	t.Setenv(EnvPCRValues, testInitialPCR)

	pt, err := s.Decrypt(t.Context(), swi)
	require.NoError(t, err)

	require.True(t, reflect.DeepEqual(input, pt), "expected %s, got %s", input, pt)
}

// Tests the Encrypt/Decrypt cycle with PCR values altered
func TestTPMSeal_Lifecycle_PCR_Fail(t *testing.T) {
	checkAndSetEnvVars(t)

	t.Setenv(EnvPCRValues, testInitialPCR)

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
	t.Setenv(EnvPCRValues, "23:0000000000000000000000000000000000000000000000000000000000000000")
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
		t.Setenv(EnvTPMPath, swTPMPath)
	}

}
