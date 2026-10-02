// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package tpm

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"

	"context"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

const Type wrapping.WrapperType = "tpm"

const (
	EnvTPMPath       = "TPM_PATH"
	EnvPCRValues     = "TPM_PCRVALUES"
	EnvUserAuth      = "TPM_USERAUTH"
	EnvHierarchyAuth = "TPM_HIERARCHYAUTH"
	EnvKey           = "TPM_KEY"
)

// Configures and manages the TPM SRK encryption wrapper
//
//	Values here are set using setConfig or options
type TPMWrapper struct {
	tpmPath       string
	pcrValues     string
	userAuth      string
	hierarchyAuth string
	key           string
	currentKeyId  *atomic.Value
}

var (
	_ wrapping.Wrapper = (*TPMWrapper)(nil)
)

// parameter names used in configuration file
const (
	tpmPath        = "tpm_path"
	pcrValues      = "pcr_values"
	userAuth       = "user_auth"
	hierarchyuAuth = "hierarchy_auth"
	key            = "key"
)

// struct used to encode the TPM sealing key and specifications about it
type Secret struct {
	Version int              `json:"version"`
	PCRs    map[int32]string `json:"pcrs"`
	TPMKey  string           `json:"tpmKey"`
}

const (
	TPMEncrypt    = iota
	secretVersion = 1
)

// Initialize a TPM based encryption wrapper
func NewWrapper() *TPMWrapper {

	s := &TPMWrapper{
		currentKeyId: new(atomic.Value),
	}
	s.currentKeyId.Store("")
	return s
}

// Set the configuration options
func (s *TPMWrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	// check overrides and require a TPM either way
	switch {
	case !opts.Options.WithDisallowEnvVars && os.Getenv(EnvTPMPath) != "":
		s.tpmPath = os.Getenv(EnvTPMPath)
	case opts.withTPMPath != "":
		s.tpmPath = opts.withTPMPath
	default:
		return nil, errors.New("'tpm_path' required but not found for wrapper configuration")
	}

	switch {
	case !opts.Options.WithDisallowEnvVars && os.Getenv(EnvPCRValues) != "":
		s.pcrValues = os.Getenv(EnvPCRValues)
	case opts.withPCRValues != "":
		s.pcrValues = opts.withPCRValues
	}

	switch {
	case !opts.Options.WithDisallowEnvVars && os.Getenv(EnvUserAuth) != "":
		s.userAuth = os.Getenv(EnvUserAuth)
	case opts.withUserAuth != "":
		s.userAuth = opts.withUserAuth
	}

	switch {
	case !opts.Options.WithDisallowEnvVars && os.Getenv(EnvKey) != "":
		s.key = os.Getenv(EnvKey)
	case opts.withKey != "":
		s.key = opts.withKey
	}

	switch {
	case !opts.Options.WithDisallowEnvVars && os.Getenv(EnvHierarchyAuth) != "":
		s.hierarchyAuth = os.Getenv(EnvHierarchyAuth)
	case opts.withHierarchyAuth != "":
		s.hierarchyAuth = opts.withHierarchyAuth
	}

	// Map that holds non-sensitive configuration info to return
	// we're returning the PCR's because its not sensitive and can get encoded in the BlobInfo/KeyInfo
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata[pcrValues] = s.pcrValues
	return wrapConfig, nil
}

func (s *TPMWrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return Type, nil
}

func (s *TPMWrapper) KeyId(_ context.Context) (string, error) {
	return s.currentKeyId.Load().(string), nil
}

// Encrypts data using a TPM's Storage Root Key (SRK)
func (s *TPMWrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, errors.New("go-kms-wrapping: given plaintext for encryption is nil")
	}

	// open the tpm
	rwc, err := openTPM(s.tpmPath)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: can't open TPM [%s]: %v", s.tpmPath, err)
	}
	defer rwc.Close()
	rwr := transport.FromReadWriter(rwc)

	// get the specified pcrs
	pcrMap, pcrList, pcrHash, err := getPCRMap(tpm2.TPMAlgSHA256, s.pcrValues)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping:  Could not get PCRMap: %s", err)
	}

	// create an H2 primary;
	// see https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent
	cPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Name:   tpm2.HandleName(tpm2.TPMRHOwner),
			Auth:   tpm2.PasswordAuth([]byte(s.hierarchyAuth)),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: can't create primary %v", err)
	}
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

	// if an external key was provided, just load that, otherwise create a new key

	var aesPrivate tpm2.TPM2BPrivate
	var aesPublic tpm2.TPM2BPublic
	if s.key != "" {

		ak, err := keyfile.Decode([]byte(s.key))
		if err != nil {
			return nil, fmt.Errorf("go-kms-wrapping: error loading external key: %v", err)
		}

		aesPrivate = ak.Privkey
		aesPublic = ak.Pubkey

	} else {
		// setup session variables used for the policy and key operatons
		// the sessions will be encrypted if the session_encryption_name is set to the RSA EK Public 'name'
		sessTrialPolicy, sessTrialPolicycleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial()}...)
		if err != nil {
			return nil, fmt.Errorf("go-kms-wrapping: setting up trial session: %v", err)
		}
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
		if err != nil {
			return nil, fmt.Errorf("go-kms-wrapping: error executing PolicyPCR: %v", err)
		}

		_, err = tpm2.PolicyAuthValue{
			PolicySession: sessTrialPolicy.Handle(),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("go-kms-wrapping: executing PolicyAuthValue: %v", err)
		}

		// now that we have the pcr's set, get its digest
		pgd, err := tpm2.PolicyGetDigest{
			PolicySession: sessTrialPolicy.Handle(),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("go-kms-wrapping: error executing PolicyGetDigest: %v", err)
		}

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
						Buffer: []byte(s.userAuth), // set the userAuth password for the AES Key
					},
				},
			},
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("go-kms-wrapping: error creating key object  %v", err)
		}

		aesPrivate = aCreate.OutPrivate
		aesPublic = aCreate.OutPublic
	}

	// now load the key
	aesKey, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPrivate: aesPrivate,
		InPublic:  aesPublic,
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: can't load object  %v", err)
	}
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
		keyfile.WithUserAuth([]byte(s.userAuth)),
	)

	// get the keyfiles PEM bytes
	kfb := new(bytes.Buffer)
	err = keyfile.Encode(kfb, tkf)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: failed to encode TPMKey: %v", err)
	}

	// get the pcrs we used in the policy and encode that into the Secret{} struct.
	//  we can optonally use these to unseal the key later on if the pcr values are not specified
	//  in the config file
	pr := make(map[int32]string)
	for i, k := range pcrMap {
		pr[int32(i)] = hex.EncodeToString(k)
	}

	wrappb := &Secret{
		Version: secretVersion,
		PCRs:    pr,
		TPMKey:  kfb.String(),
	}

	wrappedSecretjson, err := json.Marshal(wrappb)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: Error marshaling to JSON: %v", err)
	}

	// setup a real session to encrypt
	policySessionEncrypt, policySessionEncryptCleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(s.userAuth))}...)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error setting up policy session: %v", err)
	}
	defer policySessionEncryptCleanup()

	_, err = tpm2.PolicyPCR{
		PolicySession: policySessionEncrypt.Handle(),
		PcrDigest: tpm2.TPM2BDigest{
			Buffer: pcrHash,
		},
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error executing PolicyPCR: %v", err)
	}

	_, err = tpm2.PolicyAuthValue{
		PolicySession: policySessionEncrypt.Handle(),
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error executing PolicyAuthValue: %v", err)
	}

	// the aes key specifiecations are now complete for use
	keyAuth := tpm2.AuthHandle{
		Handle: aesKey.ObjectHandle,
		Name:   aesKey.Name,
		Auth:   policySessionEncrypt,
	}

	// begin to encrypt the plaintext.
	// first get an IV
	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error getting iv %v", err)
	}

	// now encrypt the plaintext
	cipherText, err := encryptDecryptSymmetric(rwr, keyAuth, iv, plaintext, false)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error encrypting %v", err)
	}

	// crate a blobinfo with the cipehrtext, iv and the PEM formatted TPM key
	ret := &wrapping.BlobInfo{
		Ciphertext: cipherText,
		Iv:         iv,
		KeyInfo: &wrapping.KeyInfo{
			Mechanism:  TPMEncrypt,
			WrappedKey: wrappedSecretjson,
		},
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext.
func (s *TPMWrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in.Ciphertext == nil {
		return nil, fmt.Errorf("go-kms-wrapping: given ciphertext for decryption is nil")
	}

	// open the tpm
	rwc, err := openTPM(s.tpmPath)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: can't open TPM %q: %v", s.tpmPath, err)
	}
	defer rwc.Close()
	rwr := transport.FromReadWriter(rwc)

	// create H2 template again
	cPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Name:   tpm2.HandleName(tpm2.TPMRHOwner),
			Auth:   tpm2.PasswordAuth([]byte(s.hierarchyAuth)),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: can't create primary %v", err)
	}
	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, err = flush.Execute(rwr)
	}()

	// decode the inner struct
	var wrappb Secret
	err = json.Unmarshal(in.KeyInfo.WrappedKey, &wrappb)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping:Error parsing JSON: %v", err)
	}

	// get a list of the pcr's used in the sealing
	var pcrList []uint
	var pcrDigest []byte
	if s.pcrValues != "" {
		_, pcrList, pcrDigest, err = getPCRMap(tpm2.TPMAlgSHA256, s.pcrValues)
		if err != nil {
			return nil, fmt.Errorf("go-kms-wrapping: error parsing pcrmap: %v", err)
		}
	}
	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
			},
		},
	}

	var regenKey *keyfile.TPMKey
	if s.key != "" {
		regenKey, err = keyfile.Decode([]byte(s.key))
		if err != nil {
			return nil, fmt.Errorf("go-kms-wrapping: error loading external key: %v", err)
		}
	} else {
		// the wrappedkey is actually the PEM format of the key we used to seal
		regenKey, err = keyfile.Decode([]byte(wrappb.TPMKey))
		if err != nil {
			return nil, fmt.Errorf("go-kms-wrapping: error decrypting regenerated key: %w", err)
		}
	}

	// now load the key
	aesKey, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPublic:  regenKey.Pubkey,
		InPrivate: regenKey.Privkey,
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping:  error executing Load: %v", err)
	}
	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: aesKey.ObjectHandle,
		}
		_, err = flush.Execute(rwr)
	}()

	// create a pcr policy along with PolicyAuth Value (to account for a password)
	// setup session variables used for the policy and key operatons

	// if no session encryption is set, just create a basic policy and session
	policySessionDecrypt, policySessionDecryptCleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(s.userAuth))}...)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error setting up policy session: %v", err)
	}
	defer policySessionDecryptCleanup()

	_, err = tpm2.PolicyPCR{
		PolicySession: policySessionDecrypt.Handle(),
		PcrDigest:     tpm2.TPM2BDigest{Buffer: pcrDigest},
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error executing PolicyPCR: %v", err)
	}

	_, err = tpm2.PolicyAuthValue{
		PolicySession: policySessionDecrypt.Handle(),
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error executing PolicyAuthValue: %v", err)
	}

	// Setup the auth for the AES key
	keyAuth := tpm2.AuthHandle{
		Handle: aesKey.ObjectHandle,
		Name:   aesKey.Name,
		Auth:   policySessionDecrypt,
	}

	// now use the AES key to decrypt the ciphertext
	decrypted, err := encryptDecryptSymmetric(rwr, keyAuth, in.Iv, in.Ciphertext, true)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error decrypting: %v", err)
	}

	return decrypted, nil
}
