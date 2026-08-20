// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package tpm

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	"context"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	wrapaead "github.com/openbao/go-kms-wrapping/v2/aead"
)

const Type wrapping.WrapperType = "tpm"

const (
	EnvTPMPath       = "TPM_PATH"
	EnvPCRValues     = "TPM_PCRVALUES"
	EnvUserAuth      = "TPM_USERAUTH"
	EnvHierarchyAuth = "TPM_HIERARCHYAUTH"
)

// Configures and manages the TPM SRK encryption wrapper
//
//	Values here are set using setConfig or options
type TPMWrapper struct {
	tpmPath       string
	pcrValues     string
	userAuth      string
	hierarchyAuth string
	currentKeyId  *atomic.Value
}

var (
	_ wrapping.Wrapper = (*TPMWrapper)(nil)
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

	// create an encryption key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error generating random %v", err)
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

	// create an H2 primary; this is just for convenience. you could create any primary with auth
	//  i'm just doing this so i can easily specify a keyfile.  A todo would be to set a owner/primary auth
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

	// setup trial session variables used for the policy and key operatons
	sessTrialPolicy, sessTrialPolicycleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial()}...)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: setting up trial session: %v", err)
	}
	defer sessTrialPolicycleanup()

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
			},
		},
	}

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

	// now that we have the digest, create the actual TPM based key based on the parent
	// remember the sensitive data **is** the encryption key we will use later for wrapaead.Encrypt(plaintext, opt...)
	cCreate, err := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:       tpm2.TPMAlgKeyedHash,
			NameAlg:    tpm2.TPMAlgSHA256,
			AuthPolicy: pgd.PolicyDigest, // set the pcr auth policy
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: false,
			},
		}),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: key, //  <<<<<<<<<<<<<<<<< set the inner encryption key as the sensitive data
				}),
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(s.userAuth), // set the key auth password
				},
			},
		},
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error creating sealed object  %v", err)
	}

	// now load the key
	loadedKey, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPrivate: cCreate.OutPrivate,
		InPublic:  cCreate.OutPublic,
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: can't load object  %v", err)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: loadedKey.ObjectHandle,
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	// create a keyfile representation (eg, a PEM format for the TPM based sealing key)
	tkf := keyfile.NewTPMKey(
		keyfile.OIDLoadableKey,
		cCreate.OutPublic,
		cCreate.OutPrivate,
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
		PCRs:   pr,
		TPMKey: kfb.String(),
	}

	wrappedSecretjson, err := json.Marshal(wrappb)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: Error marshaling to JSON: %v", err)
	}

	// now encrypt the plaintext using the aes-gcm key which we sealed earlier into the tpm object
	// the library we're using to do that is "github.com/openbao/go-kms-wrapping/v2/aead"
	directwrap := wrapaead.NewWrapper()
	err = directwrap.SetAesGcmKeyBytes(key)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error setting AESGCM Key %v", err)
	}
	c, err := directwrap.Encrypt(ctx, plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error encrypting %v", err)
	}

	//  note the ciphertext already has the iv included in it
	//  https://github.com/hashicorp/go-kms-wrapping/blob/main/aead/aead.go#L242-L249
	ret := &wrapping.BlobInfo{
		Ciphertext: c.Ciphertext, // add the aes wrapped ciphertext into the blobinfo
		KeyInfo: &wrapping.KeyInfo{
			Mechanism:  TPMSeal,
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

	// create a pcr policy along with PolicyAuth Value (to account for a password)

	policySessionUnseal, policySessionUnsealCleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(s.userAuth))}...)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error setting up policy session: %v", err)
	}
	defer policySessionUnsealCleanup()

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

	var plaintext []byte

	// decode the inner struct
	var wrappb Secret
	err = json.Unmarshal(in.KeyInfo.WrappedKey, &wrappb)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping:Error parsing JSON: %v", err)
	}

	// get a list of the pcr's used in the sealing, if any
	var pcrList []uint
	var pcrDigest []byte
	if s.pcrValues != "" {
		_, pcrList, pcrDigest, err = getPCRMap(tpm2.TPMAlgSHA256, s.pcrValues)
		if err != nil {
			return nil, fmt.Errorf("go-kms-wrapping: error parsing pcrmap: %v", err)
		}

	} else {
		for i, _ := range wrappb.PCRs {
			pcrList = append(pcrList, uint(i))
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

	// the wrappedkey is actually the PEM format of the key we used to seal
	regenKey, err := keyfile.Decode([]byte(wrappb.TPMKey))
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error decrypting regenerated key: %w", err)
	}

	// now load the key
	k, err := tpm2.Load{
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
			FlushHandle: k.ObjectHandle,
		}
		_, err = flush.Execute(rwr)
	}()

	_, err = tpm2.PolicyPCR{
		PolicySession: policySessionUnseal.Handle(),
		PcrDigest:     tpm2.TPM2BDigest{Buffer: pcrDigest},
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error executing PolicyPCR: %v", err)
	}

	_, err = tpm2.PolicyAuthValue{
		PolicySession: policySessionUnseal.Handle(),
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error executing PolicyAuthValue: %v", err)
	}

	// use this policy to unseal the data
	unsealresp, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: k.ObjectHandle,
			Name:   k.Name,
			Auth:   policySessionUnseal,
		},
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error executing unseal: %v", err)
	}

	// the unsealed data is the inner encryption key
	envInfo := &wrapping.EnvelopeInfo{
		Key:        unsealresp.OutData.Buffer,
		Ciphertext: in.Ciphertext,
	}

	// now decrypt the plaintext using the aes-gcm key which we sealed earlier into the tpm object
	// the library we're using to do that is "github.com/openbao/go-kms-wrapping/v2/aead"
	directwrap := wrapaead.NewWrapper()
	err = directwrap.SetAesGcmKeyBytes(envInfo.Key)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error setting AESGCM Key %v", err)
	}
	plaintext, err = directwrap.Decrypt(ctx, in, opt...)
	if err != nil {
		return nil, fmt.Errorf("go-kms-wrapping: error decrypting %v", err)
	}

	return plaintext, nil
}
