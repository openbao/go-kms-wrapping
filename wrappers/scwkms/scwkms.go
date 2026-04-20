// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package scwkms

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"

	key_manager "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// These constants contain the accepted env vars
const (
	EnvScwKmsWrapperKeyId = "SCW_KMS_WRAPPER_KEY_ID"
)

const (
	// ScwKmsEnvelopeAesGcmEncrypt is when a data encryption key is generated and
	// the data is encrypted with AES-GCM and the key is encrypted with Scaleway KMS
	ScwKmsEnvelopeAesGcmEncrypt = iota
)

// scwKmsClient abstracts the Scaleway Key Manager API for mocking in tests
type scwKmsClient interface {
	Encrypt(*key_manager.EncryptRequest, ...scw.RequestOption) (*key_manager.EncryptResponse, error)
	Decrypt(*key_manager.DecryptRequest, ...scw.RequestOption) (*key_manager.DecryptResponse, error)
	GetKey(*key_manager.GetKeyRequest, ...scw.RequestOption) (*key_manager.Key, error)
}

// Wrapper represents credentials and Key information for the Scaleway KMS Key used to
// encryption and decryption
type Wrapper struct {
	accessKey       string
	secretKey       string
	region          string
	projectID       string
	keyId           string
	keyNotRequired  bool
	disallowEnvVars bool

	currentKeyId *atomic.Value

	client scwKmsClient
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new ScwKms wrapper with the provided options
func NewWrapper() *Wrapper {
	k := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	k.currentKeyId.Store("")
	return k
}

// SetConfig sets the fields on the Wrapper object based on
// values from the config parameter.
//
// Order of precedence Scaleway values:
// * Environment variable
// * Passed in config map
// * Default values
func (k *Wrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	k.keyNotRequired = opts.withKeyNotRequired
	k.disallowEnvVars = opts.withDisallowEnvVars

	// Check and set KeyId
	switch {
	case os.Getenv(EnvScwKmsWrapperKeyId) != "" && !opts.withDisallowEnvVars:
		k.keyId = os.Getenv(EnvScwKmsWrapperKeyId)
	case opts.WithKeyId != "":
		k.keyId = opts.WithKeyId
	case k.keyNotRequired:
		// key not required to set config
	default:
		return nil, fmt.Errorf("key id not found in env or config for Scaleway KMS wrapper configuration")
	}

	k.currentKeyId.Store(k.keyId)

	// Check and set Scaleway access key, secret key, region, and project ID
	k.accessKey = opts.withAccessKey
	k.secretKey = opts.withSecretKey
	k.region = opts.withRegion
	k.projectID = opts.withProjectID

	// Check and set k.client
	if k.client == nil {
		client, err := k.GetScwKmsClient()
		if err != nil {
			return nil, fmt.Errorf("error initializing Scaleway KMS wrapping client: %w", err)
		}

		if !k.keyNotRequired {
			// Test the client connection using provided key ID
			keyInfo, err := client.GetKey(&key_manager.GetKeyRequest{
				Region: scw.Region(k.region),
				KeyID:  k.keyId,
			})
			if err != nil {
				return nil, fmt.Errorf("error fetching Scaleway KMS wrapping key information: %w", err)
			}
			k.currentKeyId.Store(keyInfo.ID)
		}

		k.client = client
	}

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["region"] = k.region
	wrapConfig.Metadata["key_id"] = k.keyId
	if k.projectID != "" {
		wrapConfig.Metadata["project_id"] = k.projectID
	}

	return wrapConfig, nil
}

// Type returns the wrapping type for this particular Wrapper implementation
func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeScwKms, nil
}

// KeyId returns the last known key id
func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.currentKeyId.Load().(string), nil
}

// Encrypt is used to encrypt the master key using the Scaleway KMS CMK.
// This returns the ciphertext, and/or any errors from this
// call. This should be called after the KMS client has been instantiated.
func (k *Wrapper) Encrypt(_ context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	if k.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	output, err := k.client.Encrypt(&key_manager.EncryptRequest{
		Region:    scw.Region(k.region),
		KeyID:     k.keyId,
		Plaintext: env.Key,
	})
	if err != nil {
		return nil, fmt.Errorf("error encrypting data encryption key: %w", err)
	}

	// Store the current key id
	keyId := output.KeyID
	k.currentKeyId.Store(keyId)

	ret := &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			Mechanism:  ScwKmsEnvelopeAesGcmEncrypt,
			KeyId:      keyId,
			WrappedKey: output.Ciphertext,
		},
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext. This should be called after Init.
func (k *Wrapper) Decrypt(_ context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, fmt.Errorf("given input for decryption is nil")
	}

	// Default to mechanism used before key info was stored
	if in.KeyInfo == nil {
		in.KeyInfo = &wrapping.KeyInfo{
			Mechanism: ScwKmsEnvelopeAesGcmEncrypt,
		}
	}

	var plaintext []byte
	switch in.KeyInfo.Mechanism {
	case ScwKmsEnvelopeAesGcmEncrypt:
		output, err := k.client.Decrypt(&key_manager.DecryptRequest{
			Region:     scw.Region(k.region),
			KeyID:      k.keyId,
			Ciphertext: in.KeyInfo.WrappedKey,
		})
		if err != nil {
			return nil, fmt.Errorf("error decrypting data encryption key: %w", err)
		}

		envInfo := &wrapping.EnvelopeInfo{
			Key:        output.Plaintext,
			Iv:         in.Iv,
			Ciphertext: in.Ciphertext,
		}
		plaintext, err = wrapping.EnvelopeDecrypt(envInfo, opt...)
		if err != nil {
			return nil, fmt.Errorf("error decrypting data: %w", err)
		}

	default:
		return nil, fmt.Errorf("invalid mechanism: %d", in.KeyInfo.Mechanism)
	}

	return plaintext, nil
}

// Client returns the Scaleway KMS client used by the wrapper
func (k *Wrapper) Client() scwKmsClient {
	return k.client
}

// GetScwKmsClient returns an instance of the Scaleway KMS client.
func (k *Wrapper) GetScwKmsClient() (*key_manager.API, error) {
	var clientOpts []scw.ClientOption

	if !k.disallowEnvVars {
		if config, err := scw.LoadConfig(); err == nil {
			if profile, err := config.GetActiveProfile(); err == nil {
				clientOpts = append(clientOpts, scw.WithProfile(profile))
			}
		}
		clientOpts = append(clientOpts, scw.WithEnv())
	}

	if k.accessKey != "" && k.secretKey != "" {
		clientOpts = append(clientOpts, scw.WithAuth(k.accessKey, k.secretKey))
	}

	if k.region != "" {
		region, err := scw.ParseRegion(k.region)
		if err != nil {
			return nil, fmt.Errorf("invalid Scaleway region %q: %w", k.region, err)
		}
		clientOpts = append(clientOpts, scw.WithDefaultRegion(region))
	}

	if k.projectID != "" {
		clientOpts = append(clientOpts, scw.WithDefaultProjectID(k.projectID))
	}

	scwClient, err := scw.NewClient(clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating Scaleway client: %w", err)
	}

	return key_manager.NewAPI(scwClient), nil
}
