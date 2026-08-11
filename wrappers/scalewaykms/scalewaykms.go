// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package scalewaykms

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	keymanager "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
)

const Type wrapping.WrapperType = "scalewaykms"

// keyManagerAPI is the subset of the Scaleway Key Manager API used by the
// wrapper. It is defined as an interface to allow mocking in tests.
type keyManagerAPI interface {
	Encrypt(req *keymanager.EncryptRequest, opts ...scw.RequestOption) (*keymanager.EncryptResponse, error)
	Decrypt(req *keymanager.DecryptRequest, opts ...scw.RequestOption) (*keymanager.DecryptResponse, error)
	GetKey(req *keymanager.GetKeyRequest, opts ...scw.RequestOption) (*keymanager.Key, error)
}

// Wrapper represents credentials and key information for the Scaleway Key
// Manager key used for encryption and decryption.
type Wrapper struct {
	keyId        string
	region       scw.Region
	projectID    string
	currentKeyId *atomic.Value

	client keyManagerAPI
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new Scaleway KMS wrapper
func NewWrapper() *Wrapper {
	k := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	k.currentKeyId.Store("")
	return k
}

// Type returns the wrapping type for this particular Wrapper implementation
func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return Type, nil
}

// KeyId returns the last known key id
func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.currentKeyId.Load().(string), nil
}

// SetConfig sets the fields on the Wrapper object based on values from the
// config parameter.
//
// Order of precedence for Scaleway values:
// SetConfig sets the fields on the Wrapper object based on values from the
// config parameter.
//
// Order of precedence for Scaleway values:
//   - Passed in config map
//   - Standard SCW_* environment variables (unless WithDisallowEnvVars)
//   - Scaleway configuration file, active profile (unless WithDisallowEnvVars)
func (k *Wrapper) SetConfig(ctx context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	if opts.WithKeyId == "" {
		return nil, errors.New("key id not found in config for scaleway kms wrapper configuration")
	}
	k.keyId = opts.WithKeyId

	// Build the Scaleway client from the resolved credentials/region.
	if k.client == nil {
		client, region, projectID, err := getScalewayKeyManagerClient(opts)
		if err != nil {
			return nil, fmt.Errorf("error initializing Scaleway KMS wrapping client: %w", err)
		}
		k.client = client
		k.region = region
		k.projectID = projectID

		// Test the client connection and validate the key is usable for
		// symmetric encryption.
		key, err := k.client.GetKey(&keymanager.GetKeyRequest{
			Region: k.region,
			KeyID:  k.keyId,
		}, scw.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("error fetching Scaleway KMS wrapping key information: %w", err)
		}
		if key.Usage == nil || key.Usage.SymmetricEncryption == nil {
			return nil, errors.New("configured scaleway kms key does not have the symmetric_encryption usage")
		}
		if key.State != keymanager.KeyStateEnabled {
			return nil, fmt.Errorf("configured scaleway kms key is not enabled (state: %s)", key.State)
		}
		k.currentKeyId.Store(key.ID)
	}

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["region"] = k.region.String()
	wrapConfig.Metadata["key_id"] = k.keyId
	if k.projectID != "" {
		wrapConfig.Metadata["project_id"] = k.projectID
	}

	return wrapConfig, nil
}

// Encrypt is used to encrypt the master key using the Scaleway KMS key.
// This generates a data encryption key, encrypts the plaintext locally with
// AES-GCM and wraps the data key with the Scaleway KMS key. It returns the
// ciphertext, and/or any errors from this call. This should be called after
// the Scaleway client has been instantiated.
func (k *Wrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, errors.New("given plaintext for encryption is nil")
	}

	if k.client == nil {
		return nil, errors.New("nil client")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	output, err := k.client.Encrypt(&keymanager.EncryptRequest{
		Region:    k.region,
		KeyID:     k.keyId,
		Plaintext: env.Key,
	}, scw.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	// Store the current key id. Encrypt returns the key id actually used,
	// which is helpful to detect that the key was rotated when we want to
	// rewrap older entries.
	if output.KeyID != "" {
		k.currentKeyId.Store(output.KeyID)
	}

	return &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			KeyId:      output.KeyID,
			WrappedKey: output.Ciphertext,
		},
	}, nil
}

// Decrypt is used to decrypt the ciphertext. This should be called after
// SetConfig.
func (k *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, errors.New("given input for decryption is nil")
	}
	if in.KeyInfo == nil {
		return nil, errors.New("key info is nil")
	}

	if k.client == nil {
		return nil, errors.New("nil client")
	}

	output, err := k.client.Decrypt(&keymanager.DecryptRequest{
		Region:     k.region,
		KeyID:      k.keyId,
		Ciphertext: in.KeyInfo.WrappedKey,
	}, scw.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("error decrypting data encryption key: %w", err)
	}

	envInfo := &wrapping.EnvelopeInfo{
		Key:        output.Plaintext,
		Iv:         in.Iv,
		Ciphertext: in.Ciphertext,
	}
	plaintext, err := wrapping.EnvelopeDecrypt(envInfo, opt...)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return plaintext, nil
}

// Client returns the Scaleway Key Manager client used by the wrapper.
func (k *Wrapper) Client() keyManagerAPI {
	return k.client
}

// getScalewayKeyManagerClient resolves credentials and region from the config
// map, the standard SCW_* environment variables and the Scaleway configuration
// file (in that order of precedence) and returns a ready-to-use Key Manager
// API client along with the resolved region and project id.
func getScalewayKeyManagerClient(opts *options) (keyManagerAPI, scw.Region, string, error) {
	profiles := []*scw.Profile{{}}

	if !opts.WithDisallowEnvVars {
		// Lowest precedence: the active profile from the Scaleway configuration
		// file (e.g. ~/.config/scw/config.yaml). Note that LoadConfig also reads
		// SCW_CONFIG_PATH, so it is skipped entirely here.
		if cfg, err := scw.LoadConfig(); err == nil {
			if p, err := cfg.GetActiveProfile(); err == nil && p != nil {
				profiles = append(profiles, p)
			}
		}

		// Middle precedence: the standard SCW_* environment variables.
		profiles = append(profiles, scw.LoadEnvProfile())
	}
	// Highest precedence: explicit values from the config map / options.
	configProfile := &scw.Profile{}
	if opts.withAccessKey != "" {
		configProfile.AccessKey = scw.StringPtr(opts.withAccessKey)
	}
	if opts.withSecretKey != "" {
		configProfile.SecretKey = scw.StringPtr(opts.withSecretKey)
	}
	if opts.withRegion != "" {
		configProfile.DefaultRegion = scw.StringPtr(opts.withRegion)
	}
	if opts.withProjectID != "" {
		configProfile.DefaultProjectID = scw.StringPtr(opts.withProjectID)
	}
	if opts.withAPIURL != "" {
		configProfile.APIURL = scw.StringPtr(opts.withAPIURL)
	}
	profiles = append(profiles, configProfile)

	profile := scw.MergeProfiles(profiles[0], profiles[1:]...)

	client, err := scw.NewClient(scw.WithProfile(profile))
	if err != nil {
		return nil, "", "", err
	}

	// Resolve the region. Key Manager keys are regional, so a region must be
	// determined either explicitly or via the client default.
	var region scw.Region
	if profile.DefaultRegion != nil && *profile.DefaultRegion != "" {
		region, err = scw.ParseRegion(*profile.DefaultRegion)
		if err != nil {
			return nil, "", "", fmt.Errorf("invalid scaleway region %q: %w", *profile.DefaultRegion, err)
		}
	} else if defaultRegion, ok := client.GetDefaultRegion(); ok {
		region = defaultRegion
	} else {
		return nil, "", "", errors.New("no scaleway region found in env or config for scaleway kms wrapper configuration")
	}

	projectID := ""
	if profile.DefaultProjectID != nil {
		projectID = *profile.DefaultProjectID
	}

	return keymanager.NewAPI(client), region, projectID, nil
}
