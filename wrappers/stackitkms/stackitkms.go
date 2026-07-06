// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package stackitkms

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stackitcloud/stackit-sdk-go/services/kms/v1api"
)

const Type wrapping.WrapperType = "stackitkms"

// StackitKmsEnvelopeAesGcmEncrypt is the mechanism used: a locally generated
// AES-GCM data encryption key, wrapped by STACKIT KMS.
const StackitKmsEnvelopeAesGcmEncrypt uint64 = 1

const (
	EnvStackitKmsProjectId  = "STACKITKMS_PROJECT_ID"
	EnvStackitKmsRegion     = "STACKITKMS_REGION"
	EnvStackitKmsKeyRingId  = "STACKITKMS_KEY_RING_ID"
	EnvStackitKmsKeyId      = "STACKITKMS_KEY_ID"
	EnvStackitKmsKeyVersion = "STACKITKMS_KEY_VERSION"
	EnvStackitKmsEndpoint   = "STACKITKMS_ENDPOINT"
)

// Wrapper is a wrapper that uses the STACKIT KMS encrypt/decrypt API
type Wrapper struct {
	client kmsClient

	keyId      string
	keyVersion int64

	currentKeyId *atomic.Value

	// newClient is a hook for tests to substitute a fake client
	newClient func(cc clientConfig) (kmsClient, error)
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new STACKIT KMS wrapper
func NewWrapper() *Wrapper {
	w := &Wrapper{
		currentKeyId: new(atomic.Value),
		newClient:    newSdkClient,
	}
	w.currentKeyId.Store("")
	return w
}

func (w *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return Type, nil
}

// KeyId returns the id of the key version new blobs are wrapped with, in the
// form "<key id>/<version>", so that a key rotation changes the reported id.
func (w *Wrapper) KeyId(_ context.Context) (string, error) {
	return w.currentKeyId.Load().(string), nil
}

// SetConfig sets the fields on the Wrapper object based on values from the
// config parameter, builds the client and validates the configured key.
//
// Order of precedence for each value:
// * Environment variable
// * Value from Vault configuration file
func (w *Wrapper) SetConfig(ctx context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	pick := func(env, configured string) string {
		if !opts.WithDisallowEnvVars {
			if v := os.Getenv(env); v != "" {
				return v
			}
		}
		return configured
	}

	projectId := pick(EnvStackitKmsProjectId, opts.withProjectId)
	region := pick(EnvStackitKmsRegion, opts.withRegion)
	keyRingId := pick(EnvStackitKmsKeyRingId, opts.withKeyRingId)
	keyId := pick(EnvStackitKmsKeyId, opts.WithKeyId)
	keyVersionRaw := pick(EnvStackitKmsKeyVersion, opts.withKeyVersion)
	endpoint := pick(EnvStackitKmsEndpoint, opts.withEndpoint)

	switch {
	case projectId == "":
		return nil, fmt.Errorf("'project_id' not found (config or env) for stackitkms seal configuration")
	case region == "":
		return nil, fmt.Errorf("'region' not found (config or env) for stackitkms seal configuration")
	case keyRingId == "":
		return nil, fmt.Errorf("'key_ring_id' not found (config or env) for stackitkms seal configuration")
	case keyId == "":
		return nil, fmt.Errorf("'key_id' not found (config or env) for stackitkms seal configuration")
	}

	var keyVersion int64
	if keyVersionRaw != "" {
		keyVersion, err = strconv.ParseInt(keyVersionRaw, 10, 64)
		if err != nil || keyVersion <= 0 {
			return nil, fmt.Errorf("invalid 'key_version' %q: must be a positive integer", keyVersionRaw)
		}
	}

	client, err := w.newClient(clientConfig{
		projectId: projectId,
		region:    region,
		keyRingId: keyRingId,
		endpoint:  endpoint,

		serviceAccountKey:     opts.withServiceAccountKey,
		serviceAccountKeyPath: opts.withServiceAccountKeyPath,
		privateKey:            opts.withPrivateKey,
		privateKeyPath:        opts.withPrivateKeyPath,
		token:                 opts.withToken,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create STACKIT KMS client: %w", err)
	}
	w.client = client

	// Validate the key exists and can encrypt/decrypt.
	key, err := w.client.getKey(ctx, keyId)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch STACKIT KMS key %q: %w", keyId, err)
	}
	switch key.Purpose {
	case v1api.PURPOSE_SYMMETRIC_ENCRYPT_DECRYPT, v1api.PURPOSE_ASYMMETRIC_ENCRYPT_DECRYPT:
	default:
		return nil, fmt.Errorf("STACKIT KMS key %q has purpose %q, but an encrypt/decrypt key is required", keyId, key.Purpose)
	}

	if keyVersion == 0 {
		keyVersion, err = latestUsableVersion(ctx, w.client, keyId)
		if err != nil {
			return nil, err
		}
	} else {
		version, err := w.client.getVersion(ctx, keyId, keyVersion)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch version %d of STACKIT KMS key %q: %w", keyVersion, keyId, err)
		}
		if !versionUsable(version) {
			return nil, fmt.Errorf("version %d of STACKIT KMS key %q is not usable (state %q, disabled %t)",
				keyVersion, keyId, version.State, version.Disabled)
		}
	}

	w.keyId = keyId
	w.keyVersion = keyVersion
	w.currentKeyId.Store(keyVersionId(keyId, keyVersion))

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = map[string]string{
		"project_id":  projectId,
		"region":      region,
		"key_ring_id": keyRingId,
		"key_id":      keyId,
		"key_version": strconv.FormatInt(keyVersion, 10),
	}
	if endpoint != "" {
		wrapConfig.Metadata["endpoint"] = endpoint
	}
	return wrapConfig, nil
}

// Encrypt is used to encrypt data. This should be called after SetConfig.
func (w *Wrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if w.client == nil {
		return nil, fmt.Errorf("stackitkms wrapper is not configured")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	wrappedKey, err := w.client.encrypt(ctx, w.keyId, w.keyVersion, env.Key)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data encryption key: %w", err)
	}

	keyId := keyVersionId(w.keyId, w.keyVersion)
	w.currentKeyId.Store(keyId)

	return &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			Mechanism:  StackitKmsEnvelopeAesGcmEncrypt,
			KeyId:      keyId,
			WrappedKey: wrappedKey,
		},
	}, nil
}

// Decrypt is used to decrypt the ciphertext. The key version recorded in the
// blob takes precedence over the configured one, so blobs written before a
// key rotation stay readable.
func (w *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if w.client == nil {
		return nil, fmt.Errorf("stackitkms wrapper is not configured")
	}
	if in == nil || in.KeyInfo == nil {
		return nil, fmt.Errorf("given ciphertext contains no key information")
	}

	switch in.KeyInfo.Mechanism {
	case 0, StackitKmsEnvelopeAesGcmEncrypt:
	default:
		return nil, fmt.Errorf("invalid mechanism: %d", in.KeyInfo.Mechanism)
	}

	keyId, keyVersion := w.keyId, w.keyVersion
	if id, version, ok := parseKeyVersionId(in.KeyInfo.KeyId); ok {
		keyId, keyVersion = id, version
	}

	key, err := w.client.decrypt(ctx, keyId, keyVersion, in.KeyInfo.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data encryption key: %w", err)
	}

	plaintext, err := wrapping.EnvelopeDecrypt(&wrapping.EnvelopeInfo{
		Key:        key,
		Iv:         in.Iv,
		Ciphertext: in.Ciphertext,
	}, opt...)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}
	return plaintext, nil
}

// latestUsableVersion returns the highest enabled active version of the key.
func latestUsableVersion(ctx context.Context, client kmsClient, keyId string) (int64, error) {
	versions, err := client.listVersions(ctx, keyId)
	if err != nil {
		return 0, fmt.Errorf("failed to list versions of STACKIT KMS key %q: %w", keyId, err)
	}

	var latest int64
	for i := range versions {
		if versionUsable(&versions[i]) && versions[i].Number > latest {
			latest = versions[i].Number
		}
	}
	if latest == 0 {
		return 0, fmt.Errorf("STACKIT KMS key %q has no enabled active version", keyId)
	}
	return latest, nil
}

func versionUsable(v *v1api.Version) bool {
	return v != nil && !v.Disabled && v.State == v1api.VERSIONSTATE_ACTIVE
}

func keyVersionId(keyId string, version int64) string {
	return fmt.Sprintf("%s/%d", keyId, version)
}

// parseKeyVersionId reports ok = false for ids not produced by this wrapper,
// in which case callers fall back to the configured key and version.
func parseKeyVersionId(id string) (string, int64, bool) {
	keyId, versionRaw, found := strings.Cut(id, "/")
	if !found || keyId == "" {
		return "", 0, false
	}
	version, err := strconv.ParseInt(versionRaw, 10, 64)
	if err != nil || version <= 0 {
		return "", 0, false
	}
	return keyId, version, true
}
