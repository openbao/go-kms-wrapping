// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package opentelekomcloudkms

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
	kms "github.com/opentelekomcloud/gophertelekomcloud/openstack/kms/v1/keys"
)

const (
	EnvOpenTelekomCloudKmsWrapperKeyId = "OPENTELEKOMCLOUDKMS_WRAPPER_KEY_ID"
)

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// Wrapper is a Wrapper that uses Open Telekom Cloud's KMS
type Wrapper struct {
	client *golangsdk.ServiceClient

	// keyId is the configured key ID or alias. It is used to request
	// encryption. We keep this separate from currentKeyId to support key
	// aliases/rotation.
	keyId string

	// currentKeyId is the resolved key ID from the last successful operation.
	currentKeyId *atomic.Value

	// Metadata fields stored for reporting
	region  string
	project string
}

// NewWrapper creates a new OpenTelekomCloud Wrapper
func NewWrapper() *Wrapper {
	k := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	k.currentKeyId.Store("")
	return k
}

// SetConfig sets the fields on the OpenTelekomCloud Wrapper object based on
// values from the config parameter.
//
// Order of precedence Open Telekom Cloud values:
// * Environment variable
// * Value from Vault configuration file
func (k *Wrapper) SetConfig(
	_ context.Context,
	opt ...wrapping.Option,
) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	// Check and set KeyId
	keyId, err := getConfig(
		"kms_key_id",
		os.Getenv(EnvOpenTelekomCloudKmsWrapperKeyId),
		opts.WithKeyId,
	)
	if err != nil {
		return nil, err
	}
	k.keyId = keyId

	if k.client == nil {
		if err := k.setupClient(opts); err != nil {
			return nil, err
		}
	}

	// Test the client connection using provided key ID
	keyInfo, err := kms.Get(k.client, k.keyId)
	if err != nil {
		return nil, fmt.Errorf("error fetching Open Telekom Cloud KMS key information: %w", err)
	}

	// Store the current key id. If using a key alias, this will point to the
	// actual unique key that that was used for this encrypt operation.
	k.currentKeyId.Store(keyInfo.KeyID)

	// Store non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["region"] = k.region
	wrapConfig.Metadata["project"] = k.project
	wrapConfig.Metadata["kms_key_id"] = k.keyId

	return wrapConfig, nil
}

// Type returns the type for this particular wrapper implementation
func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeOpenTelekomCloudKms, nil
}

// KeyId returns the last known key id
func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.currentKeyId.Load().(string), nil
}

// Encrypt is used to encrypt the master key using the the Open Telekom Cloud
// CMK. This returns the ciphertext, and/or any errors from this call. This
// should be called after the KMS client has been instantiated.
func (k *Wrapper) Encrypt(
	_ context.Context,
	plaintext []byte,
	opt ...wrapping.Option,
) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	// We use k.keyId (the config) here so that if it is an alias, KMS resolves
	// it to the latest version.
	resp, err := kms.EncryptData(
		k.client,
		kms.EncryptDataOpts{
			KeyID:     k.keyId,
			PlainText: base64.StdEncoding.EncodeToString(env.Key),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	// Store the actual resolved key ID returned by KMS.
	k.currentKeyId.Store(resp.KeyID)

	return &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			KeyId:      resp.KeyID,
			WrappedKey: []byte(resp.CipherText),
		},
	}, nil
}

// Decrypt is used to decrypt the ciphertext.
func (k *Wrapper) Decrypt(
	_ context.Context,
	in *wrapping.BlobInfo,
	opt ...wrapping.Option,
) ([]byte, error) {
	if in == nil {
		return nil, fmt.Errorf("given input for decryption is nil")
	}

	// KeyId is not passed to this call because Open Telekom Cloud handles this
	// internally based on the metadata stored with the encrypted data
	resp, err := kms.DecryptData(
		k.client,
		kms.DecryptDataOpts{CipherText: string(in.KeyInfo.WrappedKey)},
	)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data encryption key: %w", err)
	}

	keyBytes, err := base64.StdEncoding.DecodeString(resp.PlainText)
	if err != nil {
		return nil, err
	}

	envInfo := &wrapping.EnvelopeInfo{
		Key:        keyBytes,
		Iv:         in.Iv,
		Ciphertext: in.Ciphertext,
	}
	pt, err := wrapping.EnvelopeDecrypt(envInfo, opt...)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return pt, nil
}

func (k *Wrapper) setupClient(opts *options) error {
	region, err := getConfig(
		"region",
		os.Getenv("OPENTELEKOMCLOUD_REGION"),
		opts.withRegion,
	)
	if err != nil {
		return err
	}
	k.region = region

	project, err := getConfig(
		"project",
		os.Getenv("OPENTELEKOMCLOUD_PROJECT"),
		opts.withProject,
	)
	if err != nil {
		return err
	}
	k.project = project

	accessKey, err := getConfig(
		"access_key",
		os.Getenv("OPENTELEKOMCLOUD_ACCESS_KEY"),
		opts.withAccessKey,
	)
	if err != nil {
		return err
	}

	secretKey, err := getConfig(
		"secret_key",
		os.Getenv("OPENTELEKOMCLOUD_SECRET_KEY"),
		opts.withSecretKey,
	)
	if err != nil {
		return err
	}

	endpoint, _ := getConfig(
		"identity_endpoint",
		os.Getenv("OPENTELEKOMCLOUD_IDENTITY_ENDPOINT"),
		opts.withIdentityEndpoint,
	)

	authOpts := golangsdk.AKSKAuthOptions{
		Region:           k.region,
		ProjectId:        k.project,
		AccessKey:        accessKey,
		SecretKey:        secretKey,
		IdentityEndpoint: endpoint,
	}

	client, err := openstack.NewClient(authOpts.IdentityEndpoint)
	if err != nil {
		return fmt.Errorf("failed to create new client: %w", err)
	}

	// Configure the HTTP client to handle redirects with AK/SK resigning.
	client.HTTPClient = http.Client{
		Transport: client.HTTPClient.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			golangsdk.ReSign(req, golangsdk.SignOptions{
				AccessKey: accessKey,
				SecretKey: secretKey,
			})
			return nil
		},
	}

	err = openstack.Authenticate(client, authOpts)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	sc, err := openstack.NewKMSV1(
		client, golangsdk.EndpointOpts{
			Region:       authOpts.Region,
			Availability: golangsdk.AvailabilityPublic,
		},
	)
	if err != nil {
		return err
	}

	k.client = sc
	return nil
}

func getConfig(name string, values ...string) (string, error) {
	for _, v := range values {
		if v != "" {
			return v, nil
		}
	}

	return "", fmt.Errorf("'%s' not found for Open Telekom Cloud KMS wrapper configuration", name)
}
