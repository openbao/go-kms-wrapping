// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package incertkms

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/google/uuid"
	kmssdk "github.com/incert-kms/kms-sdk-go"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

const Type wrapping.WrapperType = "incertkms"

type Wrapper struct {
	key     uuid.UUID
	vSlot   uuid.UUID
	keyName string
	kms     *kmssdk.Client
}

var (
	_ wrapping.Wrapper       = (*Wrapper)(nil)
	_ wrapping.InitFinalizer = (*Wrapper)(nil)
)

func NewWrapper() *Wrapper {
	s := &Wrapper{
		keyName: "openbao-seal-key",
	}
	return s
}

func (w *Wrapper) Type(ctx context.Context) (wrapping.WrapperType, error) {
	return Type, nil
}

func (w *Wrapper) KeyId(ctx context.Context) (string, error) {
	return w.key.String(), nil
}

func (w *Wrapper) SetConfig(ctx context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(options...)
	if err != nil {
		return nil, err
	}

	baseURL := opts.withUrl
	if baseURL == "" {
		return nil, fmt.Errorf("incertkms: url is required")
	}

	username := opts.withUsername
	if username == "" {
		return nil, fmt.Errorf("incertkms: username is required")
	}

	password := opts.withPassword
	if password == "" {
		return nil, fmt.Errorf("incertkms: password is required")
	}

	if opts.withVSlot != "" {
		vslotId, err := uuid.Parse(opts.withVSlot)
		if err != nil {
			return nil, fmt.Errorf("incertkms: invalid vslot format: %w", err)
		}
		w.vSlot = vslotId
	}

	if opts.withKey != "" {
		keyId, err := uuid.Parse(opts.withKey)
		if err != nil {
			return nil, fmt.Errorf("incertkms: invalid key format: %w", err)
		}
		w.key = keyId
	}

	if opts.withKeyName != "" {
		w.keyName = opts.withKeyName
	}

	clientOpts := []kmssdk.Option{
		kmssdk.WithUsernameAndPassword(username, password),
		kmssdk.WithBaseURL(baseURL),
	}

	// TLS verification is enabled by default. Only override the SDK's default
	// client when the operator has supplied a custom CA or has explicitly opted
	// into skipping verification.
	if opts.tlsConfigured() {
		httpClient, err := opts.buildHTTPClient()
		if err != nil {
			return nil, err
		}
		clientOpts = append(clientOpts, kmssdk.WithHTTPClient(httpClient))
	}

	w.kms = kmssdk.NewClient(clientOpts...)

	err = w.kms.Connect(ctx)
	if err != nil {
		var apiErr *kmssdk.APIError
		if errors.As(err, &apiErr) {
			return nil, fmt.Errorf("API error %d (%s): %s\n", apiErr.StatusCode, apiErr.Code, apiErr.Message)
		}
		return nil, fmt.Errorf("unexpected error: %v\n", err)
	}

	err = w.vslotInit(ctx)
	if err != nil {
		return nil, err
	}

	err = w.keyInit(ctx)
	if err != nil {
		return nil, err
	}

	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["url"] = baseURL
	wrapConfig.Metadata["vslot"] = w.vSlot.String()
	wrapConfig.Metadata["key"] = w.key.String()

	return wrapConfig, nil
}

// Configure the VSlot to store the seal Key
// If the KMS account has only one vslot, we can use it directly.
// If there are multiple vslots, the user must specify which one to use in the configuration.
func (w *Wrapper) vslotInit(ctx context.Context) error {
	vslots, err := w.kms.GetVSlots(ctx)
	if err != nil {
		return fmt.Errorf("getting vslots: %w", err)
	}
	if len(vslots) == 0 {
		return fmt.Errorf("no vslots available on your account")
	}

	if w.vSlot == uuid.Nil {
		if len(vslots) > 1 {
			return fmt.Errorf("multiple vslots available on your account, please set preferred vslot ID in configuration")
		}
		w.vSlot = vslots[0].ID
		return nil
	}

	for _, vs := range vslots {
		if vs.ID == w.vSlot {
			w.vSlot = vs.ID
			return nil
		}
	}
	return fmt.Errorf("configured vslot ID %s is not found on your account", w.vSlot)
}

// keyInit selects the key used for sealing. A configured key id is verified
// to exist; otherwise the key is looked up by name in the vslot. Not finding a
// usable key is an error so that misconfiguration surfaces at SetConfig time
// rather than on the first Encrypt or Decrypt.
func (w *Wrapper) keyInit(ctx context.Context) error {
	// The configured key ID is valid? If yes, use it.
	if w.key != uuid.Nil {
		_, err := w.kms.GetKey(ctx, w.key)
		if err != nil {
			return fmt.Errorf("getting key: %w", err)
		}

		return nil
	}

	// Look for the seal key by name. The results come back newest first,
	//so only accept an exact name match and take the most recent one.
	keys, err := w.kms.FindKeys(ctx, w.vSlot, kmssdk.KeyFilter{Name: w.keyName})
	if err != nil {
		return fmt.Errorf("finding keys: %w", err)
	}

	for _, k := range keys {
		if k.Name != w.keyName {
			continue
		}
		if k.AlgType != "AES" {
			return fmt.Errorf("unsupported algorithm type: %s", k.AlgType)
		}
		w.key = k.ID
		return nil
	}

	return fmt.Errorf("no key named %q in vslot %s", w.keyName, w.vSlot)
}

func (w *Wrapper) Encrypt(ctx context.Context, plaintext []byte, options ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	if w.key == uuid.Nil {
		return nil, fmt.Errorf("incertkms key is not available (key id: %s, key name: %q, vslot: %s)", w.key, w.keyName, w.vSlot)
	}

	// crypto/rand.Read never returns an error
	iv := make([]byte, 12)
	_, _ = rand.Read(iv)

	ciphertext, err := w.kms.Crypto(ctx, kmssdk.OperationEncrypt, w.key, kmssdk.CryptoRequest{
		Data:       plaintext,
		Algorithm:  "AES_GCM",
		Attributes: map[string]any{"iv": iv},
	})
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	ret := &wrapping.BlobInfo{
		Ciphertext: ciphertext,
		Iv:         iv,
		KeyInfo: &wrapping.KeyInfo{
			KeyId: w.key.String(),
		},
	}
	return ret, nil
}

func (w *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, options ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, fmt.Errorf("given input for decryption is nil")
	}

	if w.key == uuid.Nil {
		return nil, fmt.Errorf("incertkms key is not available (key id: %s, key name: %q, vslot: %s)", w.key, w.keyName, w.vSlot)
	}

	if in.KeyInfo == nil {
		in.KeyInfo = &wrapping.KeyInfo{
			KeyId: w.key.String(),
		}
	}

	keyIdUuid, err := uuid.Parse(in.KeyInfo.KeyId)
	if err != nil {
		return nil, fmt.Errorf("error parsing key ID: %w", err)
	}

	plaintext, err := w.kms.Crypto(ctx, kmssdk.OperationDecrypt, keyIdUuid, kmssdk.CryptoRequest{
		Data:       in.Ciphertext,
		Algorithm:  "AES_GCM",
		Attributes: map[string]any{"iv": in.Iv},
	})
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return plaintext, nil
}

func (w *Wrapper) Init(_ context.Context, _ ...wrapping.Option) error {
	return nil
}

// Finalize logs out of the KMS, invalidating the authenticated session.
func (w *Wrapper) Finalize(ctx context.Context, _ ...wrapping.Option) error {
	if w.kms == nil {
		return nil
	}
	return w.kms.Logout(ctx)
}
