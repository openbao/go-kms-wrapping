// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"cmp"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/openbao/openbao/api/v2"
)

var ErrPrehashingDisabled = errors.New("pre-hashing is disabled")

// New returns a new KMS that uses OpenBao's Transit engine.
func New() kms.KMS {
	return &transitKMS{}
}

// transitKMS implements kms.KMS.
type transitKMS struct {
	kms.UnimplementedKMS

	client *api.Client
	mount  string // The configured Transit engine mount path.

	// To keep the client's token alive.
	lifetimeWatcher *api.LifetimeWatcher
}

func (k *transitKMS) Open(ctx context.Context, opts *kms.OpenOptions) error {
	var cfg struct {
		Address        string `mapstructure:"address"`
		Token          string `mapstructure:"token"`
		Namespace      string `mapstructure:"namespace"`
		MountPath      string `mapstructure:"mount_path"`
		DisableRenewal bool   `mapstructure:"disable_renewal"`

		TLSCaCert     string `mapstructure:"tls_ca_cert"`
		TLSServerName string `mapstructure:"tls_server_name"`
		TLSSkipVerify bool   `mapstructure:"tls_skip_verify"`

		// This is missing client cert configuration, but that is blocked on
		// https://github.com/openbao/openbao/issues/2762.
	}
	if err := mapstructure.WeakDecode(opts.ConfigMap, &cfg); err != nil {
		return err
	}

	if cfg.Token == "" {
		return errors.New("missing required parameter 'token'")
	}

	// TODO(satoqz): This reads environment variables, and we don't have a good
	// way around it yet. Fix this once the api package offers ways to create a
	// clean config.
	apiConfig := api.DefaultConfig()
	if cfg.Address != "" {
		apiConfig.Address = cfg.Address
	}

	if cfg.TLSCaCert != "" || cfg.TLSServerName != "" || cfg.TLSSkipVerify {
		if err := apiConfig.ConfigureTLS(&api.TLSConfig{
			CACertBytes:   []byte(cfg.TLSCaCert),
			TLSServerName: cfg.TLSServerName,
			Insecure:      cfg.TLSSkipVerify,
		}); err != nil {
			return err
		}
	}

	// TODO(satoqz): This also reads environment variables, with no way to
	// circumvent it at all.
	client, err := api.NewClient(apiConfig)
	if err != nil {
		return err
	}

	client.SetToken(cfg.Token)
	client.SetNamespace(cfg.Namespace)

	logger := opts.Logger
	if logger == nil {
		// So we don't need to guard against the logger being nil.
		logger = hclog.NewNullLogger()
	}

	var lifetimeWatcher *api.LifetimeWatcher
	if !cfg.DisableRenewal {
		// Renew the token immediately to get a secret to pass to lifetime
		// watcher.
		secret, err := client.Auth().Token().RenewTokenAsSelf(client.Token(), 0)
		// If we don't get an error renewing, set up a lifetime watcher. The
		// token may not be renewable or not have permission to renew-self.
		if err == nil {
			input := &api.LifetimeWatcherInput{Secret: secret}
			lifetimeWatcher, err = client.NewLifetimeWatcher(input)
			if err != nil {
				return err
			}
			go func() {
				for {
					select {
					case err := <-lifetimeWatcher.DoneCh():
						logger.Info("shutting down token renewal")
						if err != nil {
							logger.Error("error renewing token", "error", err)
						}
						return
					case <-lifetimeWatcher.RenewCh():
						logger.Trace("successfully renewed token")
					}
				}
			}()
			go lifetimeWatcher.Start()
		} else {
			logger.Info("unable to renew token, disabling renewal", "err", err)
		}
	}

	k.client = client
	k.lifetimeWatcher = lifetimeWatcher
	k.mount = cmp.Or(cfg.MountPath, "transit")

	return nil
}

func (k *transitKMS) Close(context.Context) error {
	// We have no resources to clear besides the LifetimeWatcher's Goroutines.
	if k.lifetimeWatcher != nil {
		k.lifetimeWatcher.Stop()
	}
	return nil
}

func (k *transitKMS) GetKey(_ context.Context, opts *kms.KeyOptions) (kms.Key, error) {
	var cfg struct {
		Name              string `mapstructure:"name"`
		DisablePrehashing bool   `mapstructure:"disable_prehashing"`
	}
	if err := mapstructure.WeakDecode(opts.ConfigMap, &cfg); err != nil {
		return nil, err
	}
	if cfg.Name == "" {
		return nil, errors.New("missing required parameter 'name'")
	}

	return &transitKey{
		client:            k.client,
		mount:             k.mount,
		name:              cfg.Name,
		disablePrehashing: cfg.DisablePrehashing,
	}, nil
}

// transitKey implements kms.Key.
type transitKey struct {
	kms.UnimplementedKey

	client *api.Client

	mount string // The configured Transit engine mount path.
	name  string // The configured key name.

	disablePrehashing bool
}

// See: https://openbao.org/api-docs/secret/transit/#encrypt-data
func (k *transitKey) Encrypt(ctx context.Context, opts *kms.CipherOptions) ([]byte, error) {
	data := map[string]any{
		"plaintext": base64.StdEncoding.EncodeToString(opts.Data),
	}
	if len(opts.AAD) != 0 {
		data["associated_data"] = base64.StdEncoding.EncodeToString(opts.AAD)
	}

	resp, err := k.client.Logical().WriteWithContext(
		ctx, path.Join(k.mount, "encrypt", k.name), data)
	if err != nil {
		return nil, err
	}

	ciphertext, ok := resp.Data["ciphertext"].(string)
	if !ok {
		return nil, errors.New("expected response to include 'ciphertext' field of type string")
	}
	// vault:<version>:<base64-encoded ciphertext>
	parts := strings.SplitN(ciphertext, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected ciphertext to split into 3 parts, got %d", len(parts))
	}
	out, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	opts.KeyVersion = parts[1]
	return out, nil
}

// See: https://openbao.org/api-docs/secret/transit/#decrypt-data
func (k *transitKey) Decrypt(ctx context.Context, opts *kms.CipherOptions) ([]byte, error) {
	data := map[string]any{
		"ciphertext": fmt.Sprintf("vault:%s:%s",
			opts.KeyVersion, base64.StdEncoding.EncodeToString(opts.Data)),
	}
	if len(opts.AAD) != 0 {
		data["associated_data"] = base64.StdEncoding.EncodeToString(opts.AAD)
	}

	resp, err := k.client.Logical().WriteWithContext(
		ctx, path.Join(k.mount, "decrypt", k.name), data)
	if err != nil {
		return nil, err
	}

	plaintext, ok := resp.Data["plaintext"].(string)
	if !ok {
		return nil, errors.New("expected response to include 'plaintext' field of type string")
	}
	out, err := base64.StdEncoding.DecodeString(plaintext)
	if err != nil {
		return nil, fmt.Errorf("decode plaintext: %w", err)
	}
	return out, nil
}

var hash2transit = map[crypto.Hash]string{
	crypto.SHA224:   "sha2-224",
	crypto.SHA256:   "sha2-256",
	crypto.SHA384:   "sha2-384",
	crypto.SHA512:   "sha2-512",
	crypto.SHA3_224: "sha3-224",
	crypto.SHA3_256: "sha3-256",
	crypto.SHA3_384: "sha3-384",
	crypto.SHA3_512: "sha3-512",
}

// See: https://openbao.org/api-docs/secret/transit/#sign-data
func (k *transitKey) Sign(ctx context.Context, opts *kms.SignOptions) ([]byte, error) {
	hash := opts.HashFunc()
	if opts.Prehashed && hash != crypto.Hash(0) && k.disablePrehashing {
		// We are not allowed to pre-hash but got pre-hashed data.
		return nil, ErrPrehashingDisabled
	}

	data := make(map[string]any)
	if transitHash, ok := hash2transit[hash]; ok {
		data["hash_algorithm"] = transitHash
	} else if hash != crypto.Hash(0) {
		return nil, fmt.Errorf("unsupported hash function: %s", hash)
	}

	if !opts.Prehashed && hash != crypto.Hash(0) && !k.disablePrehashing {
		// Pre-hash data for efficiency.
		h := hash.New()
		if _, err := h.Write(opts.Data); err != nil {
			return nil, fmt.Errorf("hash message: %w", err)
		}
		data["input"] = base64.StdEncoding.EncodeToString(h.Sum(nil))
		data["prehashed"] = true
	} else {
		// Data is either already hashed or cannot be pre-hashed.
		data["input"] = base64.StdEncoding.EncodeToString(opts.Data)
		data["prehashed"] = opts.Prehashed && hash != crypto.Hash(0)
	}

	switch opts := opts.SignerOpts.(type) {
	case *rsa.PSSOptions:
		switch opts.SaltLength {
		case rsa.PSSSaltLengthAuto:
			data["salt_length"] = "auto"
		case rsa.PSSSaltLengthEqualsHash:
			data["salt_length"] = "hash"
		default:
			data["salt_length"] = opts.SaltLength
		}
	case *ed25519.Options:
		// Transit fully ignores the hash_algorithm parameter when signing via
		// an Ed25519 key, this helps guard against accidental misuse.
		if hash != crypto.Hash(0) {
			return nil, errors.New("pre-hashed Ed25519 variants are not supported")
		}
	}

	resp, err := k.client.Logical().WriteWithContext(
		ctx, path.Join(k.mount, "sign", k.name), data)
	if err != nil {
		return nil, err
	}

	signature, ok := resp.Data["signature"].(string)
	if !ok {
		return nil, errors.New("expected response to include 'signature' field of type string")
	}
	// vault:<version>:<base64-encoded signature>
	parts := strings.SplitN(signature, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected signature to split into 3 parts, got %d", len(parts))
	}
	out, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	opts.KeyVersion = parts[1]
	return out, nil
}

// See: https://openbao.org/api-docs/secret/transit/#verify-signed-data
func (k *transitKey) Verify(ctx context.Context, opts *kms.VerifyOptions) error {
	hash := opts.HashFunc()
	if opts.Prehashed && hash != crypto.Hash(0) && k.disablePrehashing {
		// We are not allowed to pre-hash but got pre-hashed data.
		return ErrPrehashingDisabled
	}

	data := map[string]any{
		"signature": fmt.Sprintf("vault:%s:%s",
			opts.KeyVersion, base64.StdEncoding.EncodeToString(opts.Signature)),
	}

	if transitHash, ok := hash2transit[hash]; ok {
		data["hash_algorithm"] = transitHash
	} else if hash != crypto.Hash(0) {
		return fmt.Errorf("unsupported hash function: %s", hash)
	}

	if !opts.Prehashed && hash != crypto.Hash(0) && !k.disablePrehashing {
		// Pre-hash data for efficiency.
		h := hash.New()
		if _, err := h.Write(opts.Data); err != nil {
			return fmt.Errorf("hash message: %w", err)
		}
		data["input"] = base64.StdEncoding.EncodeToString(h.Sum(nil))
		data["prehashed"] = true
	} else {
		// Data is either already hashed or cannot be pre-hashed.
		data["input"] = base64.StdEncoding.EncodeToString(opts.Data)
		data["prehashed"] = opts.Prehashed && hash != crypto.Hash(0)
	}

	switch opts := opts.SignerOpts.(type) {
	case *rsa.PSSOptions:
		switch opts.SaltLength {
		case rsa.PSSSaltLengthAuto:
			data["salt_length"] = "auto"
		case rsa.PSSSaltLengthEqualsHash:
			data["salt_length"] = "hash"
		default:
			data["salt_length"] = opts.SaltLength
		}
	case *ed25519.Options:
		// Transit fully ignores the hash_algorithm parameter when signing via
		// an Ed25519 key, this helps guard against accidental misuse.
		if hash != crypto.Hash(0) {
			return errors.New("pre-hashed Ed25519 variants are not supported")
		}
	}

	resp, err := k.client.Logical().WriteWithContext(
		ctx, path.Join(k.mount, "verify", k.name), data)
	if err != nil {
		return err
	}

	valid, ok := resp.Data["valid"].(bool)
	switch {
	case !ok:
		err = errors.New("expected response to include 'valid' field of type bool")
	case !valid:
		err = kms.ErrInvalidSignature
	}
	return err
}

// See: https://openbao.org/api-docs/secret/transit/#export-key
func (k *transitKey) ExportPublic(ctx context.Context) (crypto.PublicKey, error) {
	resp, err := k.client.Logical().ReadWithContext(
		ctx, path.Join(k.mount, "export/public-key", k.name, "latest"))
	if err != nil {
		return nil, err
	}

	// Parse the response data:
	ty, ok := resp.Data["type"].(string)
	if !ok {
		return nil, errors.New("expected response to include 'type' field of type string")
	}
	keys, ok := resp.Data["keys"].(map[string]any)
	if !ok {
		return nil, errors.New("expected response to include 'keys' field of type object")
	}
	if len(keys) != 1 {
		return nil, fmt.Errorf("expected exactly one key, got %d", len(keys))
	}
	data, ok := keys["1"].(string)
	if !ok {
		return nil, errors.New("expected public key data of type string")
	}

	// Parse the public key:
	switch {
	case strings.HasPrefix(ty, "rsa-"), strings.HasPrefix(ty, "ecdsa-"):
		block, _ := pem.Decode([]byte(data))
		if block == nil {
			return nil, errors.New("invalid PEM data")
		}
		return x509.ParsePKIXPublicKey(block.Bytes)

	case ty == "ed25519":
		raw, err := base64.StdEncoding.DecodeString(data)
		switch {
		case err != nil:
			return nil, err
		case len(raw) != ed25519.PublicKeySize:
			return nil, errors.New("invalid ed25519 public key")
		}
		return ed25519.PublicKey(raw), nil

	default:
		return nil, fmt.Errorf("unknown key type %q", ty)
	}
}
