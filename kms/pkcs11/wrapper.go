// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/module"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/openbao/openbao/api/v2"
)

// pkcs11Wrapper implements wrapping.Wrapper.
type pkcs11Wrapper struct {
	logger log.Logger

	mod   *module.Ref
	token *module.Token

	pin      string
	keyID    string
	keyLabel string

	mechanism *uint
	oaepHash  crypto.Hash

	disableSoftwareEncryption bool

	aliases map[string]string
}

// NewWrapper returns a new PKCS#11 wrapper.
func NewWrapper() wrapping.Wrapper {
	return &pkcs11Wrapper{}
}

// NewWrapperWithAliases returns a new PKCS#11 wrapper and provides it with a
// map of library path aliases.
func NewWrapperWithAliases(aliases map[string]string) wrapping.Wrapper {
	return &pkcs11Wrapper{aliases: aliases}
}

func (w *pkcs11Wrapper) SetConfig(ctx context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := wrapping.GetOpts(opt...)
	if err != nil {
		return nil, err
	}

	var cfg struct {
		// PKCS#11 library path.
		Lib string `mapstructure:"lib"`

		// Token slot selectors.
		Slot       *uint  `mapstructure:"slot"`
		Serial     string `mapstructure:"serial"`
		TokenLabel string `mapstructure:"token_label"`

		// PIN to authenticate against the chosen token.
		PIN string `mapstructure:"pin"`

		// Key selectors.
		KeyID    string `mapstructure:"key_id"`
		KeyLabel string `mapstructure:"key_label"`

		// Other tweaks.
		Mechanism                 string `mapstructure:"mechanism"`
		RSAOAEPHash               string `mapstructure:"rsa_oaep_hash"`
		DisableSoftwareEncryption bool   `mapstructure:"disable_software_encryption"`
	}

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           &cfg,
		ErrorUnused:      true,
		WeaklyTypedInput: true,
		RootName:         "config",
	})
	if err != nil {
		return nil, err
	}
	if err := decoder.Decode(opts.WithConfigMap); err != nil {
		return nil, err
	}

	// Merge environment variables on top of the decoded config map, if we're
	// allowed to. A set environment variable replaces values previously set via
	// config map.
	if !opts.WithDisallowEnvVars {
		for _, env := range []struct {
			name   string
			target any
		}{
			{"BAO_HSM_LIB", &cfg.Lib},
			{"BAO_HSM_SLOT", &cfg.Slot},
			{"BAO_HSM_SERIAL", &cfg.Serial},
			{"BAO_HSM_TOKEN_LABEL", &cfg.TokenLabel},
			{"BAO_HSM_PIN", &cfg.PIN},
			{"BAO_HSM_KEY_ID", &cfg.KeyID},
			{"BAO_HSM_KEY_LABEL", &cfg.KeyLabel},
			{"BAO_HSM_MECHANISM", &cfg.Mechanism},
			{"BAO_HSM_RSA_OAEP_HASH", &cfg.RSAOAEPHash},
			{"BAO_HSM_DISABLE_SOFTWARE_ENCRYPTION", &cfg.DisableSoftwareEncryption},
		} {
			if v := api.ReadBaoVariable(env.name); v != "" {
				if err := mapstructure.WeakDecode(v, env.target); err != nil {
					return nil, fmt.Errorf("decode %q: %w", env, err)
				}
			}
		}

		if err := wrapping.ParsePaths(&cfg.PIN); err != nil {
			return nil, err
		}
	}

	if cfg.Lib == "" {
		return nil, errors.New("missing required parameter 'lib'")
	}

	if cfg.KeyID == "" && cfg.KeyLabel == "" {
		return nil, errors.New("must set one of 'key_id', 'key_label'")
	}

	// Trim any hex prefix:
	keyID := strings.TrimPrefix(cfg.KeyID, "0x")

	metadata := map[string]string{
		"lib": cfg.Lib,
	}

	// Build a list of selectors to find the correct token to use:
	var selectors []module.TokenSelector
	if cfg.Slot != nil {
		selectors = append(selectors, module.SelectID(*cfg.Slot))
		metadata["slot"] = strconv.Itoa(int(*cfg.Slot))
	}
	if cfg.Serial != "" {
		selectors = append(selectors, module.SelectSerial(cfg.Serial))
		metadata["serial"] = cfg.Serial
	}
	if cfg.TokenLabel != "" {
		selectors = append(selectors, module.SelectLabel(cfg.TokenLabel))
		metadata["token_label"] = cfg.TokenLabel
	}
	if len(selectors) == 0 {
		return nil, errors.New("at least one of 'slot', 'serial', 'token_label' is required")
	}

	// Parse and optionally pin the mechanism:
	mech, err := parseMechanism(cfg.Mechanism)
	if err != nil {
		return nil, fmt.Errorf("parse 'mechanism': %w", err)
	} else if mech != nil {
		metadata["mechanism"] = mechToString(*mech)
	}

	// Parse the OAEP hash:
	oaepHash, err := parseOAEPHash(cfg.RSAOAEPHash)
	if err != nil {
		return nil, fmt.Errorf("parse 'rsa_oaep_hash': %w", err)
	} else if oaepHash != crypto.Hash(0) {
		metadata["rsa_oaep_hash"] = oaepHash.String()
	}

	// Resolve library aliases and fall back to plain path if allowed.
	lib, ok := w.aliases[cfg.Lib]
	if !ok {
		if opts.WithDisallowEnvVars {
			return nil, fmt.Errorf("unknown library alias: %q", cfg.Lib)
		} else {
			lib = cfg.Lib
		}
	}

	// Open the library:
	mod, err := module.Open(lib)
	if err != nil {
		return nil, err
	}
	// Find the token:
	token, err := mod.GetToken(selectors...)
	if err != nil {
		return nil, errors.Join(err, mod.Drop())
	}

	// Notably, unlike the KMS implementation, we don't call session.Login(...)
	// here and do it per-Encrypt()/Decrypt() call instead. This is to have
	// better backwards compatibility with OpenBao's original PKCS#11 wrapper
	// implementation which behaves the same way. This also makes rotating the
	// PIN within a system that uses the same PKCS#11 slot in several places
	// easier to do, as the wrapper doesn't constantly own a session pool that
	// locks in a particular PIN.

	w.mod, w.token = mod, token
	w.pin = cfg.PIN
	w.keyID, w.keyLabel = keyID, cfg.KeyLabel
	w.mechanism, w.oaepHash = mech, oaepHash
	w.disableSoftwareEncryption = cfg.DisableSoftwareEncryption

	w.logger = opts.WithLogger
	if w.logger == nil {
		w.logger = log.NewNullLogger()
	}

	return &wrapping.WrapperConfig{Metadata: metadata}, nil
}

func (w *pkcs11Wrapper) Init(context.Context, ...wrapping.Option) error {
	return nil
}

func (w *pkcs11Wrapper) Finalize(context.Context, ...wrapping.Option) error {
	return w.mod.Drop()
}

func (w *pkcs11Wrapper) Type(context.Context) (wrapping.WrapperType, error) {
	return "pkcs11", nil
}

func (w *pkcs11Wrapper) KeyId(context.Context) (string, error) {
	return fmt.Sprintf("%s:%s", w.keyLabel, w.keyID), nil
}

func (w *pkcs11Wrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (in *wrapping.BlobInfo, err error) {
	err = w.with(ctx, nil, func(key kms.Key) error {
		opts := &kms.CipherOptions{Data: plaintext}
		ciphertext, err := key.Encrypt(ctx, opts)
		if err != nil {
			return err
		}
		in = &wrapping.BlobInfo{
			Ciphertext: ciphertext,
			KeyInfo: &wrapping.KeyInfo{
				KeyId: fmt.Sprintf("%s:%s", w.keyLabel, w.keyID),
			},
		}
		return nil
	})
	return in, err
}

func (w *pkcs11Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) (plaintext []byte, err error) {
	err = w.with(ctx, in.KeyInfo, func(key kms.Key) error {
		plaintext, err = key.Decrypt(ctx, &kms.CipherOptions{
			// We don't ever set the Iv field in Encrypt since the KMS interface
			// does not split it, but to decrypt blobs created by the original
			// wrappers/pkcs11 we must make sure to prepend it.
			Data: append(in.Iv, in.Ciphertext...),
		})
		return err
	})
	return plaintext, err
}

func (w *pkcs11Wrapper) with(ctx context.Context, info *wrapping.KeyInfo, f func(key kms.Key) error) error {
	pool, err := session.Login(ctx, w.mod, w.token, w.pin)
	if err != nil {
		return err
	}

	defer func() {
		if err := pool.Drop(ctx); err != nil {
			w.logger.Warn("failed to close session pool", "error", err.Error())
		}
	}()

	keyID := w.keyID
	keyLabel := w.keyLabel

	// Override key ID / label if we're passed a KeyInfo.
	if info != nil {
		pos := strings.LastIndex(info.KeyId, ":")
		if pos < 0 {
			return errors.New("blob has invalid key ID format")
		}
		keyID = info.KeyId[pos+1:]
		keyLabel = info.KeyId[:pos]
	}

	parsedID, err := hex.DecodeString(keyID)
	if err != nil {
		return fmt.Errorf("parse 'key_id': %w", err)
	}

	key, err := resolveKey(
		ctx,
		pool,
		parsedID, keyLabel,
		w.mechanism, w.oaepHash,
		w.disableSoftwareEncryption,
	)
	if err != nil {
		return err
	}

	return f(key)
}
