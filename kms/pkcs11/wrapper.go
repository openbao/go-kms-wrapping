// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"strings"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/openbao/openbao/api/v2"
)

// pkcs11Wrapper implements wrapping.Wrapper.
type pkcs11Wrapper struct {
	kms pkcs11KMS

	// keyID is the pre-computed key ID to return. This never changes past
	// SetConfig().
	keyID string

	// keyConfigMap is the base config map for key lookups.
	keyConfigMap kms.ConfigMap
}

// NewWrapper creates a new PKCS#11 wrapper.
func NewWrapper() wrapping.Wrapper {
	return &pkcs11Wrapper{keyID: ":"}
}

func (w *pkcs11Wrapper) SetConfig(ctx context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := wrapping.GetOpts(opt...)
	if err != nil {
		return nil, err
	}

	// Sort opts.WithConfigMap into two kms-style config maps so we can pass
	// them to the right APIs.
	kmsConfigMap := make(kms.ConfigMap)
	keyConfigMap := make(kms.ConfigMap)

	// Also collect non-sensitive wrapper metadata to return.
	metadata := make(map[string]string)

	type field struct {
		name      string
		rename    string
		env       string
		sensitive bool
		hook      func(v string)
	}

	evalFields := func(config kms.ConfigMap, fields []field) {
		for _, f := range fields {
			var (
				v  string
				ok bool
			)
			if !opts.WithDisallowEnvVars && f.env != "" {
				v, ok = api.LookupBaoVariable(f.env)
			}
			if !ok {
				v, ok = opts.WithConfigMap[f.name]
			}
			if !ok {
				continue
			}

			config[cmp.Or(f.rename, f.name)] = v

			if !f.sensitive {
				metadata[f.name] = v
			}

			if f.hook != nil {
				f.hook(v)
			}
		}
	}

	evalFields(kmsConfigMap, []field{
		{
			name: "lib",
			env:  "BAO_HSM_LIB",
		},
		{
			name:      "pin",
			env:       "BAO_HSM_PIN",
			sensitive: true,
		},
		{
			name: "slot",
			env:  "BAO_HSM_SLOT",
		},
		{
			name: "serial",
			env:  "BAO_HSM_SERIAL",
		},
		{
			name: "token_label",
			env:  "BAO_HSM_TOKEN_LABEL",
		},
		{
			name: "disable_software_encryption",
			env:  "BAO_HSM_DISABLE_SOFTWARE_ENCRYPTION",
		},
	})

	evalFields(keyConfigMap, []field{
		{
			name: "mechanism",
			env:  "BAO_HSM_MECHANISM",
		},
		{
			name: "rsa_oaep_hash",
			env:  "BAO_HSM_RSA_OAEP_HASH",
		},
		{
			name:   "key_id",
			rename: "id",
			env:    "BAO_HSM_KEY_ID",
			hook:   func(v string) { w.keyID = w.keyID + v },
		},
		{
			name:   "key_label",
			rename: "label",
			env:    "BAO_HSM_KEY_LABEL",
			hook:   func(v string) { w.keyID = v + w.keyID },
		},
	})

	if err := w.kms.Open(ctx, &kms.OpenOptions{
		ConfigMap:        kmsConfigMap,
		Logger:           opts.WithLogger,
		AllowEnvironment: !opts.WithDisallowEnvVars,
	}); err != nil {
		return nil, err
	}

	w.keyConfigMap = keyConfigMap

	return &wrapping.WrapperConfig{Metadata: metadata}, nil
}

func (w *pkcs11Wrapper) Init(context.Context, ...wrapping.Option) error {
	return nil
}

func (w *pkcs11Wrapper) Finalize(ctx context.Context, _ ...wrapping.Option) error {
	return w.kms.Close(ctx)
}

func (w *pkcs11Wrapper) Type(context.Context) (wrapping.WrapperType, error) {
	return "pkcs11", nil
}

func (w *pkcs11Wrapper) KeyId(context.Context) (string, error) {
	return w.keyID, nil
}

func (w *pkcs11Wrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	key, err := w.kms.GetKey(ctx, &kms.KeyOptions{
		ConfigMap: w.keyConfigMap,
	})
	if err != nil {
		return nil, err
	}

	opts := &kms.CipherOptions{Data: plaintext}
	ciphertext, err := key.Encrypt(ctx, opts)
	if err != nil {
		return nil, err
	}

	return &wrapping.BlobInfo{
		Iv:         opts.Nonce,
		Ciphertext: ciphertext,
		KeyInfo: &wrapping.KeyInfo{
			KeyId: w.keyID,
		},
	}, nil
}

func (w *pkcs11Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	keyConfigMap := w.keyConfigMap

	if in.KeyInfo != nil {
		pos := strings.LastIndex(in.KeyInfo.KeyId, ":")
		if pos < 0 {
			return nil, errors.New("invalid key ID format")
		}

		// Override with values from KeyInfo.
		keyConfigMap = maps.Clone(keyConfigMap)
		delete(keyConfigMap, "id")
		delete(keyConfigMap, "label")

		id := in.KeyInfo.KeyId[pos+1:]
		label := in.KeyInfo.KeyId[:pos]

		if id != "" {
			keyConfigMap["id"] = id
		}
		if label != "" {
			keyConfigMap["label"] = label
		}
	}

	key, err := w.kms.GetKey(ctx, &kms.KeyOptions{
		ConfigMap: keyConfigMap,
	})
	if err != nil {
		return nil, err
	}

	return key.Decrypt(ctx, &kms.CipherOptions{
		Data:  in.Ciphertext,
		Nonce: in.Iv,
	})
}
