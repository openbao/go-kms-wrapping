// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package securosyshsm

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/client"
	"github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/helpers"
	kms "github.com/openbao/go-kms-wrapping/v2/kms"
)

// Ensure KeyStore implements KeyStore
var _ kms.Key = (*key)(nil)

var (
	_ kms.AsymmetricKey = (*PublicKey)(nil)
	_ kms.AsymmetricKey = (*PrivateKey)(nil)
)

type key struct {
	key      helpers.KeyAttributes
	client   *client.SecurosysClient
	password string
}

func (k key) IsAsymmetric() bool {
	if k.key.PublicKey != "" {
		return true
	}
	return false
}

func (k key) Resolved() bool {
	return true
}

func (k key) Resolve(ctx context.Context) (kms.Key, error) {
	return k, nil
}

func (k key) Login(ctx context.Context, credentials *kms.Credentials) error {
	if credentials != nil {
		k.password = credentials.Password
	}
	return nil
}

func (k key) GetType() kms.KeyType {
	switch k.key.Algorithm {
	case "RSA":
		return kms.KeyType_RSA_Private
	case "AES":
		return kms.KeyType_AES
	case "EC":
		return kms.KeyType_EC_Private
	case "ED":
		return kms.KeyType_ED_Private
	}
	return kms.Keytype_Unsupported
}

func (k key) GetProtectedKeyAttributes() *kms.ProtectedKeyAttributes {
	//TODO implement me
	panic("implement me")
}

func (s key) Close(ctx context.Context) error {
	s.password = ""
	return nil

}

func (s key) GetId() string {
	if s.key.Id != nil {
		return *s.key.Id
	}
	return s.key.Label
}

func (s key) GetName() string {
	return s.key.Label
}

func (s key) GetGroupId() string {
	return ""
}

func (s key) IsPersistent() bool {
	//TODO implement me
	panic("implement me")
}

func (s key) IsSensitive() bool {
	return s.key.Attributes["sensitive"]
}

func (s key) GetLength() uint32 {
	return uint32(s.key.KeySize)
}

func (s key) GetAlgorithm() string {
	if s.key.CurveOid != "" {
		return s.key.CurveOid
	}
	return s.key.AlgorithmOid
}

func (s key) GetKeyAttributes() *kms.KeyAttributes {
	attributes := s.key.Attributes

	keyAttributes := kms.KeyAttributes{
		Curve:            helpers.MapStringCurverToCurve(s.key.CurveOid),
		IsSensitive:      attributes["sensitive"],
		IsDerivable:      attributes["derive"],
		IsExportable:     attributes["extractable"],
		IsRemovable:      attributes["destroyable"],
		CanDecrypt:       attributes["decrypt"],
		CanEncrypt:       attributes["encrypt"],
		CanDerive:        attributes["derive"],
		CanSign:          attributes["sign"],
		CanVerify:        attributes["sign"],
		CanUnwrap:        attributes["unwrap"],
		CanWrap:          attributes["unwrap"],
		ProviderSpecific: convertPolicyToMap(s.key.Policy),
	}
	return &keyAttributes
}

type SecretKey struct {
	key
}

type PublicKey struct {
	key
	publicKeyString string
}

func (p *PublicKey) GetPublic(ctx context.Context) (kms.Key, error) {
	return p, nil
}

func (p *PublicKey) ExportPublic(ctx context.Context) ([]byte, error) {
	if p.publicKeyString == "" {
		return nil, errors.New("public key string is empty")
	}

	// Try to decode PEM first
	block, _ := pem.Decode([]byte(p.publicKeyString))
	if block != nil {
		// It’s a valid PEM — just return DER bytes
		return block.Bytes, nil
	}

	// Not PEM → try Base64 decode (no headers)
	derBytes, err := base64.StdEncoding.DecodeString(p.publicKeyString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 public key: %w", err)
	}

	// Optional: verify it’s a valid public key
	_, err = x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ASN.1 public key: %w", err)
	}
	return derBytes, nil
}

func (p *PublicKey) ExportComponentPublic(ctx context.Context) (interface{}, error) {
	return nil, nil
}

type PrivateKey struct {
	key
	publicKeyString string
}

func (p *PrivateKey) GetPublic(ctx context.Context) (kms.Key, error) {
	return p, nil
}

func (p *PrivateKey) ExportPublic(ctx context.Context) ([]byte, error) {
	if p.publicKeyString == "" {
		return nil, errors.New("public key string is empty")
	}

	// Try to decode PEM first
	block, _ := pem.Decode([]byte(p.publicKeyString))
	if block != nil {
		// It’s a valid PEM — just return DER bytes
		return block.Bytes, nil
	}

	// Not PEM → try Base64 decode (no headers)
	derBytes, err := base64.StdEncoding.DecodeString(p.publicKeyString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 public key: %w", err)
	}

	// Optional: verify it’s a valid public key
	_, err = x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ASN.1 public key: %w", err)
	}
	return derBytes, nil
}

func (p *PrivateKey) ExportComponentPublic(ctx context.Context) (interface{}, error) {
	return nil, nil
}

func convertPolicyToMap(policy *helpers.Policy) map[string]interface{} {
	if policy == nil {
		return nil
	}
	// Convert struct -> JSON bytes
	data, _ := json.Marshal(policy)

	// Convert JSON bytes -> map[string]interface{}
	var result map[string]interface{}
	err := json.Unmarshal(data, &result)
	if err != nil {
		return nil
	}
	return result
}
func WithPrivateKey(ctx context.Context, key *PrivateKey) context.Context {
	return context.WithValue(ctx, kms.CONTEXT_KEY_NAME, key)
}
func WithPublicKey(ctx context.Context, key *PublicKey) context.Context {
	return context.WithValue(ctx, kms.CONTEXT_KEY_NAME, key)
}
func WithSecretKey(ctx context.Context, key *SecretKey) context.Context {
	return context.WithValue(ctx, kms.CONTEXT_KEY_NAME, key)
}

func PrivateKeyFromContext(ctx context.Context) *PrivateKey {
	val := ctx.Value(kms.CONTEXT_KEY_NAME)
	ctxValue, ok := val.(*PrivateKey)
	if !ok {
		// handle missing or wrong type safely
		return nil // or return an error
	}
	return ctxValue
}
func PublicKeyFromContext(ctx context.Context) *PublicKey {
	val := ctx.Value(kms.CONTEXT_KEY_NAME)
	ctxValue, ok := val.(*PublicKey)
	if !ok {
		// handle missing or wrong type safely
		return nil // or return an error
	}
	return ctxValue
}
func SecretKeyFromContext(ctx context.Context) *SecretKey {
	val := ctx.Value(kms.CONTEXT_KEY_NAME)
	ctxValue, ok := val.(*SecretKey)
	if !ok {
		// handle missing or wrong type safely
		return nil // or return an error
	}
	return ctxValue
}
