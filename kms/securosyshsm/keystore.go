// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package securosyshsm

import (
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/mitchellh/mapstructure"
	"github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/client"
	"github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/helpers"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

// Ensure KeyStore implements KeyStore
var (
	_ kms.KeyStore    = (*keyStore)(nil)
	_ kms.NewKeyStore = NewKeyStore
)

// KeyStore is a KeyStore backed by a Securosys HSM.
// In real life, this would use the Securosys SDK / PKCS#11 library.
var LOGGER = slog.New(slog.NewTextHandler(os.Stdout, nil))

type keyStore struct {
	params *map[string]any
	client *client.SecurosysClient
	closed bool
}

func (s *keyStore) Close(ctx context.Context) error {
	if s.closed {
		return nil
	}
	// TODO: finalize HSM session
	s.closed = true
	return nil
}

func (s *keyStore) Login(ctx context.Context, _ *kms.Credentials) error {
	s.closed = false
	return nil
}

func (s *keyStore) ListKeys(ctx context.Context) ([]kms.Key, error) {
	// 1️⃣ Check if connection is closed
	if err := IsConnectionClosed(s.closed); err != nil {
		return nil, err
	}

	// 2️⃣ Respect context cancellation before doing anything
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// 3️⃣ Get keys from client (assuming GetKeys doesn’t accept ctx)
	keys, err := s.client.GetKeys()
	if err != nil {
		return nil, err
	}

	var mappedKeys []kms.Key

	// 4️⃣ Iterate with cancellation checks
	for _, keyLabel := range keys {
		select {
		case <-ctx.Done():
			// Graceful exit if context is cancelled mid-loop
			return mappedKeys, ctx.Err()
		default:
		}

		getKey, err := s.client.GetKey(keyLabel, "")
		if err != nil {
			continue // skip key on error
		}

		if getKey.Algorithm == "ED" || getKey.Algorithm == "RSA" || getKey.Algorithm == "AES" || getKey.Algorithm == "EC" {
			if getKey.PublicKey == "" {
				mappedKeys = append(mappedKeys, &SecretKey{
					key: key{
						client:   s.client,
						password: "",
						key:      getKey,
					},
				})

			} else {
				mappedKeys = append(mappedKeys, &PrivateKey{
					key: key{
						client:   s.client,
						password: "",
						key:      getKey,
					},
					publicKeyString: getKey.PublicKey,
				})

			}
		}
	}

	return mappedKeys, nil
}
func (s *keyStore) GetKeyById(ctx context.Context, keyId string) (kms.Key, error) {
	// 1️⃣ Check if context is already cancelled
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// 2️⃣ Determine password
	keyPassword := ""
	//if len(password) > 0 {
	//	keyPassword = password[0]
	//}

	// 3️⃣ Get key from client (if client supports context, pass it)
	getKey, err := s.client.GetKey(keyId, keyPassword)
	if err != nil {
		return nil, err
	}

	if getKey.PublicKey == "" {
		return &SecretKey{
			key: key{
				client:   s.client,
				password: keyPassword,
				key:      getKey,
			},
		}, nil

	} else {
		return &PrivateKey{
			key: key{
				client:   s.client,
				password: keyPassword,
				key:      getKey,
			},
			publicKeyString: getKey.PublicKey,
		}, nil

	}
}

func (s *keyStore) GetKeyByName(ctx context.Context, keyName string) (kms.Key, error) {
	// 1️⃣ Check context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// 2️⃣ Determine password
	keyPassword := ""
	//if len(password) > 0 {
	//	keyPassword = password[0]
	//}

	// 3️⃣ Get key from client
	getKey, err := s.client.GetKey(keyName, keyPassword)
	if err != nil {
		return nil, err
	}
	if getKey.PublicKey == "" {
		return &SecretKey{
			key: key{
				client:   s.client,
				password: keyPassword,
				key:      getKey,
			},
		}, nil

	} else {
		return &PrivateKey{
			key: key{
				client:   s.client,
				password: keyPassword,
				key:      getKey,
			},
			publicKeyString: getKey.PublicKey,
		}, nil

	}
}

func (s *keyStore) GetKeyByAttrs(ctx context.Context, attrs map[string]interface{}) (kms.Key, error) {
	return nil, fmt.Errorf("GetKeyByAttrs is not supported by SecurosysKMS")
}

func (s *keyStore) GetInfo() map[string]string {
	//TODO implement me
	panic("implement me")
}

func (s *keyStore) GenerateRandom(ctx context.Context, length int) ([]byte, error) {
	if length < 1 {
		return nil, errors.New("length must be greater than zero")
	}

	// Check context before starting
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	generateRandom, _, err := s.client.GenerateRandom(length)
	if err != nil {
		return nil, err
	}

	random, _ := b64.StdEncoding.DecodeString(generateRandom.Random)
	return random, nil
}

func (s *keyStore) GenerateSecretKey(ctx context.Context, keyAttributes *kms.KeyAttributes) (kms.Key, error) {
	// Check context
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	keyType := ""
	switch keyAttributes.KeyType {
	case kms.KeyType_AES:
		keyType = "AES"
	case kms.KeyType_Generic_Secret:
		return nil, errors.New("Generic Secret Key is not yet supported")
	default:
		return nil, errors.New("Not supported key type")
	}

	attributes := attributesMapper(keyAttributes)

	keyPassword := ""
	//if len(password) > 0 {
	//	keyPassword = password[0]
	//}

	keyName, err := s.client.CreateOrUpdateKey(keyAttributes.Name, keyPassword, attributes, keyType, float64(keyAttributes.BitKeyLen), nil, "", false)
	if err != nil {
		return nil, err
	}

	newKey, err := s.client.GetKey(keyName, keyPassword)
	if err != nil {
		return nil, err
	}
	k := &key{
		client:   s.client,
		password: keyPassword,
		key:      newKey,
	}
	secret := &SecretKey{
		*k,
	}
	return secret, nil
}

func (s *keyStore) GenerateKeyPair(ctx context.Context, keyPairAttributes *kms.KeyAttributes) (privKey kms.Key, pubKey kms.Key, err error) {
	// Check context
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}

	keyType := ""
	var curveOid string
	var keySize float64
	switch keyPairAttributes.KeyType {
	case kms.KeyType_RSA_Private:
		keyType = "RSA"
		curveOid = ""
		keySize = float64(keyPairAttributes.BitKeyLen)
	case kms.KeyType_EC_Private:
		keyType = "EC"
		curveOid = helpers.MapCurveToStringCurve(keyPairAttributes.Curve)
		keySize = 0
	case kms.KeyType_ED_Private:
		keyType = "ED"
		curveOid = "1.3.101.112"
		keySize = 0
	default:
		return nil, nil, errors.New("unsupported key type")
	}

	attributes := attributesMapper(keyPairAttributes)

	keyPassword := ""
	//if len(password) > 0 {
	//	keyPassword = password[0]
	//}

	policy, err := MapToPolicy(keyPairAttributes.ProviderSpecific)
	if err != nil {
		return nil, nil, err
	}
	keyName, err := s.client.CreateOrUpdateKey(keyPairAttributes.Name, keyPassword, attributes, keyType, keySize, policy, curveOid, false)
	if err != nil {
		return nil, nil, err
	}

	getKey, err := s.client.GetKey(keyName, keyPassword)
	if err != nil {
		return nil, nil, err
	}

	k := &key{
		client:   s.client,
		password: keyPassword,
		key:      getKey,
	}
	var priv = &PrivateKey{
		*k,
		k.key.PublicKey,
	}
	var pub = &PublicKey{
		*k,
		k.key.PublicKey,
	}
	return priv, pub, nil
}

func (s *keyStore) RemoveKey(ctx context.Context, key kms.Key) error {
	// Check context
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	return s.client.RemoveKey(key.GetName())
}

// KeyStoreFactory creates KeyStore instances
type KeyStoreFactory struct{}

func NewKeyStore(params map[string]any) (kms.KeyStore, error) {
	if params == nil {
		return nil, errors.New("params parameters required")
	}

	bytes, _ := json.Marshal(params)
	var config *helpers.SecurosysConfig
	json.Unmarshal(bytes, &config)

	c, err := client.NewClient(config)

	if err != nil {
		return nil, err
	}
	connection, status, err := c.CheckConnection()
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, errors.New(connection)
	}
	//LOGGER.Info(connection)
	return &keyStore{
		client: c,
		closed: false,
	}, nil
}

func attributesMapper(keyAttributes *kms.KeyAttributes) map[string]bool {
	var attributes = make(map[string]bool)
	attributes["decrypt"] = keyAttributes.CanDecrypt
	attributes["sign"] = keyAttributes.CanSign
	attributes["unwrap"] = keyAttributes.CanUnwrap
	attributes["verify"] = keyAttributes.CanVerify
	attributes["wrap"] = keyAttributes.CanWrap
	attributes["derive"] = keyAttributes.CanDerive
	attributes["encrypt"] = keyAttributes.CanEncrypt
	attributes["sensitive"] = keyAttributes.IsSensitive
	attributes["extractable"] = keyAttributes.IsExportable
	attributes["destroyable"] = keyAttributes.IsRemovable
	return attributes
}
func PolicyToMap(policy *helpers.Policy) (map[string]interface{}, error) {
	if policy == nil {
		return nil, nil
	}

	// Marshal struct to JSON
	data, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}

	// Unmarshal JSON into map
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	return m, nil
}
func MapToPolicy(m map[string]interface{}) (*helpers.Policy, error) {
	var policy helpers.Policy
	if m == nil {
		return nil, nil
	}
	if err := mapstructure.Decode(m, &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

func IsConnectionClosed(closed bool) error {
	if closed {
		return errors.New("keystore already closed")
	}
	return nil
}
