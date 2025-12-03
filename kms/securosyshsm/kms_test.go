// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package securosyshsm

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/stretchr/testify/assert"
)

var provider = map[string]interface{}{
	"restapi": "TSB_URL",
	"auth":    "NONE",
}

var AES_KEY_NAME = "aes_tee_key"
var RSA_KEY_NAME = "output_key_tee"

func GenerateTestKeyAES(ctx context.Context, keystore kms.KeyStore) (*SecretKey, error) {

	key, err := keystore.GetKeyByName(ctx, "OPENBAO_AES_TEST_KEY")
	if key != nil {
		return key.(*SecretKey), nil
	}
	key, err = keystore.GenerateSecretKey(ctx, &kms.KeyAttributes{
		KeyType:     kms.KeyType_AES,
		Name:        "OPENBAO_AES_TEST_KEY",
		BitKeyLen:   256,
		IsRemovable: true,
		CanDecrypt:  true,
		CanEncrypt:  true,
	})
	return key.(*SecretKey), err
}
func GenerateTestKeyRSA(ctx context.Context, keystore kms.KeyStore) (*PrivateKey, error) {
	key, err := keystore.GetKeyByName(ctx, "OPENBAO_RSA_TEST_KEY")
	if key != nil {
		return key.(*PrivateKey), nil
	}
	privateKey, _, err := keystore.GenerateKeyPair(ctx, &kms.KeyAttributes{
		KeyType:     kms.KeyType_RSA_Private,
		Name:        "OPENBAO_RSA_TEST_KEY",
		BitKeyLen:   2048,
		IsRemovable: true,
		CanDecrypt:  true,
		CanEncrypt:  true,
		CanSign:     true,
		CanVerify:   true,
	})
	return privateKey.(*PrivateKey), err
}
func GenerateTestKeyEC(ctx context.Context, curve kms.Curve, keystore kms.KeyStore) (*PrivateKey, error) {
	key, err := keystore.GetKeyByName(ctx, "OPENBAO_EC_TEST_KEY")
	if key != nil {
		return key.(*PrivateKey), nil
	}
	privateKey, _, err := keystore.GenerateKeyPair(ctx, &kms.KeyAttributes{
		KeyType:     kms.KeyType_EC_Private,
		Name:        "OPENBAO_EC_TEST_KEY",
		Curve:       kms.Curve_P256,
		IsRemovable: true,
		CanDecrypt:  true,
		CanEncrypt:  true,
		CanSign:     true,
		CanVerify:   true,
	})
	return privateKey.(*PrivateKey), err
}
func GenerateTestKeyED(ctx context.Context, keystore kms.KeyStore) (*PrivateKey, error) {
	key, err := keystore.GetKeyByName(ctx, "OPENBAO_ED_TEST_KEY")
	if key != nil {
		return key.(*PrivateKey), nil
	}
	privateKey, _, err := keystore.GenerateKeyPair(ctx, &kms.KeyAttributes{
		KeyType:     kms.KeyType_ED_Private,
		Name:        "OPENBAO_ED_TEST_KEY",
		Curve:       kms.Curve_None,
		IsRemovable: true,
		CanDecrypt:  true,
		CanEncrypt:  true,
		CanSign:     true,
		CanVerify:   true,
	})
	return privateKey.(*PrivateKey), err
}
func RemoveKey(ctx context.Context, key kms.Key, keystore kms.KeyStore) error {
	err := keystore.RemoveKey(ctx, key)
	return err
}

func TestKMS(t *testing.T) {
	t.Run("Keystore: Init", func(t *testing.T) {
		_, err := NewKeyStore(provider)
		assert.NoError(t, err)

	})
	t.Run("Keystore: GenerateSecretKey", func(t *testing.T) {
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		key, err := keystore.GenerateSecretKey(t.Context(), &kms.KeyAttributes{
			KeyType:     kms.KeyType_AES,
			Name:        "AES_KEY_OPENBAO_TEST_CREATE_KEY",
			BitKeyLen:   256,
			IsRemovable: true,
		})
		assert.NoError(t, err)

		if key.GetName() != "AES_KEY_OPENBAO_TEST_CREATE_KEY" {
			assert.NoError(t, errors.New(fmt.Sprintf("Key label is not correct. Want %s got %s", "AES_KEY_OPENBAO_TEST", key.GetName())))
		}

	})
	t.Run("Keystore: RemoveKey", func(t *testing.T) {
		ctx := t.Context()
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		key, err := keystore.GetKeyByName(ctx, "AES_KEY_OPENBAO_TEST_CREATE_KEY")
		assert.NoError(t, err)
		err = keystore.RemoveKey(ctx, key)
		assert.NoError(t, err)

	})
	t.Run("Keystore: ListKeys", func(t *testing.T) {
		ctx := t.Context()
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		keys, err := keystore.ListKeys(ctx)
		if err != nil {
			assert.NoError(t, err)
		}
		if len(keys) == 0 {
			assert.NoError(t, errors.New("no keys found"))
		}
	})
	t.Run("Keystore: GetKeyByName", func(t *testing.T) {
		ctx := t.Context()
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		key, err := keystore.GetKeyByName(ctx, AES_KEY_NAME)
		if err != nil {
			assert.NoError(t, err)
		}
		if key.GetName() != AES_KEY_NAME {
			assert.NoError(t, errors.New(fmt.Sprintf("Key label is not correct. Want %s got %s", AES_KEY_NAME, key.GetName())))
		}
		if key.GetType() != kms.KeyType_AES {
			assert.NoError(t, errors.New(fmt.Sprintf("Key type is not correct. Want %d got %d", kms.KeyType_AES, key.GetType())))
		}
		if key.GetLength() != 256 {
			assert.NoError(t, errors.New(fmt.Sprintf("Key size is not correct. Want %d got %d", 256, key.GetLength())))
		}
	})
	t.Run("Keystore: GetKeyById", func(t *testing.T) {
		ctx := t.Context()
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		key, err := keystore.GetKeyById(ctx, RSA_KEY_NAME)
		if err != nil {
			assert.NoError(t, err)
		}
		if key.GetName() != RSA_KEY_NAME {
			assert.NoError(t, errors.New(fmt.Sprintf("Key label is not correct. Want %s got %s", RSA_KEY_NAME, key.GetName())))
		}
		if key.GetType() != kms.KeyType_RSA_Private {
			assert.NoError(t, errors.New(fmt.Sprintf("Key type is not correct. Want %d got %d", kms.KeyType_RSA_Private, key.GetType())))
		}
		if key.GetLength() != 2048 {
			assert.NoError(t, errors.New(fmt.Sprintf("Key size is not correct. Want %d got %d", 2048, key.GetLength())))
		}
	})
	t.Run("Keystore: DeleteKey", func(t *testing.T) {
		//TODO: After create keu is ready
	})
	t.Run("Key: GetName", func(t *testing.T) {
		ctx := t.Context()
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		key1, err := keystore.GetKeyByName(ctx, AES_KEY_NAME)
		if err != nil {
			assert.NoError(t, err)
		}
		if key1.GetName() != AES_KEY_NAME {
			assert.NoError(t, errors.New(fmt.Sprintf("Key label is not correct. Want %s got %s", AES_KEY_NAME, key1.GetName())))
		}
		key2, err := keystore.GetKeyByName(ctx, RSA_KEY_NAME)
		if err != nil {
			assert.NoError(t, err)
		}
		if key1.GetName() != AES_KEY_NAME {
			assert.NoError(t, errors.New(fmt.Sprintf("Key label is not correct. Want %s got %s", RSA_KEY_NAME, key2.GetName())))
		}
	})
	t.Run("Key: GetType", func(t *testing.T) {
		ctx := t.Context()
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		key1, err := keystore.GetKeyByName(ctx, AES_KEY_NAME)
		if err != nil {
			assert.NoError(t, err)
		}
		if key1.GetType() != kms.KeyType_AES {
			assert.NoError(t, errors.New(fmt.Sprintf("Key type is not correct. Want %d got %d", kms.KeyType_AES, key1.GetType())))
		}
		key2, err := keystore.GetKeyByName(ctx, RSA_KEY_NAME)
		if err != nil {
			assert.NoError(t, err)
		}
		if key2.GetType() != kms.KeyType_RSA_Private {
			assert.NoError(t, errors.New(fmt.Sprintf("Key type is not correct. Want %d got %d", kms.KeyType_RSA_Private, key2.GetType())))
		}
	})
	t.Run("Key: GetLength", func(t *testing.T) {
		ctx := t.Context()
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		key1, err := keystore.GetKeyByName(ctx, AES_KEY_NAME)
		if err != nil {
			assert.NoError(t, err)
		}
		if key1.GetLength() != 256 {
			assert.NoError(t, errors.New(fmt.Sprintf("Key size is not correct. Want %d got %d", 256, key1.GetLength())))
		}
		key2, err := keystore.GetKeyByName(ctx, RSA_KEY_NAME)
		if err != nil {
			assert.NoError(t, err)
		}
		if key2.GetLength() != 2048 {
			assert.NoError(t, errors.New(fmt.Sprintf("Key size is not correct. Want %d got %d", 2048, key2.GetLength())))
		}
	})
	t.Run("Encrypt/Decrypt: Cipher_AES_GCM", func(t *testing.T) {
		ctx := t.Context()
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		aesKey, err := GenerateTestKeyAES(ctx, keystore)
		assert.NoError(t, err)
		ctx = WithSecretKey(ctx, aesKey)
		cipherEncrypt, err := CipherFactory{}.NewCipher(ctx, kms.CipherOp_Encrypt, &kms.CipherParameters{
			Algorithm: kms.CipherMode_AES_GCM,
		})
		assert.NoError(t, err)
		update, err := cipherEncrypt.Update(ctx, []byte("te"))
		if update == nil {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
		}
		if string(update) != "te" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
		}
		assert.NoError(t, err)
		encryptedPayload, err := cipherEncrypt.Close(ctx, []byte("st"))
		assert.NoError(t, err)

		decryptCipher, err := CipherFactory{}.NewCipher(ctx, kms.CipherOp_Decrypt, &kms.CipherParameters{
			Algorithm: kms.CipherMode_AES_GCM,
		})
		payload, err := decryptCipher.Close(ctx, encryptedPayload)
		assert.NoError(t, err)
		if string(payload) != "test" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
		}
		err = RemoveKey(ctx, aesKey, keystore)
		assert.NoError(t, err)

	})
	//t.Run("Encrypt/Decrypt: Cipher_AES_ECB", func(t *testing.T) { ctx := t.Context()
	//	keystore, err := NewKeyStore(provider)
	//	assert.NoError(t, err)
	//	aesKey, err := GenerateTestKeyAES(keystore)
	//	assert.NoError(t, err)
	//	cipherEncrypt, err := NewCipher(kms.Encrypt, aesKey, &kms.CipherParameters{
	//		Algorithm: kms.Cipher_AES_ECB,
	//	})
	//	assert.NoError(t, err)
	//	update, err := cipherEncrypt.Update([]byte("te"))
	//	if update == nil {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
	//	}
	//	if string(update) != "te" {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
	//	}
	//	assert.NoError(t, err)
	//	encryptedPayload, iv, mac, err := cipherEncrypt.Close([]byte("st"))
	//	assert.NoError(t, err)
	//
	//	decryptCipher, err := NewCipher(kms.Decrypt, aesKey, &kms.CipherParameters{
	//		Algorithm: kms.Cipher_AES_ECB,
	//		IV:        iv,
	//		MAC:       mac,
	//	})
	//	payload, _, _, err := decryptCipher.Close(encryptedPayload)
	//	assert.NoError(t, err)
	//	if string(payload) != "test" {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
	//	}
	//	err = RemoveKey(aesKey, keystore)
	//	assert.NoError(t, err)
	//
	//})
	//t.Run("Encrypt/Decrypt: Cipher_AES_CTR", func(t *testing.T) { ctx := t.Context()
	//	keystore, err := NewKeyStore(provider)
	//	assert.NoError(t, err)
	//	aesKey, err := GenerateTestKeyAES(keystore)
	//	assert.NoError(t, err)
	//	cipherEncrypt, err := NewCipher(kms.Encrypt, aesKey, &kms.CipherParameters{
	//		Algorithm: kms.Cipher_AES_CTR,
	//	})
	//	assert.NoError(t, err)
	//	update, err := cipherEncrypt.Update([]byte("te"))
	//	if update == nil {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
	//	}
	//	if string(update) != "te" {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
	//	}
	//	assert.NoError(t, err)
	//	encryptedPayload, iv, mac, err := cipherEncrypt.Close([]byte("st"))
	//	assert.NoError(t, err)
	//
	//	decryptCipher, err := NewCipher(kms.Decrypt, aesKey, &kms.CipherParameters{
	//		Algorithm: kms.Cipher_AES_CTR,
	//		IV:        iv,
	//		MAC:       mac,
	//	})
	//	payload, _, _, err := decryptCipher.Close(encryptedPayload)
	//	assert.NoError(t, err)
	//	if string(payload) != "test" {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
	//	}
	//	err = RemoveKey(aesKey, keystore)
	//	assert.NoError(t, err)
	//
	//})
	//t.Run("Encrypt/Decrypt: Cipher_AES_CBC", func(t *testing.T) { ctx := t.Context()
	//	keystore, err := NewKeyStore(provider)
	//	assert.NoError(t, err)
	//	aesKey, err := GenerateTestKeyAES(keystore)
	//	assert.NoError(t, err)
	//	cipherEncrypt, err := NewCipher(kms.Encrypt, aesKey, &kms.CipherParameters{
	//		Algorithm: kms.Cipher_AES_CBC,
	//	})
	//	assert.NoError(t, err)
	//	update, err := cipherEncrypt.Update([]byte("te"))
	//	if update == nil {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
	//	}
	//	if string(update) != "te" {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
	//	}
	//	assert.NoError(t, err)
	//	encryptedPayload, iv, mac, err := cipherEncrypt.Close([]byte("st"))
	//	assert.NoError(t, err)
	//
	//	decryptCipher, err := NewCipher(kms.Decrypt, aesKey, &kms.CipherParameters{
	//		Algorithm: kms.Cipher_AES_CBC,
	//		IV:        iv,
	//		MAC:       mac,
	//	})
	//	payload, _, _, err := decryptCipher.Close(encryptedPayload)
	//	assert.NoError(t, err)
	//	if string(payload) != "test" {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
	//	}
	//	err = RemoveKey(aesKey, keystore)
	//	assert.NoError(t, err)
	//
	//})
	//t.Run("Encrypt/Decrypt: Cipher_RSA_MODE", func(t *testing.T) { ctx := t.Context()
	//	keystore, err := NewKeyStore(provider)
	//	assert.NoError(t, err)
	//	rsaKey, err := GenerateTestKeyRSA(keystore)
	//	assert.NoError(t, err)
	//	cipherEncrypt, err := NewCipher(kms.Encrypt, rsaKey, &kms.CipherParameters{
	//		Algorithm: kms.Cipher_RSA_MODE,
	//	})
	//	assert.NoError(t, err)
	//	update, err := cipherEncrypt.Update([]byte("te"))
	//	if update == nil {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
	//	}
	//	if string(update) != "te" {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
	//	}
	//	assert.NoError(t, err)
	//	encryptedPayload, iv, mac, err := cipherEncrypt.Close([]byte("st"))
	//	assert.NoError(t, err)
	//
	//	decryptCipher, err := NewCipher(kms.Decrypt, rsaKey, &kms.CipherParameters{
	//		Algorithm: kms.Cipher_RSA_MODE,
	//		IV:        iv,
	//		MAC:       mac,
	//	})
	//	payload, _, _, err := decryptCipher.Close(encryptedPayload)
	//	assert.NoError(t, err)
	//	if string(payload) != "test" {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
	//	}
	//	err = RemoveKey(rsaKey, keystore)
	//	assert.NoError(t, err)
	//
	//})
	//t.Run("Encrypt/Decrypt: Cipher_RSA_PADDING_OAEP", func(t *testing.T) { ctx := t.Context()
	//	keystore, err := NewKeyStore(provider)
	//	assert.NoError(t, err)
	//	rsaKey, err := GenerateTestKeyRSA(keystore)
	//	assert.NoError(t, err)
	//	cipherEncrypt, err := NewCipher(kms.Encrypt, rsaKey, &kms.CipherParameters{
	//		Algorithm: kms.Cipher_RSA_PADDING_OAEP,
	//	})
	//	assert.NoError(t, err)
	//	update, err := cipherEncrypt.Update([]byte("te"))
	//	if update == nil {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
	//	}
	//	if string(update) != "te" {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
	//	}
	//	assert.NoError(t, err)
	//	encryptedPayload, iv, mac, err := cipherEncrypt.Close([]byte("st"))
	//	assert.NoError(t, err)
	//
	//	decryptCipher, err := NewCipher(kms.Decrypt, rsaKey, &kms.CipherParameters{
	//		Algorithm: kms.Cipher_RSA_PADDING_OAEP,
	//		IV:        iv,
	//		MAC:       mac,
	//	})
	//	payload, _, _, err := decryptCipher.Close(encryptedPayload)
	//	assert.NoError(t, err)
	//	if string(payload) != "test" {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
	//	}
	//	err = RemoveKey(rsaKey, keystore)
	//	assert.NoError(t, err)
	//
	//})
	//t.Run("Encrypt/Decrypt: Cipher_RSA_PADDING_OAEP_SHA1", func(t *testing.T) { ctx := t.Context()
	//	keystore, err := NewKeyStore(provider)
	//	assert.NoError(t, err)
	//	rsaKey, err := GenerateTestKeyRSA(keystore)
	//	assert.NoError(t, err)
	//	cipherEncrypt, err := NewCipher(kms.Encrypt, rsaKey, &kms.CipherParameters{
	//		Algorithm: kms.Cipher_RSA_PADDING_OAEP_SHA1,
	//	})
	//	assert.NoError(t, err)
	//	update, err := cipherEncrypt.Update([]byte("te"))
	//	if update == nil {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
	//	}
	//	if string(update) != "te" {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
	//	}
	//	assert.NoError(t, err)
	//	encryptedPayload, iv, mac, err := cipherEncrypt.Close([]byte("st"))
	//	assert.NoError(t, err)
	//
	//	decryptCipher, err := NewCipher(kms.Decrypt, rsaKey, &kms.CipherParameters{
	//		Algorithm: kms.Cipher_RSA_PADDING_OAEP_SHA1,
	//		IV:        iv,
	//		MAC:       mac,
	//	})
	//	payload, _, _, err := decryptCipher.Close(encryptedPayload)
	//	assert.NoError(t, err)
	//	if string(payload) != "test" {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
	//	}
	//	err = RemoveKey(rsaKey, keystore)
	//	assert.NoError(t, err)
	//
	//})
	//t.Run("Encrypt/Decrypt: Cipher_RSA_PADDING_OAEP_SHA224", func(t *testing.T) { ctx := t.Context()
	//	keystore, err := NewKeyStore(provider)
	//	assert.NoError(t, err)
	//	rsaKey, err := GenerateTestKeyRSA(keystore)
	//	assert.NoError(t, err)
	//	cipherEncrypt, err := NewCipher(kms.Encrypt, rsaKey, &kms.CipherParameters{
	//		Algorithm: kms.Cipher_RSA_PADDING_OAEP_SHA224,
	//	})
	//	assert.NoError(t, err)
	//	update, err := cipherEncrypt.Update([]byte("te"))
	//	if update == nil {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
	//	}
	//	if string(update) != "te" {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
	//	}
	//	assert.NoError(t, err)
	//	encryptedPayload, iv, mac, err := cipherEncrypt.Close([]byte("st"))
	//	assert.NoError(t, err)
	//
	//	decryptCipher, err := NewCipher(kms.Decrypt, rsaKey, &kms.CipherParameters{
	//		Algorithm: kms.Cipher_RSA_PADDING_OAEP_SHA224,
	//		IV:        iv,
	//		MAC:       mac,
	//	})
	//	payload, _, _, err := decryptCipher.Close(encryptedPayload)
	//	assert.NoError(t, err)
	//	if string(payload) != "test" {
	//		assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
	//	}
	//	err = RemoveKey(rsaKey, keystore)
	//	assert.NoError(t, err)
	//
	//})
	t.Run("Encrypt/Decrypt: Cipher_RSA_PADDING_OAEP_SHA256", func(t *testing.T) {
		ctx := t.Context()
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(ctx, keystore)
		assert.NoError(t, err)
		ctx = WithPrivateKey(ctx, rsaKey)

		cipherEncrypt, err := CipherFactory{}.NewCipher(ctx, kms.CipherOp_Encrypt, &kms.CipherParameters{
			Algorithm: kms.CipherMode_RSA_OAEP_SHA256,
		})
		assert.NoError(t, err)
		update, err := cipherEncrypt.Update(ctx, []byte("te"))
		if update == nil {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
		}
		if string(update) != "te" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
		}
		assert.NoError(t, err)
		encryptedPayload, err := cipherEncrypt.Close(ctx, []byte("st"))
		assert.NoError(t, err)

		decryptCipher, err := CipherFactory{}.NewCipher(ctx, kms.CipherOp_Decrypt, &kms.CipherParameters{
			Algorithm: kms.CipherMode_RSA_OAEP_SHA256,
		})
		payload, err := decryptCipher.Close(ctx, encryptedPayload)
		assert.NoError(t, err)
		if string(payload) != "test" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
		}
		err = RemoveKey(ctx, rsaKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Encrypt/Decrypt: Cipher_RSA_PADDING_OAEP_SHA384", func(t *testing.T) {
		ctx := t.Context()
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(ctx, keystore)
		assert.NoError(t, err)
		ctx = WithPrivateKey(ctx, rsaKey)

		cipherEncrypt, err := CipherFactory{}.NewCipher(ctx, kms.CipherOp_Encrypt, &kms.CipherParameters{
			Algorithm: kms.CipherMode_RSA_OAEP_SHA384,
		})
		assert.NoError(t, err)
		update, err := cipherEncrypt.Update(ctx, []byte("te"))
		if update == nil {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
		}
		if string(update) != "te" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
		}
		assert.NoError(t, err)
		encryptedPayload, err := cipherEncrypt.Close(ctx, []byte("st"))
		assert.NoError(t, err)

		decryptCipher, err := CipherFactory{}.NewCipher(ctx, kms.CipherOp_Decrypt, &kms.CipherParameters{
			Algorithm: kms.CipherMode_RSA_OAEP_SHA384,
		})
		payload, err := decryptCipher.Close(ctx, encryptedPayload)
		assert.NoError(t, err)
		if string(payload) != "test" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
		}
		err = RemoveKey(ctx, rsaKey, keystore)
		assert.NoError(t, err)
	})
	t.Run("Encrypt/Decrypt: Cipher_RSA_PADDING_OAEP_SHA512", func(t *testing.T) {
		ctx := t.Context()
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(ctx, keystore)
		assert.NoError(t, err)
		ctx = WithPrivateKey(ctx, rsaKey)

		cipherEncrypt, err := CipherFactory{}.NewCipher(ctx, kms.CipherOp_Encrypt, &kms.CipherParameters{
			Algorithm: kms.CipherMode_RSA_OAEP_SHA512,
		})
		assert.NoError(t, err)
		update, err := cipherEncrypt.Update(ctx, []byte("te"))
		if update == nil {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is nil. Want %s", "te")))
		}
		if string(update) != "te" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher encrypt update is %s. Want %s", string(update), "te")))
		}
		assert.NoError(t, err)
		encryptedPayload, err := cipherEncrypt.Close(ctx, []byte("st"))
		assert.NoError(t, err)

		decryptCipher, err := CipherFactory{}.NewCipher(ctx, kms.CipherOp_Decrypt, &kms.CipherParameters{
			Algorithm: kms.CipherMode_RSA_OAEP_SHA512,
		})
		payload, err := decryptCipher.Close(ctx, encryptedPayload)
		assert.NoError(t, err)
		if string(payload) != "test" {
			assert.NoError(t, errors.New(fmt.Sprintf("cipher decrypted payload is %s. Want %s", string(payload), "test")))
		}
		err = RemoveKey(ctx, rsaKey, keystore)
		assert.NoError(t, err)

	})
	//t.Run("Sign/Verify: Sign_SHA224_RSA_PKCS1_PSS", func(t *testing.T) {
	//	ctx := t.Context()
	//	keystore, err := NewKeyStore(provider)
	//	assert.NoError(t, err)
	//	rsaKey, err := GenerateTestKeyRSA(keystore)
	//	assert.NoError(t, err)
	//	signer, err := NewSigner(rsaKey, &kms.SignerParameters{
	//		Algorithm: kms.Sign_SHA224_RSA_PKCS1_PSS,
	//	})
	//	assert.NoError(t, err)
	//	err = signer.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	signature, err := signer.Close([]byte("st"))
	//	assert.NoError(t, err)
	//
	//	verifier, err := NewVerifier(rsaKey, &kms.VerifierParameters{
	//		Algorithm: kms.Sign_SHA224_RSA_PKCS1_PSS,
	//		Signature: signature,
	//	})
	//	err = verifier.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	err = verifier.Close([]byte("st"))
	//	assert.NoError(t, err)
	//	err = verifier.CloseEx([]byte("test"), signature)
	//	assert.NoError(t, err)
	//	err = RemoveKey(rsaKey, keystore)
	//	assert.NoError(t, err)
	//
	//})
	//t.Run("Sign/Verify: Sign_SHA256_RSA_PKCS1_PSS", func(t *testing.T) {
	//	ctx := t.Context()
	//	keystore, err := NewKeyStore(provider)
	//	assert.NoError(t, err)
	//	rsaKey, err := GenerateTestKeyRSA(keystore)
	//	assert.NoError(t, err)
	//	signer, err := NewSigner(rsaKey, &kms.SignerParameters{
	//		Algorithm: kms.Sign_SHA256_RSA_PKCS1_PSS,
	//	})
	//	assert.NoError(t, err)
	//	err = signer.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	signature, err := signer.Close([]byte("st"))
	//	assert.NoError(t, err)
	//
	//	verifier, err := NewVerifier(rsaKey, &kms.VerifierParameters{
	//		Algorithm: kms.Sign_SHA256_RSA_PKCS1_PSS,
	//		Signature: signature,
	//	})
	//	err = verifier.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	err = verifier.Close([]byte("st"))
	//	assert.NoError(t, err)
	//	err = verifier.CloseEx([]byte("test"), signature)
	//	assert.NoError(t, err)
	//	err = RemoveKey(rsaKey, keystore)
	//	assert.NoError(t, err)
	//
	//})
	//t.Run("Sign/Verify: Sign_SHA384_RSA_PKCS1_PSS", func(t *testing.T) {
	//	ctx := t.Context()
	//	keystore, err := NewKeyStore(provider)
	//	assert.NoError(t, err)
	//	rsaKey, err := GenerateTestKeyRSA(keystore)
	//	assert.NoError(t, err)
	//	signer, err := NewSigner(rsaKey, &kms.SignerParameters{
	//		Algorithm: kms.Sign_SHA384_RSA_PKCS1_PSS,
	//	})
	//	assert.NoError(t, err)
	//	err = signer.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	signature, err := signer.Close([]byte("st"))
	//	assert.NoError(t, err)
	//
	//	verifier, err := NewVerifier(rsaKey, &kms.VerifierParameters{
	//		Algorithm: kms.Sign_SHA384_RSA_PKCS1_PSS,
	//		Signature: signature,
	//	})
	//	err = verifier.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	err = verifier.Close([]byte("st"))
	//	assert.NoError(t, err)
	//	err = verifier.CloseEx([]byte("test"), signature)
	//	assert.NoError(t, err)
	//	err = RemoveKey(rsaKey, keystore)
	//	assert.NoError(t, err)
	//
	//})
	//t.Run("Sign/Verify: Sign_SHA512_RSA_PKCS1_PSS", func(t *testing.T) {
	//	ctx := t.Context()
	//	keystore, err := NewKeyStore(provider)
	//	assert.NoError(t, err)
	//	rsaKey, err := GenerateTestKeyRSA(keystore)
	//	assert.NoError(t, err)
	//	signer, err := NewSigner(rsaKey, &kms.SignerParameters{
	//		Algorithm: kms.Sign_SHA512_RSA_PKCS1_PSS,
	//	})
	//	assert.NoError(t, err)
	//	err = signer.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	signature, err := signer.Close([]byte("st"))
	//	assert.NoError(t, err)
	//
	//	verifier, err := NewVerifier(rsaKey, &kms.VerifierParameters{
	//		Algorithm: kms.Sign_SHA512_RSA_PKCS1_PSS,
	//		Signature: signature,
	//	})
	//	err = verifier.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	err = verifier.Close([]byte("st"))
	//	assert.NoError(t, err)
	//	err = verifier.CloseEx([]byte("test"), signature)
	//	assert.NoError(t, err)
	//	err = RemoveKey(rsaKey, keystore)
	//	assert.NoError(t, err)
	//
	//})
	//t.Run("Sign/Verify: Sign_SHA224_RSA", func(t *testing.T) {
	//	ctx := t.Context()
	//	keystore, err := NewKeyStore(provider)
	//	assert.NoError(t, err)
	//	rsaKey, err := GenerateTestKeyRSA(keystore)
	//	assert.NoError(t, err)
	//	signer, err := NewSigner(rsaKey, &kms.SignerParameters{
	//		Algorithm: kms.Sign_SHA224_RSA,
	//	})
	//	assert.NoError(t, err)
	//	err = signer.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	signature, err := signer.Close([]byte("st"))
	//	assert.NoError(t, err)
	//
	//	verifier, err := NewVerifier(rsaKey, &kms.VerifierParameters{
	//		Algorithm: kms.Sign_SHA224_RSA,
	//		Signature: signature,
	//	})
	//	err = verifier.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	err = verifier.Close([]byte("st"))
	//	assert.NoError(t, err)
	//	err = verifier.CloseEx([]byte("test"), signature)
	//	assert.NoError(t, err)
	//	err = RemoveKey(rsaKey, keystore)
	//	assert.NoError(t, err)
	//
	//})
	t.Run("Sign/Verify: Sign_SHA256_RSA", func(t *testing.T) {
		ctx := t.Context()
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(ctx, keystore)
		assert.NoError(t, err)
		ctx = WithPrivateKey(ctx, rsaKey)
		signer, err := SignerFactory{}.NewSigner(ctx, &kms.SignerParameters{
			Algorithm: kms.SignAlgo_RSA_PKCS1_PSS_SHA_256,
		})
		assert.NoError(t, err)
		err = signer.Update(ctx, []byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close(ctx, []byte("st"))
		assert.NoError(t, err)

		verifier, err := VerifierFactory{}.NewVerifier(ctx, &kms.VerifierParameters{
			Algorithm: kms.SignAlgo_RSA_PKCS1_PSS_SHA_256,
			Signature: signature,
		})
		err = verifier.Update(ctx, []byte("te"))
		assert.NoError(t, err)
		err = verifier.Close(ctx, []byte("st"), nil)
		assert.NoError(t, err)
		err = verifier.Close(ctx, []byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(ctx, rsaKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Sign_SHA384_RSA", func(t *testing.T) {
		ctx := t.Context()
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(ctx, keystore)
		assert.NoError(t, err)
		ctx = WithPrivateKey(ctx, rsaKey)
		signer, err := SignerFactory{}.NewSigner(ctx, &kms.SignerParameters{
			Algorithm: kms.SignAlgo_RSA_PKCS1_PSS_SHA_384,
		})
		assert.NoError(t, err)
		err = signer.Update(ctx, []byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close(ctx, []byte("st"))
		assert.NoError(t, err)

		verifier, err := VerifierFactory{}.NewVerifier(ctx, &kms.VerifierParameters{
			Algorithm: kms.SignAlgo_RSA_PKCS1_PSS_SHA_384,
			Signature: signature,
		})
		err = verifier.Update(ctx, []byte("te"))
		assert.NoError(t, err)
		err = verifier.Close(ctx, []byte("st"), nil)
		assert.NoError(t, err)
		err = verifier.Close(ctx, []byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(ctx, rsaKey, keystore)
		assert.NoError(t, err)
	})
	t.Run("Sign/Verify: Sign_SHA512_RSA", func(t *testing.T) {
		ctx := t.Context()
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		rsaKey, err := GenerateTestKeyRSA(ctx, keystore)
		assert.NoError(t, err)
		ctx = WithPrivateKey(ctx, rsaKey)
		signer, err := SignerFactory{}.NewSigner(ctx, &kms.SignerParameters{
			Algorithm: kms.SignAlgo_RSA_PKCS1_PSS_SHA_512,
		})
		assert.NoError(t, err)
		err = signer.Update(ctx, []byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close(ctx, []byte("st"))
		assert.NoError(t, err)

		verifier, err := VerifierFactory{}.NewVerifier(ctx, &kms.VerifierParameters{
			Algorithm: kms.SignAlgo_RSA_PKCS1_PSS_SHA_512,
			Signature: signature,
		})
		err = verifier.Update(ctx, []byte("te"))
		assert.NoError(t, err)
		err = verifier.Close(ctx, []byte("st"), nil)
		assert.NoError(t, err)
		err = verifier.Close(ctx, []byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(ctx, rsaKey, keystore)
		assert.NoError(t, err)

	})
	//t.Run("Sign/Verify: Sign_SHA1_ECDSA", func(t *testing.T) {
	//	ctx := t.Context()
	//	keystore, err := NewKeyStore(provider)
	//	assert.NoError(t, err)
	//	ecKey, err := GenerateTestKeyEC(keystore)
	//	assert.NoError(t, err)
	//	signer, err := NewSigner(ecKey, &kms.SignerParameters{
	//		Algorithm: kms.Sign_SHA1_ECDSA,
	//	})
	//	assert.NoError(t, err)
	//	err = signer.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	signature, err := signer.Close([]byte("st"))
	//	assert.NoError(t, err)
	//
	//	verifier, err := NewVerifier(ecKey, &kms.VerifierParameters{
	//		Algorithm: kms.Sign_SHA1_ECDSA,
	//		Signature: signature,
	//	})
	//	err = verifier.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	err = verifier.Close([]byte("st"))
	//	assert.NoError(t, err)
	//	err = verifier.CloseEx([]byte("test"), signature)
	//	assert.NoError(t, err)
	//	err = RemoveKey(ecKey, keystore)
	//	assert.NoError(t, err)
	//
	//})
	//t.Run("Sign/Verify: Sign_SHA224_ECDSA", func(t *testing.T) {
	//	ctx := t.Context()
	//	keystore, err := NewKeyStore(provider)
	//	assert.NoError(t, err)
	//	ecKey, err := GenerateTestKeyEC(keystore)
	//	assert.NoError(t, err)
	//	signer, err := NewSigner(ecKey, &kms.SignerParameters{
	//		Algorithm: kms.Sign_SHA224_ECDSA,
	//	})
	//	assert.NoError(t, err)
	//	err = signer.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	signature, err := signer.Close([]byte("st"))
	//	assert.NoError(t, err)
	//
	//	verifier, err := NewVerifier(ecKey, &kms.VerifierParameters{
	//		Algorithm: kms.Sign_SHA224_ECDSA,
	//		Signature: signature,
	//	})
	//	err = verifier.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	err = verifier.Close([]byte("st"))
	//	assert.NoError(t, err)
	//	err = verifier.CloseEx([]byte("test"), signature)
	//	assert.NoError(t, err)
	//	err = RemoveKey(ecKey, keystore)
	//	assert.NoError(t, err)
	//
	//})
	t.Run("Sign/Verify: Sign_SHA256_ECDSA", func(t *testing.T) {
		ctx := t.Context()
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		ecKey, err := GenerateTestKeyEC(ctx, kms.Curve_P256, keystore)
		assert.NoError(t, err)
		ctx = WithPrivateKey(ctx, ecKey)
		signer, err := SignerFactory{}.NewSigner(ctx, &kms.SignerParameters{
			Algorithm: kms.SignAlgo_EC_P256,
		})
		assert.NoError(t, err)
		err = signer.Update(ctx, []byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close(ctx, []byte("st"))
		assert.NoError(t, err)

		verifier, err := VerifierFactory{}.NewVerifier(ctx, &kms.VerifierParameters{
			Algorithm: kms.SignAlgo_EC_P256,
			Signature: signature,
		})
		err = verifier.Update(ctx, []byte("te"))
		assert.NoError(t, err)
		err = verifier.Close(ctx, []byte("st"), nil)
		assert.NoError(t, err)
		err = verifier.Close(ctx, []byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(ctx, ecKey, keystore)
		assert.NoError(t, err)
	})
	t.Run("Sign/Verify: Sign_SHA384_ECDSA", func(t *testing.T) {
		ctx := t.Context()
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		ecKey, err := GenerateTestKeyEC(ctx, kms.Curve_P384, keystore)
		assert.NoError(t, err)
		ctx = WithPrivateKey(ctx, ecKey)
		signer, err := SignerFactory{}.NewSigner(ctx, &kms.SignerParameters{
			Algorithm: kms.SignAlgo_EC_P384,
		})
		assert.NoError(t, err)
		err = signer.Update(ctx, []byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close(ctx, []byte("st"))
		assert.NoError(t, err)

		verifier, err := VerifierFactory{}.NewVerifier(ctx, &kms.VerifierParameters{
			Algorithm: kms.SignAlgo_EC_P384,
			Signature: signature,
		})
		err = verifier.Update(ctx, []byte("te"))
		assert.NoError(t, err)
		err = verifier.Close(ctx, []byte("st"), nil)
		assert.NoError(t, err)
		err = verifier.Close(ctx, []byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(ctx, ecKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Sign_SHA512_ECDSA", func(t *testing.T) {
		ctx := t.Context()
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		ecKey, err := GenerateTestKeyEC(ctx, kms.Curve_P521, keystore)
		assert.NoError(t, err)
		ctx = WithPrivateKey(ctx, ecKey)
		signer, err := SignerFactory{}.NewSigner(ctx, &kms.SignerParameters{
			Algorithm: kms.SignAlgo_EC_P521,
		})
		assert.NoError(t, err)
		err = signer.Update(ctx, []byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close(ctx, []byte("st"))
		assert.NoError(t, err)

		verifier, err := VerifierFactory{}.NewVerifier(ctx, &kms.VerifierParameters{
			Algorithm: kms.SignAlgo_EC_P521,
			Signature: signature,
		})
		err = verifier.Update(ctx, []byte("te"))
		assert.NoError(t, err)
		err = verifier.Close(ctx, []byte("st"), nil)
		assert.NoError(t, err)
		err = verifier.Close(ctx, []byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(ctx, ecKey, keystore)
		assert.NoError(t, err)

	})
	t.Run("Sign/Verify: Ed25519", func(t *testing.T) {
		ctx := t.Context()
		keystore, err := NewKeyStore(provider)
		assert.NoError(t, err)
		edKey, err := GenerateTestKeyED(ctx, keystore)
		assert.NoError(t, err)
		ctx = WithPrivateKey(ctx, edKey)
		signer, err := SignerFactory{}.NewSigner(ctx, &kms.SignerParameters{
			Algorithm: kms.SignAlgo_ED,
		})
		assert.NoError(t, err)
		err = signer.Update(ctx, []byte("te"))
		assert.NoError(t, err)
		signature, err := signer.Close(ctx, []byte("st"))
		assert.NoError(t, err)

		verifier, err := VerifierFactory{}.NewVerifier(ctx, &kms.VerifierParameters{
			Algorithm: kms.SignAlgo_ED,
			Signature: signature,
		})
		err = verifier.Update(ctx, []byte("te"))
		assert.NoError(t, err)
		err = verifier.Close(ctx, []byte("st"), nil)
		assert.NoError(t, err)
		err = verifier.Close(ctx, []byte("test"), signature)
		assert.NoError(t, err)
		err = RemoveKey(ctx, edKey, keystore)
		assert.NoError(t, err)

	})

	//t.Run("Sign/Verify: Sign_SHA3224_ECDSA", func(t *testing.T) {
	//	ctx := t.Context()
	//	keystore, err := NewKeyStore(provider)
	//	assert.NoError(t, err)
	//	ecKey, err := GenerateTestKeyEC(keystore)
	//	assert.NoError(t, err)
	//	signer, err := NewSigner(ecKey, &kms.SignerParameters{
	//		Algorithm: kms.Sign_SHA3224_ECDSA,
	//	})
	//	assert.NoError(t, err)
	//	err = signer.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	signature, err := signer.Close([]byte("st"))
	//	assert.NoError(t, err)
	//
	//	verifier, err := NewVerifier(ecKey, &kms.VerifierParameters{
	//		Algorithm: kms.Sign_SHA3224_ECDSA,
	//		Signature: signature,
	//	})
	//	err = verifier.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	err = verifier.Close([]byte("st"))
	//	assert.NoError(t, err)
	//	err = verifier.CloseEx([]byte("test"), signature)
	//	assert.NoError(t, err)
	//	err = RemoveKey(ecKey, keystore)
	//	assert.NoError(t, err)
	//
	//})
	//t.Run("Sign/Verify: Sign_SHA3256_ECDSA", func(t *testing.T) {
	//	ctx := t.Context()
	//	keystore, err := NewKeyStore(provider)
	//	assert.NoError(t, err)
	//	ecKey, err := GenerateTestKeyEC(keystore)
	//	assert.NoError(t, err)
	//	signer, err := NewSigner(ecKey, &kms.SignerParameters{
	//		Algorithm: kms.Sign_SHA3256_ECDSA,
	//	})
	//	assert.NoError(t, err)
	//	err = signer.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	signature, err := signer.Close([]byte("st"))
	//	assert.NoError(t, err)
	//
	//	verifier, err := NewVerifier(ecKey, &kms.VerifierParameters{
	//		Algorithm: kms.Sign_SHA3256_ECDSA,
	//		Signature: signature,
	//	})
	//	err = verifier.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	err = verifier.Close([]byte("st"))
	//	assert.NoError(t, err)
	//	err = verifier.CloseEx([]byte("test"), signature)
	//	assert.NoError(t, err)
	//	err = RemoveKey(ecKey, keystore)
	//	assert.NoError(t, err)
	//
	//})
	//t.Run("Sign/Verify: Sign_SHA3384_ECDSA", func(t *testing.T) {
	//	ctx := t.Context()
	//	keystore, err := NewKeyStore(provider)
	//	assert.NoError(t, err)
	//	ecKey, err := GenerateTestKeyEC(keystore)
	//	assert.NoError(t, err)
	//	signer, err := NewSigner(ecKey, &kms.SignerParameters{
	//		Algorithm: kms.Sign_SHA3384_ECDSA,
	//	})
	//	assert.NoError(t, err)
	//	err = signer.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	signature, err := signer.Close([]byte("st"))
	//	assert.NoError(t, err)
	//
	//	verifier, err := NewVerifier(ecKey, &kms.VerifierParameters{
	//		Algorithm: kms.Sign_SHA3384_ECDSA,
	//		Signature: signature,
	//	})
	//	err = verifier.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	err = verifier.Close([]byte("st"))
	//	assert.NoError(t, err)
	//	err = verifier.CloseEx([]byte("test"), signature)
	//	assert.NoError(t, err)
	//	err = RemoveKey(ecKey, keystore)
	//	assert.NoError(t, err)
	//
	//})
	//t.Run("Sign/Verify: Sign_SHA3512_ECDSA", func(t *testing.T) {
	//	ctx := t.Context()
	//	keystore, err := NewKeyStore(provider)
	//	assert.NoError(t, err)
	//	ecKey, err := GenerateTestKeyEC(keystore)
	//	assert.NoError(t, err)
	//	signer, err := NewSigner(ecKey, &kms.SignerParameters{
	//		Algorithm: kms.Sign_SHA3512_ECDSA,
	//	})
	//	assert.NoError(t, err)
	//	err = signer.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	signature, err := signer.Close([]byte("st"))
	//	assert.NoError(t, err)
	//
	//	verifier, err := NewVerifier(ecKey, &kms.VerifierParameters{
	//		Algorithm: kms.Sign_SHA3512_ECDSA,
	//		Signature: signature,
	//	})
	//	err = verifier.Update([]byte("te"))
	//	assert.NoError(t, err)
	//	err = verifier.Close([]byte("st"))
	//	assert.NoError(t, err)
	//	err = verifier.CloseEx([]byte("test"), signature)
	//	assert.NoError(t, err)
	//	err = RemoveKey(ecKey, keystore)
	//	assert.NoError(t, err)
	//
	//})
}
