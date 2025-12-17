// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package securosyshsm

import (
	"context"
	b64 "encoding/base64"
	"errors"
	"time"

	//"github.com/andreburgaud/crypt2go/padding"
	"github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/helpers"
	kms "github.com/openbao/go-kms-wrapping/v2/kms"
)

// Ensure KeyStoreFactory implements KeyStoreFactory
var _ kms.CipherFactory = (*CipherFactory)(nil)

// Ensure KeyStore implements KeyStore
var _ kms.Cipher = (*Cipher)(nil)

// Constants for cipher operations
const (
	AES_GCM_MAC_BIT_LEN = 128 // 128 bits
)

type CipherFactory struct {
}

//	type cipher struct {
//		operation kms.CipherOperation
//		//privateKey   *PrivateKey
//		//secretKey    *SecretKey
//		cipherParams *kms.CipherParameters
//		buffer       []byte
//	}
type Cipher struct {
	operation    kms.CipherOperation
	key          *key
	cipherParams *kms.CipherParameters
	buffer       []byte
}

func (c *Cipher) Update(ctx context.Context, input []byte) (output []byte, err error) {
	// Check for context cancellation before doing work
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	// This emulates multi-part ciphering, since the actual encryption/decryption operations are performed remotely (KMS server-side).
	// So we just buffer the input until Close() is called.
	// TODO: we should fix a max buffer size since the caller could call this for very large data.
	c.buffer = append(c.buffer, input...)
	return nil, nil // nothing processed yet
}

func (c *Cipher) Close(ctx context.Context, input []byte) (output []byte, err error) {
	// Check for context cancellation before doing work
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	c.buffer = append(c.buffer, input...)
	algorithm := c.cipherParams.Algorithm
	cipherAlgorithm, err := helpers.MapCipherAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	//Only Support AES encrypt/decrypt
	if c.operation == kms.CipherOp_Decrypt {
		payload, err := c.Decrypt(cipherAlgorithm)
		return c.RemovePaddingIfNeeded(payload), err
	} else {
		c.AddPaddingIfNeeded()
		return c.Encrypt(cipherAlgorithm)
	}

}

func (c *Cipher) DecryptAsyncRequest(additionalMetaData map[string]string) (string, error) {
	tagLength := 0
	encryptedPayload := c.buffer
	init_vector := ""
	aad := ""
	algorithm := c.cipherParams.Algorithm
	cipherAlgorithm, err := helpers.MapCipherAlgorithm(algorithm)
	if err != nil {
		return "", err
	}

	result, _, err := c.key.client.AsyncDecrypt(
		c.key.GetName(),
		c.key.password,
		b64.StdEncoding.EncodeToString(encryptedPayload),
		init_vector,
		cipherAlgorithm,
		tagLength,
		aad,
		additionalMetaData,
	)
	return result, err
}
func (c *Cipher) GetRequest(requestId string) (*helpers.RequestResponse, error) {
	request, _, err := c.key.client.GetRequest(requestId)
	return request, err
}

func (c *Cipher) Decrypt(cipherAlgorithm string) (outputData []byte, err error) {
	init_vector := ""
	aad := ""
	tagLength := -1
	encryptedPayload := c.buffer

	if c.cipherParams.Algorithm == kms.CipherMode_AES_GCM96 {
		tagLength = AES_GCM_MAC_BIT_LEN
		if algoParams, ok := c.cipherParams.Parameters.(*kms.AESGCMCipherParameters); ok && algoParams != nil {
			if len(algoParams.AAD) > 0 {
				aad = b64.StdEncoding.EncodeToString(algoParams.AAD)
			}

			if len((c.cipherParams.Parameters.(*kms.AESGCMCipherParameters)).Nonce) == 0 {
				return nil, errors.New("invalid cipher parameters for AES GCM decryption")
			}

			init_vector = b64.StdEncoding.EncodeToString(c.cipherParams.Parameters.(*kms.AESGCMCipherParameters).Nonce)

		} else {
			return nil, errors.New("invalid cipher parameters for AES GCM decryption")
		}

		response, _, err := c.key.client.Decrypt(
			c.key.GetName(),
			c.key.password,
			b64.StdEncoding.EncodeToString(encryptedPayload),
			init_vector,
			cipherAlgorithm,
			tagLength,
			aad,
		)
		if err != nil {
			return nil, errors.New("Decrypt failed to execute. Decrypt returned status: " + err.Error())

		}
		payload, _ := b64.StdEncoding.DecodeString(response.Payload)
		return payload, nil

	}

	// Endpoint for no AAD algos
	var result string
	result, _, _ = c.key.client.AsyncDecrypt(
		c.key.GetName(),
		c.key.password,
		b64.StdEncoding.EncodeToString(encryptedPayload),
		init_vector,
		cipherAlgorithm,
		tagLength,
		aad,
		make(map[string]string),
	)

	request, _, err := c.key.client.GetRequest(result)
	for request.Status == "PENDING" {
		if err != nil {
			c.buffer = nil
			return nil, err
		}
		time.Sleep(5 * time.Second)
		request, _, err = c.key.client.GetRequest(result)
	}
	if request.Status != "EXECUTED" {
		c.buffer = nil
		return nil, errors.New("Decrypt failed to execute. Decrypt returned status: " + request.Status)
	}
	c.buffer = nil
	payload, _ := b64.StdEncoding.DecodeString(request.Result)

	return payload, nil
}

func (c *Cipher) RemovePaddingIfNeeded(payload []byte) []byte {
	if c.key.GetType() == kms.KeyType_AES {
		//switch c.cipherParams.Algorithm {
		//case kms.Cipher_AES_ECB:
		//	padder := padding.NewPkcs7Padding(16)
		//	payload, _ := padder.Unpad(payload)
		//	return payload
		//case kms.Cipher_AES_CBC:
		//	//case kms.Cipher_AES_CTR:
		//	padder := padding.NewPkcs7Padding(16)
		//	payload, _ := padder.Unpad(payload)
		//	return payload
		//}

	}
	return payload

}
func (c *Cipher) AddPaddingIfNeeded() {
	if c.key.GetType() == kms.KeyType_AES {
		//switch c.cipherParams.Algorithm {
		//case kms.Cipher_AES_ECB:
		//	padder := padding.NewPkcs7Padding(16)
		//	c.buffer, _ = padder.Pad(c.buffer)
		//	break
		//case kms.Cipher_AES_CBC:
		//	//case kms.Cipher_AES_CTR:
		//	padder := padding.NewPkcs7Padding(16)
		//	c.buffer, _ = padder.Pad(c.buffer)
		//	break
		//}

	}

}
func (c *Cipher) Encrypt(cipherAlgorithm string) (outputData []byte, err error) {
	aad := ""
	tagLength := -1

	if c.cipherParams.Algorithm == kms.CipherMode_AES_GCM96 {
		tagLength = AES_GCM_MAC_BIT_LEN
		if c.cipherParams.Parameters == nil {
			c.cipherParams.Parameters = &kms.AESGCMCipherParameters{}
		} else if algoParams, ok := c.cipherParams.Parameters.(*kms.AESGCMCipherParameters); ok {
			if algoParams != nil {
				if len(algoParams.AAD) > 0 {
					aad = b64.StdEncoding.EncodeToString(algoParams.AAD)
				}
			} else {
				return nil, errors.New("invalid cipher parameters for AES GCM encryption")
			}

		} else {
			return nil, errors.New("invalid cipher parameters for AES GCM encryption")
		}
	}

	encrypt, _, err := c.key.client.Encrypt(
		c.key.GetName(),
		c.key.password,
		b64.StdEncoding.EncodeToString(c.buffer),
		cipherAlgorithm,
		tagLength,
		aad,
	)
	if err != nil {
		c.buffer = nil
		return nil, err
	}
	var encryptedPayload []byte
	if encrypt.EncryptedPayloadWithoutMessageAuthenticationCode == "" {
		encryptedPayload, _ = b64.StdEncoding.DecodeString(encrypt.EncryptedPayload)
	} else {
		encryptedPayload, _ = b64.StdEncoding.DecodeString(encrypt.EncryptedPayloadWithoutMessageAuthenticationCode)

	}

	var initializationVector []byte
	if encrypt.InitializationVector != nil {
		initializationVector, _ = b64.StdEncoding.DecodeString(*encrypt.InitializationVector)
	}
	var messageAuthenticationCode []byte

	if encrypt.MessageAuthenticationCode != nil {
		messageAuthenticationCode, _ = b64.StdEncoding.DecodeString(*encrypt.MessageAuthenticationCode)
	}
	c.buffer = nil

	// Return to the caller the generated  IV/Nonce + ciphertext + MAC (if any)
	switch algoParams := c.cipherParams.Parameters.(type) {
	case *kms.AESGCMCipherParameters:
		if algoParams != nil && len(initializationVector) > 0 {
			algoParams.Nonce = make([]byte, len(initializationVector))
			copy(algoParams.Nonce, initializationVector)
		}
	}

	return c.combineCipherOutput(encryptedPayload, messageAuthenticationCode), nil

}
func (c *Cipher) combineCipherOutput(encryptedPayload, messageAuthenticationCode []byte) []byte {
	if c.cipherParams.Algorithm == kms.CipherMode_AES_GCM96 {

		combined := make([]byte, 0, len(encryptedPayload)+len(messageAuthenticationCode))
		combined = append(combined, encryptedPayload...)
		combined = append(combined, messageAuthenticationCode...)

		return combined

	} else {
		out := make([]byte, len(encryptedPayload))
		copy(out, encryptedPayload)
		return out

	}
}

func (c CipherFactory) NewCipher(ctx context.Context, operation kms.CipherOperation, cipherParams *kms.CipherParameters) (kms.Cipher, error) {

	secretKey := SecretKeyFromContext(ctx)
	if secretKey != nil {
		return &Cipher{
			operation:    operation,
			key:          &secretKey.key,
			cipherParams: cipherParams,
		}, nil

	}

	privateKey := PrivateKeyFromContext(ctx)
	if privateKey != nil {
		return &Cipher{
			operation:    operation,
			key:          &privateKey.key,
			cipherParams: cipherParams,
		}, nil

	}

	publicKey := PublicKeyFromContext(ctx)
	if publicKey != nil {
		return &Cipher{
			operation:    operation,
			key:          &publicKey.key,
			cipherParams: cipherParams,
		}, nil

	}

	return nil, errors.New("cipherFactory needs a key")
}

//func (s CipherFactory) NewCipher(operation kms.CipherOperation, key kms.Key, cipherParams *kms.CipherParameters) (kms.Cipher, error) {
//	sk, ok := key.(*Key)
//	if !ok {
//		return nil, errors.New("invalid key type: not Key")
//	}
//	return &Cipher{
//		operation:    operation,
//		key:          sk,
//		cipherParams: cipherParams,
//	}, nil
//
//}
