// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package securosyshsm

import (
	"context"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"time"

	//"github.com/andreburgaud/crypt2go/padding"
	"github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/helpers"
	kms "github.com/openbao/go-kms-wrapping/v2/kms"
)

// Ensure KeyStore implements KeyStore
var _ kms.Cipher = (*Cipher)(nil)

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
	c.buffer = append(c.buffer, input...)
	return c.buffer, nil // nothing processed yet
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
	vector := ""
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
		vector,
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
	tagLength := 128
	encryptedPayload := c.buffer
	IV, encryptedPayload, MAC, err := c.splitCipherOutput(encryptedPayload)
	if err != nil {
		return nil, err
	}
	if MAC != nil {
		tagLength = len(MAC) * 8
		encryptedPayload = append(encryptedPayload, MAC...)
	}
	vector := ""
	if IV != nil {
		vector = b64.StdEncoding.EncodeToString(IV)
	}
	aad := ""
	if c.cipherParams.Algorithm == kms.CipherMode_AES_GCM {
		if params, ok := c.cipherParams.Parameters.(*kms.AESGCMCipherParameters); ok && params != nil {
			if len(params.AAD) > 0 {
				aad = b64.StdEncoding.EncodeToString(params.AAD)
			}
		}
	}
	var result string
	result, _, err = c.key.client.AsyncDecrypt(
		c.key.GetName(),
		c.key.password,
		b64.StdEncoding.EncodeToString(encryptedPayload),
		vector,
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
	if c.cipherParams.Algorithm == kms.CipherMode_AES_GCM {
		if params, ok := c.cipherParams.Parameters.(*kms.AESGCMCipherParameters); ok && params != nil {
			if len(params.AAD) > 0 {
				aad = b64.StdEncoding.EncodeToString(params.AAD)
			}
		}
	}

	//.AAD != nil {
	//	aad = b64.StdEncoding.EncodeToString(c.cipherParams.AAD)
	//}
	tagLength := 0
	if c.cipherParams.Algorithm == kms.CipherMode_AES_GCM {
		tagLength = 128
	} else {
		tagLength = -1
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
	return c.combineCipherOutput(initializationVector, encryptedPayload, messageAuthenticationCode), nil

}
func (c *Cipher) combineCipherOutput(initializationVector, encryptedPayload, messageAuthenticationCode []byte) []byte {
	if c.cipherParams.Algorithm == kms.CipherMode_AES_GCM {
		totalLen := len(initializationVector) + len(encryptedPayload) + len(messageAuthenticationCode)
		combined := make([]byte, 0, totalLen)

		combined = append(combined, initializationVector...)
		combined = append(combined, encryptedPayload...)
		combined = append(combined, messageAuthenticationCode...)

		return combined

	} else {
		out := make([]byte, len(encryptedPayload))
		copy(out, encryptedPayload)
		return out

	}
}
func (c *Cipher) splitCipherOutput(output []byte) (initializationVector, encryptedPayload, messageAuthenticationCode []byte, err error) {

	if c.cipherParams.Algorithm == kms.CipherMode_AES_GCM {
		const ivSize = 12 // standard AES-GCM IV size
		macSize := 128 / 8

		if len(output) < ivSize+macSize {
			return nil, nil, nil, fmt.Errorf("cipher: invalid AES-GCM ciphertext length")
		}

		initializationVector = output[:ivSize]
		encryptedPayload = output[ivSize : len(output)-macSize]
		messageAuthenticationCode = output[len(output)-macSize:]

		return initializationVector, encryptedPayload, messageAuthenticationCode, nil

	} else {
		return nil, output, nil, nil
	}
}

type CipherFactory struct {
}

func (c CipherFactory) NewCipher(ctx context.Context, operation kms.CipherOperation, cipherParams *kms.CipherParameters) (kms.Cipher, error) {
	privateKey := PrivateKeyFromContext(ctx)
	if privateKey != nil {
		return &Cipher{
			operation:    operation,
			key:          &privateKey.key,
			cipherParams: cipherParams,
		}, nil

	}
	secretKey := SecretKeyFromContext(ctx)
	if secretKey != nil {
		return &Cipher{
			operation:    operation,
			key:          &secretKey.key,
			cipherParams: cipherParams,
		}, nil

	}

	return nil, errors.New("cipherFactory needs a key")
}

// Ensure KeyStoreFactory implements KeyStoreFactory
var _ kms.CipherFactory = (*CipherFactory)(nil)

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
