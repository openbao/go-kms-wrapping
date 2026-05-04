// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/openbao/go-kms-wrapping/kms/securosyshsm/v2/client"
	"github.com/openbao/go-kms-wrapping/kms/securosyshsm/v2/helpers"
	kms "github.com/openbao/go-kms-wrapping/v2/kms"
)

// Ensure securosysKey implements kms.Key
var _ kms.Key = (*securosysKey)(nil)

// securosysKey implements kms.Key using a Securosys HSM key.
//
// Cipher operations default to AES_GCM for symmetric keys and
// RSA_PADDING_OAEP_WITH_SHA256 for RSA keys. Callers can select another HSM
// cipher by passing "cipher_algorithm" in kms.KeyOptions.ConfigMap; supported
// values are listed in helpers.AES_CIPHER_LIST and helpers.RSA_CIPHER_LIST.
type securosysKey struct {
	kms.UnimplementedKey
	client          *client.SecurosysClient
	keyAttrs        helpers.KeyAttributes
	password        string
	cipherAlgorithm string
}

// Encrypt encrypts opts.Data with the configured Securosys key.
//
// Supported ciphers are the AES and RSA algorithms listed in helpers/consts.go.
// AAD is supported only with AES_GCM; when the HSM returns a nonce/IV it is
// written back to opts.Nonce for the matching Decrypt call.
func (k *securosysKey) Encrypt(ctx context.Context, opts *kms.CipherOptions) ([]byte, error) {
	if k.client == nil {
		return nil, errors.New("key not initialized")
	}
	if opts == nil || opts.Data == nil {
		return nil, errors.New("cipher options and data are required")
	}

	cipherAlgorithm, err := k.resolveCipherAlgorithm()
	if err != nil {
		return nil, err
	}

	aad := ""
	tagLength := -1 // Default: no tag length specified

	if len(opts.AAD) > 0 {
		if cipherAlgorithm != "AES_GCM" {
			return nil, errors.New("AAD is only supported with AES_GCM")
		}
		aad = base64.StdEncoding.EncodeToString(opts.AAD)
		tagLength = 128 // Use tag length when AAD is provided
	}

	// Call the encrypt API
	encryptResp, _, err := k.client.Encrypt(
		k.keyAttrs.Label,
		k.password,
		base64.StdEncoding.EncodeToString(opts.Data),
		cipherAlgorithm,
		tagLength,
		aad,
	)
	if err != nil {
		return nil, fmt.Errorf("encrypt failed: %w", err)
	}

	var encryptedPayload []byte
	if encryptResp.EncryptedPayloadWithoutMessageAuthenticationCode == "" {
		encryptedPayload, err = base64.StdEncoding.DecodeString(encryptResp.EncryptedPayload)
	} else {
		encryptedPayload, err = base64.StdEncoding.DecodeString(encryptResp.EncryptedPayloadWithoutMessageAuthenticationCode)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted payload: %w", err)
	}

	// Extract nonce/IV if provided
	var nonce []byte
	if encryptResp.InitializationVector != nil {
		nonce, err = base64.StdEncoding.DecodeString(*encryptResp.InitializationVector)
		if err != nil {
			return nil, fmt.Errorf("failed to decode initialization vector: %w", err)
		}
	}

	// Extract MAC if provided
	var mac []byte
	if encryptResp.MessageAuthenticationCode != nil {
		mac, err = base64.StdEncoding.DecodeString(*encryptResp.MessageAuthenticationCode)
		if err != nil {
			return nil, fmt.Errorf("failed to decode MAC: %w", err)
		}
	}

	// Combine nonce + ciphertext + MAC
	opts.Nonce = nonce
	result := combineCipherOutput(encryptedPayload, mac)

	return result, nil
}

// Decrypt decrypts opts.Data with the configured Securosys key.
//
// For AES_GCM callers must pass the nonce produced by Encrypt in opts.Nonce.
// AAD must match the Encrypt call and is supported only with AES_GCM.
func (k *securosysKey) Decrypt(ctx context.Context, opts *kms.CipherOptions) ([]byte, error) {
	if k.client == nil {
		return nil, errors.New("key not initialized")
	}
	if opts == nil || opts.Data == nil {
		return nil, errors.New("cipher options and data are required")
	}

	cipherAlgorithm, err := k.resolveCipherAlgorithm()
	if err != nil {
		return nil, err
	}

	aad := ""
	tagLength := -1
	initVector := ""
	if cipherAlgorithm == "AES_GCM" {
		tagLength = 128
	}

	if len(opts.AAD) > 0 {
		if cipherAlgorithm != "AES_GCM" {
			return nil, errors.New("AAD is only supported with AES_GCM")
		}
		aad = base64.StdEncoding.EncodeToString(opts.AAD)
	}

	// If nonce is provided, use it
	if len(opts.Nonce) > 0 {
		initVector = base64.StdEncoding.EncodeToString(opts.Nonce)
	}

	// Call the decrypt API
	decryptResp, _, err := k.client.Decrypt(
		k.keyAttrs.Label,
		k.password,
		base64.StdEncoding.EncodeToString(opts.Data),
		initVector,
		cipherAlgorithm,
		tagLength,
		aad,
	)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}

	payload, err := base64.StdEncoding.DecodeString(decryptResp.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode decrypted payload: %w", err)
	}

	return payload, nil
}

// Sign creates a digital signature with an asymmetric Securosys key.
//
// Supported signature families are RSA PKCS#1 v1.5, RSA-PSS, ECDSA, and EdDSA.
// RSA and ECDSA support SHA-256, SHA-384, and SHA-512. RSA-PSS is selected by
// passing *rsa.PSSOptions; plain RSA is selected by passing a crypto.Hash.
// ECDSA with Prehashed=true maps to NONE_WITH_ECDSA, and Ed25519 maps to EDDSA.
func (k *securosysKey) Sign(ctx context.Context, opts *kms.SignOptions) ([]byte, error) {
	if k.client == nil {
		return nil, errors.New("key not initialized")
	}
	if opts == nil || opts.Data == nil {
		return nil, errors.New("sign options and data are required")
	}

	// Check if this is an asymmetric key
	if k.keyAttrs.PublicKey == "" {
		return nil, errors.New("key is not a signing key")
	}
	pub, err := k.ExportPublic(ctx)
	if err != nil {
		return nil, err
	}
	// Determine signature algorithm based on SignerOpts
	sigAlgorithm, err := mapSignAlgorithmFromOpts(opts, pub)
	if err != nil {
		return nil, err
	}

	// Prepare the data to sign
	var inputData string
	if opts.Prehashed {
		// Data is already hashed
		inputData = base64.StdEncoding.EncodeToString(opts.Data)
	} else {
		// Raw data - let the HSM hash it
		inputData = base64.StdEncoding.EncodeToString(opts.Data)
	}

	// Call async sign
	result, _, err := k.client.AsyncSign(
		k.keyAttrs.Label,
		k.password,
		inputData,
		"UNSPECIFIED",
		sigAlgorithm,
		map[string]string{},
	)
	if err != nil {
		return nil, fmt.Errorf("sign failed: %w", err)
	}

	// Poll for result
	request, _, err := k.client.GetRequest(result)
	for request.Status == "PENDING" {
		if err != nil {
			return nil, err
		}
		time.Sleep(5 * time.Second)
		request, _, err = k.client.GetRequest(result)
	}
	if request.Status != "EXECUTED" {
		return nil, fmt.Errorf("sign failed with status: %s", request.Status)
	}

	signature, err := base64.StdEncoding.DecodeString(request.Result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	opts.KeyVersion = k.keyAttrs.Version
	return signature, nil
}

// Verify verifies a digital signature created by Sign.
//
// The same SignerOpts and Prehashed values used for Sign must be supplied so
// the request maps to the same Securosys signature algorithm.
func (k *securosysKey) Verify(ctx context.Context, opts *kms.VerifyOptions) error {
	if k.client == nil {
		return errors.New("key not initialized")
	}
	if opts == nil || opts.Signature == nil || opts.Data == nil {
		return errors.New("verify options, signature and data are required")
	}
	pub, err := k.ExportPublic(ctx)
	if err != nil {
		return err
	}

	// Determine signature algorithm
	sigAlgorithm, err := mapSignAlgorithmFromVerifyOpts(opts, pub)
	if err != nil {
		return err
	}

	// Prepare the data to verify
	var inputData string
	if opts.Prehashed {
		inputData = base64.StdEncoding.EncodeToString(opts.Data)
	} else {
		inputData = base64.StdEncoding.EncodeToString(opts.Data)
	}

	// Call verify
	result, _, err := k.client.Verify(
		k.keyAttrs.Label,
		k.password,
		inputData,
		sigAlgorithm,
		base64.StdEncoding.EncodeToString(opts.Signature),
	)
	if err != nil {
		return fmt.Errorf("verify failed: %w", err)
	}

	if !result {
		return kms.ErrInvalidSignature
	}

	return nil
}

// ExportPublic exports a key's associated public key if applicable.
//
// Securosys may return the public key as PEM or base64 DER; both encodings are
// accepted and parsed through x509.ParsePKIXPublicKey.
func (k *securosysKey) ExportPublic(ctx context.Context) (crypto.PublicKey, error) {
	if k.keyAttrs.PublicKey == "" {
		return nil, errors.New("key does not have a public key")
	}

	publicKeyStr := k.keyAttrs.PublicKey

	// Try to decode PEM first
	block, _ := pem.Decode([]byte(publicKeyStr))
	if block != nil {
		// It's a valid PEM — parse as DER
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PEM public key: %w", err)
		}
		return pub, nil
	}

	// Not PEM → try Base64 decode
	derBytes, err := base64.StdEncoding.DecodeString(publicKeyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 public key: %w", err)
	}

	// Parse as ASN.1 DER
	pub, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ASN.1 public key: %w", err)
	}

	return pub, nil
}

// Close terminates this key.
func (k *securosysKey) Close(ctx context.Context) error {
	k.password = ""
	return nil
}

// combineCipherOutput combines encrypted payload with an optional MAC/tag.
func combineCipherOutput(encryptedPayload, mac []byte) []byte {
	combined := make([]byte, 0, len(encryptedPayload)+len(mac))
	combined = append(combined, encryptedPayload...)
	combined = append(combined, mac...)
	return combined
}

// resolveCipherAlgorithm returns the HSM cipher algorithm for this key.
//
// The provider-specific "cipher_algorithm" key option takes precedence. If it
// is omitted, RSA keys default to RSA_PADDING_OAEP_WITH_SHA256 and all other
// keys default to AES_GCM.
func (k *securosysKey) resolveCipherAlgorithm() (string, error) {
	if k.cipherAlgorithm != "" {
		return normalizeCipherAlgorithm(k.cipherAlgorithm)
	}
	if k.keyAttrs.Algorithm == "RSA" {
		return "RSA_PADDING_OAEP_WITH_SHA256", nil
	}
	return "AES_GCM", nil
}

// normalizeCipherAlgorithm accepts either native Securosys HSM names from the
// helper constants or compatibility names supported by helpers.MapCipherAlgorithm.
func normalizeCipherAlgorithm(algorithm string) (string, error) {
	if containsString(helpers.AES_CIPHER_LIST, algorithm) || containsString(helpers.RSA_CIPHER_LIST, algorithm) {
		return algorithm, nil
	}
	return helpers.MapCipherAlgorithm(algorithm)
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

// mapRSAAlgorithm maps Go RSA signing options to Securosys HSM algorithm names.
//
// pss=true selects *_WITH_RSA_PSS algorithms; pss=false selects plain
// *_WITH_RSA. The supported hash functions are SHA-256, SHA-384, and SHA-512.
func mapRSAAlgorithm(hash crypto.Hash, prehashed, pss bool) (string, error) {
	if hash == crypto.Hash(0) {
		if prehashed && !pss {
			return "NONE_WITH_RSA", nil
		}
		if pss {
			return "", errors.New("hash function required for RSA-PSS")
		}
		return "", errors.New("hash function required for RSA")
	}

	switch hash {
	case crypto.SHA256:
		if prehashed && pss {
			return "NONESHA256_WITH_RSA_PSS", nil
		}
		if pss {
			return "SHA256_WITH_RSA_PSS", nil
		}
		return "SHA256_WITH_RSA", nil
	case crypto.SHA384:
		if prehashed && pss {
			return "NONESHA384_WITH_RSA_PSS", nil
		}
		if pss {
			return "SHA384_WITH_RSA_PSS", nil
		}
		return "SHA384_WITH_RSA", nil
	case crypto.SHA512:
		if prehashed && pss {
			return "NONESHA512_WITH_RSA_PSS", nil
		}
		if pss {
			return "SHA512_WITH_RSA_PSS", nil
		}
		return "SHA512_WITH_RSA", nil
	default:
		if pss {
			return "", fmt.Errorf("unsupported RSA-PSS hash: %v", hash)
		}
		return "", fmt.Errorf("unsupported RSA hash: %v", hash)
	}
}

// mapSignAlgorithmFromOpts maps kms.SignOptions and public-key type to the
// Securosys HSM signature algorithm string.
//
// Supported mappings:
//   - *rsa.PublicKey + crypto.SHA{256,384,512}: SHA*_WITH_RSA
//   - *rsa.PublicKey + *rsa.PSSOptions: SHA*_WITH_RSA_PSS
//   - *ecdsa.PublicKey + crypto.SHA{256,384,512}: SHA*_WITH_ECDSA
//   - *ecdsa.PublicKey + Prehashed=true: NONE_WITH_ECDSA
//   - ed25519.PublicKey: EDDSA
func mapSignAlgorithmFromOpts(opts *kms.SignOptions, pub crypto.PublicKey) (string, error) {
	if opts == nil {
		return "", errors.New("sign options are required")
	}
	if opts.SignerOpts == nil {
		return "", errors.New("signer options are required")
	}

	hash := opts.HashFunc()
	prehashed := opts.Prehashed

	switch key := pub.(type) {

	// --- RSA ---
	case *rsa.PublicKey:
		if _, ok := opts.SignerOpts.(*rsa.PSSOptions); ok {
			return mapRSAAlgorithm(hash, prehashed, true)
		}
		return mapRSAAlgorithm(hash, prehashed, false)

	// --- ECDSA ---
	case *ecdsa.PublicKey:
		if prehashed {
			return "NONE_WITH_ECDSA", nil
		}

		// If hash not provided → derive from curve
		if hash == crypto.Hash(0) {
			switch key.Curve.Params().BitSize {
			case 256:
				hash = crypto.SHA256
			case 384:
				hash = crypto.SHA384
			case 521:
				hash = crypto.SHA512
			default:
				return "", fmt.Errorf("unsupported ECDSA curve size: %d", key.Curve.Params().BitSize)
			}
		}

		switch hash {
		case crypto.SHA256:
			return "SHA256_WITH_ECDSA", nil
		case crypto.SHA384:
			return "SHA384_WITH_ECDSA", nil
		case crypto.SHA512:
			return "SHA512_WITH_ECDSA", nil
		default:
			return "", fmt.Errorf("unsupported ECDSA hash: %v", hash)
		}

	// --- Ed25519 ---
	case ed25519.PublicKey:
		return "EDDSA", nil

	default:
		return "", fmt.Errorf("unsupported key type: %T", pub)
	}
}

// mapSignAlgorithmFromVerifyOpts maps VerifyOptions to a Securosys HSM
// signature algorithm string.
//
// Verify must use the same family/hash mapping as Sign. See
// mapSignAlgorithmFromOpts for the supported algorithm matrix.
func mapSignAlgorithmFromVerifyOpts(opts *kms.VerifyOptions, pub crypto.PublicKey) (string, error) {
	if opts == nil {
		return "", errors.New("verify options are required")
	}
	if opts.SignerOpts == nil {
		return "", errors.New("signer options are required")
	}

	hash := opts.HashFunc()
	prehashed := opts.Prehashed

	switch key := pub.(type) {

	// --- RSA-PSS ---
	case *rsa.PublicKey:
		if _, ok := opts.SignerOpts.(*rsa.PSSOptions); ok {
			return mapRSAAlgorithm(hash, prehashed, true)
		}
		return mapRSAAlgorithm(hash, prehashed, false)

	// --- ECDSA ---
	case *ecdsa.PublicKey:
		if prehashed {
			return "NONE_WITH_ECDSA", nil
		}

		// Derive hash from curve if not provided
		if hash == crypto.Hash(0) {
			switch key.Curve.Params().BitSize {
			case 256:
				hash = crypto.SHA256
			case 384:
				hash = crypto.SHA384
			case 521:
				hash = crypto.SHA512
			default:
				return "", fmt.Errorf("unsupported ECDSA curve size: %d", key.Curve.Params().BitSize)
			}
		}

		switch hash {
		case crypto.SHA256:
			return "SHA256_WITH_ECDSA", nil
		case crypto.SHA384:
			return "SHA384_WITH_ECDSA", nil
		case crypto.SHA512:
			return "SHA512_WITH_ECDSA", nil
		default:
			return "", fmt.Errorf("unsupported ECDSA hash: %v", hash)
		}

	// --- Ed25519 ---
	case ed25519.PublicKey:
		return "EDDSA", nil

	default:
		return "", fmt.Errorf("unsupported key type: %T", pub)
	}
}
