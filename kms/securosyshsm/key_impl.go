// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strings"
	"time"

	kms "github.com/openbao/go-kms-wrapping/v2/kms"
	client "github.com/securosys-com/tsb-client-go"
	"github.com/securosys-com/tsb-client-go/helpers"
)

const (
	defaultApprovalTimeout     = 10 * time.Minute
	defaultRequestPollInterval = 5 * time.Second
)

// securosysKey implements kms.Key using a Securosys HSM key.
type securosysKey struct {
	kms.UnimplementedKey
	client          *client.SecurosysClient
	keyAttrs        helpers.KeyAttributes
	password        string
	cipherAlgorithm string
	approvalTimeout time.Duration
	closeCtx        context.Context
}

// Encrypt encrypts opts.Data with the configured Securosys key.
func (k *securosysKey) Encrypt(ctx context.Context, opts *kms.CipherOptions) ([]byte, error) {
	if isMLKEMAlgorithm(k.keyAttrs.Algorithm) {
		return k.client.EncryptMLKEMHybrid(ctx, k.keyAttrs.Label, k.password, opts.Data, opts.AAD)
	}

	cipherAlgorithm, err := k.resolveCipherAlgorithm()
	if err != nil {
		return nil, err
	}

	aad := ""
	tagLength := -1 // Default: no tag length specified
	if cipherAlgorithm == "AES_GCM" {
		tagLength = 128
	}

	if len(opts.AAD) > 0 {
		if cipherAlgorithm != "AES_GCM" {
			return nil, errors.New("AAD is only supported with AES_GCM")
		}
		aad = base64.StdEncoding.EncodeToString(opts.AAD)
	}

	encryptResp, _, err := k.client.Encrypt(
		ctx,
		k.keyAttrs.Label,
		k.password,
		base64.StdEncoding.EncodeToString(opts.Data),
		client.CipherAlgorithm(cipherAlgorithm),
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

	var nonce []byte
	if encryptResp.InitializationVector != nil {
		nonce, err = base64.StdEncoding.DecodeString(*encryptResp.InitializationVector)
		if err != nil {
			return nil, fmt.Errorf("failed to decode initialization vector: %w", err)
		}
	}

	var mac []byte
	if encryptResp.MessageAuthenticationCode != nil {
		mac, err = base64.StdEncoding.DecodeString(*encryptResp.MessageAuthenticationCode)
		if err != nil {
			return nil, fmt.Errorf("failed to decode MAC: %w", err)
		}
	}

	result := combineCipherOutput(nonce, encryptedPayload, mac)

	return result, nil
}

// Decrypt decrypts opts.Data with the configured Securosys key.
func (k *securosysKey) Decrypt(ctx context.Context, opts *kms.CipherOptions) ([]byte, error) {
	if isMLKEMAlgorithm(k.keyAttrs.Algorithm) {
		ctx, cancel := k.approvalContext(ctx)
		defer cancel()
		return k.client.DecryptMLKEMHybrid(ctx, k.keyAttrs.Label, k.password, opts.Data, opts.AAD)
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

	nonceSize := cipherNonceSize(cipherAlgorithm)
	if len(opts.Data) < nonceSize {
		return nil, fmt.Errorf("ciphertext is shorter than the required %d-byte nonce", nonceSize)
	}
	ciphertext := opts.Data
	if nonceSize > 0 {
		initVector = base64.StdEncoding.EncodeToString(opts.Data[:nonceSize])
		ciphertext = opts.Data[nonceSize:]
	}

	payload, err := k.decryptPayload(ctx, ciphertext, initVector, cipherAlgorithm, tagLength, aad)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

func (k *securosysKey) decryptPayload(ctx context.Context, ciphertext []byte, initVector, cipherAlgorithm string, tagLength int, aad string) ([]byte, error) {
	encryptedPayload := base64.StdEncoding.EncodeToString(ciphertext)
	ctx, cancel := k.approvalContext(ctx)
	defer cancel()
	decryptResp, _, err := k.client.Decrypt(
		ctx,
		k.keyAttrs.Label,
		k.password,
		encryptedPayload,
		initVector,
		client.CipherAlgorithm(cipherAlgorithm),
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
func (k *securosysKey) Sign(ctx context.Context, opts *kms.SignOptions) ([]byte, error) {
	if k.keyAttrs.PublicKey == "" {
		return nil, errors.New("key is not a signing key")
	}
	pub, err := k.ExportPublic(ctx)
	if err != nil {
		return nil, err
	}
	sigAlgorithm, err := mapSignAlgorithmFromOpts(opts, pub)
	if err != nil {
		return nil, err
	}

	inputData := base64.StdEncoding.EncodeToString(opts.Data)
	ctx, cancel := k.approvalContext(ctx)
	defer cancel()
	result, _, err := k.client.Sign(
		ctx,
		k.keyAttrs.Label,
		k.password,
		inputData,
		"UNSPECIFIED",
		client.SignatureAlgorithm(sigAlgorithm),
		signatureTypeForPublicKey(pub),
	)
	if err != nil {
		return nil, fmt.Errorf("sign failed: %w", err)
	}

	signature, err := base64.StdEncoding.DecodeString(result.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	return signature, nil
}

// Verify verifies a digital signature created by Sign.
func (k *securosysKey) Verify(ctx context.Context, opts *kms.VerifyOptions) error {
	pub, err := k.ExportPublic(ctx)
	if err != nil {
		return err
	}

	sigAlgorithm, err := mapSignAlgorithmFromVerifyOpts(opts, pub)
	if err != nil {
		return err
	}

	inputData := base64.StdEncoding.EncodeToString(opts.Data)

	result, _, err := k.client.Verify(
		ctx,
		k.keyAttrs.Label,
		k.password,
		inputData,
		client.SignatureAlgorithm(sigAlgorithm),
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
func (k *securosysKey) ExportPublic(ctx context.Context) (crypto.PublicKey, error) {
	if k.keyAttrs.PublicKey == "" {
		return nil, errors.New("key does not have a public key")
	}

	publicKeyStr := k.keyAttrs.PublicKey

	block, _ := pem.Decode([]byte(publicKeyStr))
	if block != nil {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PEM public key: %w", err)
		}
		return pub, nil
	}

	derBytes, err := base64.StdEncoding.DecodeString(publicKeyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 public key: %w", err)
	}

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

func (k *securosysKey) approvalContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}

	timeoutCancel := func() {}
	if _, ok := ctx.Deadline(); !ok {
		approvalTimeout := k.approvalTimeout
		if approvalTimeout <= 0 {
			approvalTimeout = defaultApprovalTimeout
		}
		ctx, timeoutCancel = context.WithTimeout(ctx, approvalTimeout)
	}

	ctx, stopSignalNotify := signal.NotifyContext(ctx, os.Interrupt)
	ctx, cancel := context.WithCancel(ctx)

	stopClose := func() bool { return false }
	if k.closeCtx != nil {
		stopClose = context.AfterFunc(k.closeCtx, cancel)
	}

	return ctx, func() {
		stopClose()
		cancel()
		stopSignalNotify()
		timeoutCancel()
	}
}

// combineCipherOutput prepends the nonce and appends an optional MAC/tag to
// the encrypted payload, as required by kms.CipherOptions.
func combineCipherOutput(nonce, encryptedPayload, mac []byte) []byte {
	combined := make([]byte, 0, len(nonce)+len(encryptedPayload)+len(mac))
	combined = append(combined, nonce...)
	combined = append(combined, encryptedPayload...)
	combined = append(combined, mac...)
	return combined
}

func cipherNonceSize(cipherAlgorithm string) int {
	switch cipherAlgorithm {
	case "AES_GCM":
		return 12
	case "AES", "AES_CTR", "AES_CBC_NO_PADDING":
		return 16
	default:
		return 0
	}
}

func isMLKEMAlgorithm(algorithm string) bool {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024":
		return true
	default:
		return false
	}
}

// resolveCipherAlgorithm returns the HSM cipher algorithm for this key.
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
func normalizeCipherAlgorithm(algorithm string) (string, error) {
	if slices.Contains(helpers.AES_CIPHER_LIST, algorithm) || slices.Contains(helpers.RSA_CIPHER_LIST, algorithm) {
		return algorithm, nil
	}
	return helpers.MapCipherAlgorithm(algorithm)
}

// mapRSAAlgorithm maps Go RSA signing options to Securosys HSM algorithm names.
func mapRSAAlgorithm(hash crypto.Hash, prehashed, pss bool) (string, error) {
	if hash == crypto.Hash(0) {
		if prehashed && pss {
			return "NONE_WITH_RSA_PSS", nil
		}
		if prehashed {
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
		if prehashed {
			return "NONESHA256_WITH_RSA", nil
		}
		return "SHA256_WITH_RSA", nil
	case crypto.SHA384:
		if prehashed && pss {
			return "NONESHA384_WITH_RSA_PSS", nil
		}
		if pss {
			return "SHA384_WITH_RSA_PSS", nil
		}
		if prehashed {
			return "NONESHA384_WITH_RSA", nil
		}
		return "SHA384_WITH_RSA", nil
	case crypto.SHA512:
		if prehashed && pss {
			return "NONESHA512_WITH_RSA_PSS", nil
		}
		if pss {
			return "SHA512_WITH_RSA_PSS", nil
		}
		if prehashed {
			return "NONESHA512_WITH_RSA", nil
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
		if algorithm, ok, err := mapPostQuantumSignAlgorithm(opts.Prehashed, hash, pub); ok || err != nil {
			return algorithm, err
		}
		return "", fmt.Errorf("unsupported key type: %T", pub)
	}
}

func signatureTypeForPublicKey(pub crypto.PublicKey) client.SignatureType {
	switch pub.(type) {
	case ed25519.PublicKey:
		return client.SignatureTypeRAW
	default:
		return client.SignatureTypeDER
	}
}

// mapSignAlgorithmFromVerifyOpts maps VerifyOptions to a Securosys HSM
// signature algorithm string.
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
		if algorithm, ok, err := mapPostQuantumSignAlgorithm(opts.Prehashed, hash, pub); ok || err != nil {
			return algorithm, err
		}
		return "", fmt.Errorf("unsupported key type: %T", pub)
	}
}

func mapPostQuantumSignAlgorithm(prehashed bool, hash crypto.Hash, pub crypto.PublicKey) (string, bool, error) {
	if _, ok := pub.(*mldsa.PublicKey); !ok {
		return "", false, nil
	}
	if prehashed || hash != 0 {
		return "", true, errors.New("ML-DSA requires raw message signing with crypto.Hash(0)")
	}
	return "ML_DSA", true, nil
}
