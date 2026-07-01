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

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/go-kms-wrapping/kms/securosyshsm/v2/internal/client"
	"github.com/openbao/go-kms-wrapping/kms/securosyshsm/v2/internal/helpers"
	kms "github.com/openbao/go-kms-wrapping/v2/kms"
)

// Ensure securosysKey implements kms.Key
var _ kms.Key = (*securosysKey)(nil)

var ErrApprovalTimeout = errors.New("approval timeout exceeded")
var ErrKMSClosed = errors.New("securosys hsm kms closed")

const defaultApprovalTimeout = 60 * time.Second
const defaultRequestPollInterval = 1 * time.Second

// securosysKey implements kms.Key using a Securosys HSM key.
type securosysKey struct {
	kms.UnimplementedKey
	client          *client.SecurosysClient
	keyAttrs        helpers.KeyAttributes
	password        string
	cipherAlgorithm string
	logger          hclog.Logger
	closeCtx        context.Context
}

// Encrypt encrypts opts.Data with the configured Securosys key.
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

	encryptResp, _, err := k.client.Encrypt(
		ctx,
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

	opts.Nonce = nonce
	result := combineCipherOutput(encryptedPayload, mac)

	return result, nil
}

// Decrypt decrypts opts.Data with the configured Securosys key.
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

	if len(opts.Nonce) > 0 {
		initVector = base64.StdEncoding.EncodeToString(opts.Nonce)
	}

	payload, err := k.decryptPayload(ctx, opts.Data, initVector, cipherAlgorithm, tagLength, aad)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

func (k *securosysKey) decryptPayload(ctx context.Context, ciphertext []byte, initVector, cipherAlgorithm string, tagLength int, aad string) ([]byte, error) {
	encryptedPayload := base64.StdEncoding.EncodeToString(ciphertext)

	if containsString(helpers.AES_CIPHER_LIST, cipherAlgorithm) {
		return k.decryptPayloadSync(ctx, encryptedPayload, initVector, cipherAlgorithm, tagLength, aad)
	}

	return k.decryptPayloadAsync(ctx, encryptedPayload, initVector, cipherAlgorithm, tagLength, aad)
}

func (k *securosysKey) decryptPayloadSync(ctx context.Context, encryptedPayload, initVector, cipherAlgorithm string, tagLength int, aad string) ([]byte, error) {
	decryptResp, _, err := k.client.Decrypt(
		ctx,
		k.keyAttrs.Label,
		k.password,
		encryptedPayload,
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

func (k *securosysKey) decryptPayloadAsync(ctx context.Context, encryptedPayload, initVector, cipherAlgorithm string, tagLength int, aad string) ([]byte, error) {
	requestID, _, err := k.client.AsyncDecrypt(
		ctx,
		k.keyAttrs.Label,
		k.password,
		encryptedPayload,
		initVector,
		cipherAlgorithm,
		tagLength,
		aad,
		map[string]string{},
	)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}

	request, err := k.waitForRequest(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("async decrypt failed: %w", err)
	}
	if request.Status != "EXECUTED" {
		return nil, fmt.Errorf("decrypt failed with status: %s", request.Status)
	}

	payload, err := base64.StdEncoding.DecodeString(request.Result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode decrypted payload: %w", err)
	}

	return payload, nil
}

// Sign creates a digital signature with an asymmetric Securosys key.
func (k *securosysKey) Sign(ctx context.Context, opts *kms.SignOptions) ([]byte, error) {
	if k.client == nil {
		return nil, errors.New("key not initialized")
	}
	if opts == nil || opts.Data == nil {
		return nil, errors.New("sign options and data are required")
	}

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

	result, _, err := k.client.AsyncSign(
		ctx,
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

	request, err := k.waitForRequest(ctx, result)
	if err != nil {
		return nil, err
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

func (k *securosysKey) waitForRequest(ctx context.Context, requestID string) (*helpers.RequestResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	logger := k.logger
	waitStarted := time.Now()
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultApprovalTimeout)
		defer cancel()
	}
	ctx, cancelOnClose := k.contextWithKMSClose(ctx)
	defer cancelOnClose()

	pollInterval := defaultRequestPollInterval
	if logger != nil {
		if deadline, ok := ctx.Deadline(); ok {
			logger.Info("waiting for securosys async request approval", "request_id", requestID, "poll_interval", pollInterval.String(), "timeout_in", time.Until(deadline).Round(time.Second).String())
		} else {
			logger.Info("waiting for securosys async request approval", "request_id", requestID, "poll_interval", pollInterval.String())
		}
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		request, _, err := k.client.GetRequest(ctx, requestID)
		if err != nil {
			if ctx.Err() != nil {
				if logger != nil {
					logger.Warn("securosys async request wait stopped", "request_id", requestID, "elapsed", time.Since(waitStarted).Round(time.Second).String(), "error", ctx.Err())
				}
				return nil, k.waitForRequestStopError(ctx, requestID)
			}
			if logger != nil {
				logger.Error("failed to poll securosys async request", "request_id", requestID, "elapsed", time.Since(waitStarted).Round(time.Second).String(), "error", err)
			}
			return nil, err
		}
		if logger != nil {
			logger.Info("polled securosys async request", "request_id", requestID, "status", request.Status, "elapsed", time.Since(waitStarted).Round(time.Second).String())
		}
		if request.Status != "PENDING" && request.Status != "APPROVED" {
			if logger != nil {
				logger.Info("securosys async request completed", "request_id", requestID, "status", request.Status, "elapsed", time.Since(waitStarted).Round(time.Second).String())
			}
			return request, nil
		}

		select {
		case <-ctx.Done():
			if logger != nil {
				logger.Warn("securosys async request wait stopped", "request_id", requestID, "status", request.Status, "elapsed", time.Since(waitStarted).Round(time.Second).String(), "error", ctx.Err())
			}
			return nil, k.waitForRequestStopError(ctx, requestID)
		case <-ticker.C:
		}
	}
}

func (k *securosysKey) contextWithKMSClose(ctx context.Context) (context.Context, context.CancelFunc) {
	if k.closeCtx == nil {
		return ctx, func() {}
	}

	waitCtx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-k.closeCtx.Done():
			cancel()
		case <-waitCtx.Done():
		}
	}()
	return waitCtx, cancel
}

func (k *securosysKey) waitForRequestStopError(ctx context.Context, requestID string) error {
	if k.closeCtx != nil {
		select {
		case <-k.closeCtx.Done():
			return fmt.Errorf("%w while waiting for request %s: %w", ErrKMSClosed, requestID, context.Canceled)
		default:
		}
	}
	return waitForRequestContextError(ctx, requestID)
}

func waitForRequestContextError(ctx context.Context, requestID string) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w for request %s: %w", ErrApprovalTimeout, requestID, ctx.Err())
	}
	return fmt.Errorf("wait for request %s stopped: %w", requestID, ctx.Err())
}

// combineCipherOutput combines encrypted payload with an optional MAC/tag.
func combineCipherOutput(encryptedPayload, mac []byte) []byte {
	combined := make([]byte, 0, len(encryptedPayload)+len(mac))
	combined = append(combined, encryptedPayload...)
	combined = append(combined, mac...)
	return combined
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
		return "", fmt.Errorf("unsupported key type: %T", pub)
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
		return "", fmt.Errorf("unsupported key type: %T", pub)
	}
}
