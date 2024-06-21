// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// heavily inspired and adapted from ceph's internal kmip package
// https://github.com/ceph/ceph-csi/blob/devel/internal/kms/kmip.go

package kmip

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gemalto/kmip-go"
	"github.com/gemalto/kmip-go/kmip14"
	"github.com/gemalto/kmip-go/ttlv"
	uuid "github.com/hashicorp/go-uuid"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// These constants contain the accepted env vars; the Vault one is for backwards compat
const (
	EnvKmipWrapperKeyId   = "KMIP_WRAPPER_KEY_ID"
	EnvVaultKmipSealKeyId = "VAULT_KMIP_SEAL_KEY_ID"
)

const (
	// KMIP version.
	protocolMajor = 1
	protocolMinor = 4
	nonceSize     = 16
)

// Wrapper is a Wrapper that uses KMIP
type Wrapper struct {
	client       *kmipKMS
	keyId        string
	currentKeyId *atomic.Value
	serverName   string
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new KMIP Wrapper
func NewWrapper() *Wrapper {
	k := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	k.currentKeyId.Store("")
	return k
}

// SetConfig sets the fields on the KmipWrapper object based on
// values from the config parameter.
//
// Order of precedence Kmip values:
// * Environment variable
// * Value from Vault configuration file
// * Instance metadata role (access key and secret key)
func (k *Wrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	// Check and set KeyId
	switch {
	case os.Getenv(EnvKmipWrapperKeyId) != "" && !opts.Options.WithDisallowEnvVars:
		k.keyId = os.Getenv(EnvKmipWrapperKeyId)
	case os.Getenv(EnvVaultKmipSealKeyId) != "" && !opts.Options.WithDisallowEnvVars:
		k.keyId = os.Getenv(EnvVaultKmipSealKeyId)
	case opts.WithKeyId != "":
		k.keyId = opts.WithKeyId
	default:
		return nil, fmt.Errorf("key id not found (env or config) for kmip wrapper configuration")
	}

	// Set and check k.client
	if k.client == nil {
		k.client = &kmipKMS{}

		if !opts.Options.WithDisallowEnvVars {
			k.client.endpoint = os.Getenv("KMIP_ENDPOINT")
		}
		if k.client.endpoint == "" {
			k.client.endpoint = opts.withEndpoint
		}

		caCertFile := ""
		if !opts.Options.WithDisallowEnvVars {
			caCertFile = os.Getenv("KMIP_CA_CERT")
		}
		if caCertFile == "" {
			caCertFile = opts.withCaCert
		}

		caCert, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert file: %w", err)
		}

		clientCertFile := ""
		if !opts.Options.WithDisallowEnvVars {
			clientCertFile = os.Getenv("KMIP_CLIENT_CERT")
		}
		if clientCertFile == "" {
			clientCertFile = opts.withClientCert
		}

		clientCert, err := os.ReadFile(clientCertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client cert file: %w", err)
		}

		clientKeyFile := ""
		if !opts.Options.WithDisallowEnvVars {
			clientKeyFile = os.Getenv("KMIP_CLIENT_KEY")
		}
		if clientKeyFile == "" {
			clientKeyFile = opts.withClientKey
		}

		clientKey, err := os.ReadFile(clientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client key file: %w", err)
		}

		k.serverName = ""
		if !opts.Options.WithDisallowEnvVars {
			k.serverName = os.Getenv("KMIP_SERVER_NAME")
		}
		if k.serverName == "" {
			k.serverName = opts.withServerName
		}

		k.client.uniqueIdentifier = k.keyId

		if !opts.Options.WithDisallowEnvVars {
			timeoutString := os.Getenv("KMIP_READ_TIMEOUT")
			timeout := uint64(0)
			if timeoutString != "" {
				var err error
				timeout, err = strconv.ParseUint(timeoutString, 10, 64)
				if err != nil {
					return nil, err
				}
			}
			k.client.readTimeout = uint8(timeout)
		}
		if k.client.readTimeout == 0 {
			k.client.readTimeout = opts.withReadTimeout
		}

		if !opts.Options.WithDisallowEnvVars {
			timeoutString := os.Getenv("KMIP_WRITE_TIMEOUT")
			timeout := uint64(0)
			if timeoutString != "" {
				var err error
				timeout, err = strconv.ParseUint(timeoutString, 10, 64)
				if err != nil {
					return nil, err
				}
			}
			k.client.writeTimeout = uint8(timeout)
		}
		if k.client.writeTimeout == 0 {
			k.client.writeTimeout = opts.withWriteTimeout
		}

		caCertPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to get system cert pool: %w", err)
		}
		caCertPool.AppendCertsFromPEM(caCert)
		cert, err := tls.X509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("invalid X509 key pair: %w", err)
		}

		k.client.tlsConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			ServerName:   k.serverName,
			RootCAs:      caCertPool,
			Certificates: []tls.Certificate{cert},
		}
		conn, err := tls.Dial("tcp", k.client.endpoint, k.client.tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to dial kmip connection endpoint: %w", err)
		}
		defer conn.Close()
	}
	// Store the current key id. If using a key alias, this will point to the actual
	// unique key that that was used for this encrypt operation.
	k.currentKeyId.Store(k.keyId)

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["kms_key_id"] = k.keyId
	wrapConfig.Metadata["endpoint"] = k.client.endpoint
	wrapConfig.Metadata["read_timeout"] = strconv.Itoa(int(k.client.readTimeout))
	wrapConfig.Metadata["write_timeout"] = strconv.Itoa(int(k.client.writeTimeout))
	if k.serverName != "" {
		wrapConfig.Metadata["server_name"] = k.serverName
	}

	return wrapConfig, nil
}

// Type returns the type for this particular wrapper implementation
func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeKmip, nil
}

// KeyId returns the last known key id
func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.currentKeyId.Load().(string), nil
}

// Encrypt is used to encrypt the master key using the the KMIP.
// This returns the ciphertext, and/or any errors from this
// call. This should be called after the KMS client has been instantiated.
func (k *Wrapper) Encrypt(_ context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	WrappedKey, err := k.client.EncryptDEK(context.Background(), nil, env.Key)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	// Store the current key id.
	k.currentKeyId.Store(k.keyId)

	ret := &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			KeyId:      k.keyId,
			WrappedKey: WrappedKey,
		},
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext. This should be called after Init.
func (k *Wrapper) Decrypt(_ context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, fmt.Errorf("given input for decryption is nil")
	}

	keyBytes, err := k.client.DecryptDEK(context.Background(), nil, in.KeyInfo.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data encryption key: %w", err)
	}

	envInfo := &wrapping.EnvelopeInfo{
		Key:        keyBytes,
		Iv:         in.Iv,
		Ciphertext: in.Ciphertext,
	}
	plaintext, err := wrapping.EnvelopeDecrypt(envInfo, opt...)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return plaintext, nil
}

type kmipKMS struct {
	// standard KMIP configuration options
	endpoint         string
	tlsConfig        *tls.Config
	uniqueIdentifier string
	readTimeout      uint8
	writeTimeout     uint8
}

// EncryptDEK uses the KMIP encrypt operation to encrypt the DEK.
func (kms *kmipKMS) EncryptDEK(ctx context.Context, nonce []byte, plainDEK []byte) ([]byte, error) {
	conn, err := kms.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var iv []byte
	iv, err = uuid.GenerateRandomBytes(nonceSize)
	if err != nil {
		return nil, err
	}
	respMsg, decoder, uniqueBatchItemID, err := kms.send(conn,
		kmip14.OperationEncrypt,
		EncryptRequestPayload{
			UniqueIdentifier: kms.uniqueIdentifier,
			Data:             append(iv, plainDEK...),
			CryptographicParameters: kmip.CryptographicParameters{
				PaddingMethod:          kmip14.PaddingMethodPKCS5,
				CryptographicAlgorithm: kmip14.CryptographicAlgorithmAES,
				BlockCipherMode:        kmip14.BlockCipherModeCBC,
			},
			IVCounterNonce: iv,
		})
	if err != nil {
		return nil, err
	}

	batchItem, err := kms.verifyResponse(respMsg, kmip14.OperationEncrypt, uniqueBatchItemID)
	if err != nil {
		return nil, err
	}

	ttlvPayload, ok := batchItem.ResponsePayload.(ttlv.TTLV)
	if !ok {
		return nil, errors.New("failed to parse responsePayload")
	}

	var encryptRespPayload EncryptResponsePayload
	err = decoder.DecodeValue(&encryptRespPayload, ttlvPayload)
	if err != nil {
		return nil, err
	}

	return encryptRespPayload.Data, nil
}

// DecryptDEK uses the KMIP decrypt operation  to decrypt the DEK.
func (kms *kmipKMS) DecryptDEK(ctx context.Context, nonce []byte, encryptedDEK []byte) ([]byte, error) {
	conn, err := kms.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if len(encryptedDEK) < nonceSize {
		return nil, errors.New("invalid encrypted DEK")
	}

	respMsg, decoder, uniqueBatchItemID, err := kms.send(conn,
		kmip14.OperationDecrypt,
		DecryptRequestPayload{
			UniqueIdentifier: kms.uniqueIdentifier,
			Data:             encryptedDEK[nonceSize:],
			IVCounterNonce:   encryptedDEK[:nonceSize],
			CryptographicParameters: kmip.CryptographicParameters{
				PaddingMethod:          kmip14.PaddingMethodPKCS5,
				CryptographicAlgorithm: kmip14.CryptographicAlgorithmAES,
				BlockCipherMode:        kmip14.BlockCipherModeCBC,
			},
		})
	if err != nil {
		return nil, err
	}

	batchItem, err := kms.verifyResponse(respMsg, kmip14.OperationDecrypt, uniqueBatchItemID)
	if err != nil {
		return nil, err
	}

	ttlvPayload, ok := batchItem.ResponsePayload.(ttlv.TTLV)
	if !ok {
		return nil, errors.New("failed to parse responsePayload")
	}

	var decryptRespPayload DecryptRequestPayload
	err = decoder.DecodeValue(&decryptRespPayload, ttlvPayload)
	if err != nil {
		return nil, err
	}

	return decryptRespPayload.Data, nil
}

// connect to the kmip endpoint, perform TLS and KMIP handshakes.
func (kms *kmipKMS) connect() (*tls.Conn, error) {
	conn, err := tls.Dial("tcp", kms.endpoint, kms.tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial kmip connection endpoint: %w", err)
	}
	if kms.readTimeout != 0 {
		err = conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(kms.readTimeout)))
		if err != nil {
			return nil, fmt.Errorf("failed to set read deadline: %w", err)
		}
	}
	if kms.writeTimeout != 0 {
		err = conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(kms.writeTimeout)))
		if err != nil {
			return nil, fmt.Errorf("failed to set write deadline: %w", err)
		}
	}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	err = conn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("failed to perform connection handshake: %w", err)
	}

	err = kms.discover(conn)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// discover performs KMIP discover operation.
// https://docs.oasis-open.org/kmip/spec/v1.4/kmip-spec-v1.4.html
// chapter 4.26.
func (kms *kmipKMS) discover(conn io.ReadWriter) error {
	respMsg, decoder, uniqueBatchItemID, err := kms.send(conn,
		kmip14.OperationDiscoverVersions,
		kmip.DiscoverVersionsRequestPayload{
			ProtocolVersion: []kmip.ProtocolVersion{
				{
					ProtocolVersionMajor: protocolMajor,
					ProtocolVersionMinor: protocolMinor,
				},
			},
		})
	if err != nil {
		return err
	}

	batchItem, err := kms.verifyResponse(
		respMsg,
		kmip14.OperationDiscoverVersions,
		uniqueBatchItemID)
	if err != nil {
		return err
	}

	ttlvPayload, ok := batchItem.ResponsePayload.(ttlv.TTLV)
	if !ok {
		return errors.New("failed to parse responsePayload")
	}

	var respDiscoverVersionsPayload kmip.DiscoverVersionsResponsePayload
	err = decoder.DecodeValue(&respDiscoverVersionsPayload, ttlvPayload)
	if err != nil {
		return err
	}

	if len(respDiscoverVersionsPayload.ProtocolVersion) != 1 {
		return fmt.Errorf("invalid len of discovered protocol versions %v expected 1",
			len(respDiscoverVersionsPayload.ProtocolVersion))
	}
	pv := respDiscoverVersionsPayload.ProtocolVersion[0]
	if pv.ProtocolVersionMajor != protocolMajor || pv.ProtocolVersionMinor != protocolMinor {
		return fmt.Errorf("invalid discovered protocol version %v.%v expected %v.%v",
			pv.ProtocolVersionMajor, pv.ProtocolVersionMinor, protocolMajor, protocolMinor)
	}

	return nil
}

// send sends KMIP operation over tls connection, returns
// kmip response message,
// ttlv Decoder to decode message into desired format,
// batchItem ID,
// and error.
func (kms *kmipKMS) send(
	conn io.ReadWriter,
	operation kmip14.Operation,
	payload interface{},
) (*kmip.ResponseMessage, *ttlv.Decoder, []byte, error) {
	biUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, nil, nil,
			fmt.Errorf("failed to generate unique batch item ID: %w", err)
	}
	biID, err := uuid.ParseUUID(biUUID)
	if err != nil {
		return nil, nil, nil,
			fmt.Errorf("failed to parse unique batch item ID: %w", err)
	}

	msg := kmip.RequestMessage{
		RequestHeader: kmip.RequestHeader{
			ProtocolVersion: kmip.ProtocolVersion{
				ProtocolVersionMajor: protocolMajor,
				ProtocolVersionMinor: protocolMinor,
			},
			BatchCount: 1,
		},
		BatchItem: []kmip.RequestBatchItem{
			{
				UniqueBatchItemID: biID[:],
				Operation:         operation,
				RequestPayload:    payload,
			},
		},
	}

	req, err := ttlv.Marshal(msg)
	if err != nil {
		return nil, nil, nil,
			fmt.Errorf("failed to ttlv marshal message: %w", err)
	}

	_, err = conn.Write(req)
	if err != nil {
		return nil, nil, nil,
			fmt.Errorf("failed to write request onto connection: %w", err)
	}

	decoder := ttlv.NewDecoder(bufio.NewReader(conn))
	resp, err := decoder.NextTTLV()
	if err != nil {
		return nil, nil, nil,
			fmt.Errorf("failed to read ttlv KMIP value: %w", err)
	}

	var respMsg kmip.ResponseMessage
	err = decoder.DecodeValue(&respMsg, resp)
	if err != nil {
		return nil, nil, nil,
			fmt.Errorf("failed to decode response value: %w", err)
	}

	return &respMsg, decoder, biID[:], nil
}

// verifyResponse verifies the response success and return the batch item.
func (kms *kmipKMS) verifyResponse(
	respMsg *kmip.ResponseMessage,
	operation kmip14.Operation,
	uniqueBatchItemID []byte,
) (*kmip.ResponseBatchItem, error) {
	if respMsg.ResponseHeader.BatchCount != 1 {
		return nil, fmt.Errorf("batch count %q should be \"1\"",
			respMsg.ResponseHeader.BatchCount)
	}
	if len(respMsg.BatchItem) != 1 {
		return nil, fmt.Errorf("batch Intems list len %q should be \"1\"",
			len(respMsg.BatchItem))
	}
	batchItem := respMsg.BatchItem[0]
	if operation != batchItem.Operation {
		return nil, fmt.Errorf("unexpected operation, real %q expected %q",
			batchItem.Operation, operation)
	}
	if !bytes.Equal(uniqueBatchItemID, batchItem.UniqueBatchItemID) {
		return nil, fmt.Errorf("unexpected uniqueBatchItemID, real %q expected %q",
			batchItem.UniqueBatchItemID, uniqueBatchItemID)
	}
	if kmip14.ResultStatusSuccess != batchItem.ResultStatus {
		return nil, fmt.Errorf("unexpected result status %q expected success %q,"+
			"result reason %q, result message %q",
			batchItem.ResultStatus, kmip14.ResultStatusSuccess,
			batchItem.ResultReason, batchItem.ResultMessage)
	}

	return &batchItem, nil
}

// TODO: use the following structs from https://github.com/gemalto/kmip-go
// when https://github.com/ThalesGroup/kmip-go/issues/21 is resolved.
// refer: https://docs.oasis-open.org/kmip/spec/v1.4/kmip-spec-v1.4.html.
type EncryptRequestPayload struct {
	UniqueIdentifier        string
	CryptographicParameters kmip.CryptographicParameters
	Data                    []byte
	IVCounterNonce          []byte
}

type EncryptResponsePayload struct {
	UniqueIdentifier string
	Data             []byte
	IVCounterNonce   []byte
}

type DecryptRequestPayload struct {
	UniqueIdentifier        string
	CryptographicParameters kmip.CryptographicParameters
	Data                    []byte
	IVCounterNonce          []byte
}

type DecryptResponsePayload struct {
	UniqueIdentifier string
	Data             []byte
	IVCounterNonce   []byte
}
