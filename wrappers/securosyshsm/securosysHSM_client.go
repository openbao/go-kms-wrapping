// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package securosyshsm

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2"
	helpers "github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/helpers"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

const (
	EnvAdditionalAuthenticationData = "SECUROSYSHSM_ADDITIONAL_AUTHENTICATION_DATA"
	EnvTagLength                    = "SECUROSYSHSM_TAG_LENGTH"
	EnvCipherAlgorithm              = "SECUROSYSHSM_CIPHER_ALGORITHM"
)

type securosysHSMClientEncryptor interface {
	Close()
	Encrypt(plaintext string) (data []byte, err error)
	Decrypt(ciphertext string, keyVersion string, initializationVector string) (plaintext []byte, err error)
}
type SecurosysHSMClient struct {
	keystore kms.KeyStore
	key      kms.Key
	config   *Configurations
}

func newSecurosysHSMClient(logger hclog.Logger, opts *options) (*SecurosysHSMClient, *wrapping.WrapperConfig, error) {
	ctx := context.Background()
	var keyLabel, keyPassword, certPath, keyPath, approvalTimeout, auth, bearerToken, checkEvery, tsbApiEndpoint string
	var wrapperConfig *Configurations = new(Configurations)

	switch {
	case opts.withKeyLabel != "":
		keyLabel = opts.withKeyLabel
	default:
		return nil, nil, fmt.Errorf("key_label is required")
	}

	switch {
	case opts.withKeyPassword != "":
		keyPassword = opts.withKeyPassword
	}
	switch {
	case opts.withApprovalTimeout != "":
		approvalTimeout = opts.withApprovalTimeout
	default:
		approvalTimeout = "60"

	}
	var policyPart map[string]map[string]string = make(map[string]map[string]string)
	policyStr := ""
	policyType := 0

	if opts.withPolicy != "" {
		simplyPolicy := strings.Replace(opts.withPolicy, "\n", "", -1)
		policyType = 1
		policyStr = simplyPolicy
	} else if opts.withPolicyRuleUse != "" || opts.withPolicyRuleBlock != "" || opts.withPolicyRuleUnBlock != "" || opts.withPolicyRuleModify != "" {
		if opts.withPolicyRuleUse != "" {
			simplyPolicy := strings.Replace(opts.withPolicyRuleUse, "\n", "", -1)
			policyType = 2
			policyPart["use"] = make(map[string]string)
			var temp map[string]string
			err := json.Unmarshal([]byte(simplyPolicy), &temp)
			if err != nil {
				logger.Error(fmt.Sprintf("Rule 'use' is not valid. Error: %s\n", err))
				os.Exit(1)
			}
			policyPart["use"] = temp

		}
		if opts.withPolicyRuleBlock != "" {
			simplyPolicy := strings.Replace(opts.withPolicyRuleBlock, "\n", "", -1)
			policyType = 2
			policyPart["block"] = make(map[string]string)
			var temp map[string]string
			err := json.Unmarshal([]byte(simplyPolicy), &temp)
			if err != nil {
				logger.Error(fmt.Sprintf("Rule 'block' is not valid. Error: %s\n", err))
				os.Exit(1)
			}
			policyPart["block"] = temp
		}
		if opts.withPolicyRuleUnBlock != "" {
			simplyPolicy := strings.Replace(opts.withPolicyRuleUnBlock, "\n", "", -1)
			policyType = 2
			policyPart["unblock"] = make(map[string]string)
			var temp map[string]string
			err := json.Unmarshal([]byte(simplyPolicy), &temp)
			if err != nil {
				logger.Error(fmt.Sprintf("Rule 'unblock' is not valid. Error: %s\n", err))
				os.Exit(1)
			}
			policyPart["unblock"] = temp
		}
		if opts.withPolicyRuleModify != "" {
			simplyPolicy := strings.Replace(opts.withPolicyRuleModify, "\n", "", -1)
			policyType = 2
			policyPart["modify"] = make(map[string]string)
			var temp map[string]string
			err := json.Unmarshal([]byte(simplyPolicy), &temp)
			if err != nil {
				logger.Error(fmt.Sprintf("Rule 'modify' is not valid. Error: %s\n", err))
				os.Exit(1)
			}
			policyPart["modify"] = temp
		}
	} else if opts.withFullPolicy != "" {
		policyStr = opts.withFullPolicy
		policyType = 0
	} else if opts.withFullPolicyFile != "" {
		policyFilePath := opts.withFullPolicyFile
		data, err := os.ReadFile(policyFilePath)
		if err != nil {
			logger.Error(fmt.Sprintf("Error on reading policy file. Error: %s\n", err))
			os.Exit(1)
		}
		policyStr = string(data[:])
		policyType = 0
	} else {
		policyType = 1
		policyStr = "{}"
	}
	if policyType == 0 {
		var err error
		wrapperConfig.Policy, err = helpers.PreparePolicy(policyStr, false)
		if err != nil {
			logger.Error(fmt.Sprintf("Something wrong on full policy json. Error: %s\n", err))
			os.Exit(1)
		}
	} else {
		var err error
		wrapperConfig.Policy, err = helpers.PreparePolicy(policyStr, true)
		if err != nil {
			logger.Error(fmt.Sprintf("Something wrong on policy. Error: %s\n", err))
			os.Exit(1)
		}
	}

	switch {
	case opts.withAuth != "":
		auth = opts.withAuth
	default:
		return nil, nil, fmt.Errorf("auth is required")
	}
	switch {
	case opts.withBearerToken != "":
		bearerToken = opts.withBearerToken
	}
	switch {
	case opts.withCertPath != "":
		certPath = opts.withCertPath
	}
	switch {
	case opts.withKeyPath != "":
		keyPath = opts.withKeyPath
	}
	switch {
	case opts.withCheckEvery != "":
		checkEvery = opts.withCheckEvery
	}
	switch {
	case opts.withTSBApiEndpoint != "":
		tsbApiEndpoint = opts.withTSBApiEndpoint
	default:
		return nil, nil, fmt.Errorf("tsb_api_endpoint is required")
	}
	var keyPair KeyPair
	json.Unmarshal([]byte(opts.withApplicationKeyPair), &keyPair)
	var apiKeys ApiKeyTypes
	json.Unmarshal([]byte(opts.withApiKeys), &apiKeys)

	wrapperConfig.Settings.RestApi = tsbApiEndpoint
	wrapperConfig.Settings.Auth = auth
	wrapperConfig.Settings.BearerToken = bearerToken
	wrapperConfig.Settings.CertPath = certPath
	wrapperConfig.Settings.KeyPath = keyPath
	wrapperConfig.Key.RSALabel = keyLabel
	wrapperConfig.Key.RSAPassword = keyPassword
	wrapperConfig.Settings.ApplicationKeyPair = keyPair
	wrapperConfig.Settings.ApiKeys = apiKeys
	configuration = wrapperConfig

	data, err := strconv.Atoi(checkEvery)
	if err == nil {
		wrapperConfig.Settings.CheckEvery = data
	}
	data, err = strconv.Atoi(approvalTimeout)
	if err == nil {
		wrapperConfig.Settings.ApprovalTimeout = data
	}
	valid := wrapperConfig.checkConfigFile()
	if !valid {
		os.Exit(1)
	}
	provider := map[string]interface{}{
		"restapi":     wrapperConfig.Settings.RestApi,
		"auth":        wrapperConfig.Settings.Auth,
		"bearertoken": wrapperConfig.Settings.BearerToken,
		"certpath":    wrapperConfig.Settings.CertPath,
		"keypath":     wrapperConfig.Settings.KeyPath,
		"apikeys":     wrapperConfig.Settings.ApiKeys,
	}

	keystore, err := securosyshsm.NewKeyStore(provider)
	if err != nil {
		return nil, nil, err
	}
	client := &SecurosysHSMClient{
		keystore: keystore,
	}

	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["tsb_api_endpoint"] = tsbApiEndpoint
	wrapConfig.Metadata["check_every"] = checkEvery
	wrapConfig.Metadata["key_label"] = keyLabel
	wrapConfig.Metadata["auth"] = auth
	// wrapConfig.Metadata["bearer_token"] = bearerToken
	// wrapConfig.Metadata["cert_path"] = certPath
	// wrapConfig.Metadata["key_path"] = keyPath
	wrapConfig.Metadata["approval_timeout"] = approvalTimeout
	// wrapConfig.Metadata["key_password"] = keyPassword

	key, err := client.keystore.GetKeyByName(ctx, keyLabel)

	if key == nil {
		toMap, err := securosyshsm.PolicyToMap(wrapperConfig.Policy)
		if err != nil {
			return nil, nil, err
		}
		newKey, _, err := keystore.GenerateKeyPair(ctx, &kms.KeyAttributes{
			ProviderSpecific: toMap,
			KeyType:          kms.KeyType_RSA_Private,
			Name:             keyLabel,
			BitKeyLen:        2048,
			IsRemovable:      true,
			IsSensitive:      true,
			CanEncrypt:       true,
			CanDecrypt:       true,
			CanSign:          true,
			CanVerify:        true,
			CanWrap:          true,
			CanUnwrap:        true,
			IsTrusted:        true,
		})
		if newKey == nil {
			return client, wrapConfig, fmt.Errorf("Error on creating RSA Key: %s", err)
		}
		client.key = newKey
	} else {
		client.key = key
	}
	client.config = wrapperConfig

	return client, wrapConfig, nil
}

func (c *SecurosysHSMClient) Encrypt(plaintext string) ([]byte, error) {
	ctx := context.Background()
	ctx = securosyshsm.WithPrivateKey(ctx, c.key.(*securosyshsm.PrivateKey))

	cipher, err := securosyshsm.CipherFactory{}.NewCipher(ctx, kms.CipherOp_Encrypt, &kms.CipherParameters{
		Algorithm: kms.CipherMode_RSA_OAEP_SHA256,
	})
	if err != nil {
		return nil, err
	}
	encrypted, err := cipher.Close(ctx, []byte(plaintext))
	if err != nil {
		return nil, err
	}
	encryptedBase64 := base64.StdEncoding.EncodeToString(encrypted)
	return []byte(fmt.Sprintf("securosys:%s:%s:%s", "v1", encryptedBase64, nil)), nil
}

func (c *SecurosysHSMClient) Decrypt(encryptedPayload string, keyVersion string, initializationVector string) ([]byte, error) {
	ctx := context.Background()
	ctx = securosyshsm.WithPrivateKey(ctx, c.key.(*securosyshsm.PrivateKey))
	cipher, err := securosyshsm.CipherFactory{}.NewCipher(ctx, kms.CipherOp_Decrypt, &kms.CipherParameters{
		Algorithm: kms.CipherMode_RSA_OAEP_SHA256,
	})
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedPayload)
	if cc, ok := cipher.(*securosyshsm.Cipher); ok {
		_, err2 := cc.Update(ctx, encryptedBytes)
		if err2 != nil {
			return nil, err2
		}
		requestId, err := cc.DecryptAsyncRequest(map[string]string{
			"app": "OpenBao - Unseal Operation",
		})
		if err != nil {
			return nil, err
		}
		resp, err := cc.GetRequest(requestId)

		if err != nil {
			return nil, err
		}
		// Create a context to handle Ctrl+C
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigs
			logger.Warn("Interrupt received, stopping approval wait loop...")
			cancel()
		}()
		start := time.Now()
		for resp.Status == "PENDING" {
			select {
			case <-ctx.Done():
				logger.Error(fmt.Sprintf("Unseal operation interrupted by user"))
				return nil, ctx.Err()
			default:
				now := time.Now()
				if now.Unix()-start.Unix() >= int64(c.config.Settings.ApprovalTimeout) {
					logger.Error(fmt.Sprintf("Timeout for all approvals exceeded a %ss. Application will be closed. Vault remains sealed.", strconv.Itoa(c.config.Settings.ApprovalTimeout)))
					os.Exit(1)
				}
				time.Sleep(time.Duration(c.config.Settings.CheckEvery) * time.Second)
				if len(resp.NotYetApprovedBy) > 0 {
					logger.Info(fmt.Sprintf("Waiting for %d approval:", len(resp.NotYetApprovedBy)))
				} else {
					logger.Info("All approval collected!")
				}

				for _, approver := range resp.NotYetApprovedBy {
					logger.Info(fmt.Sprintf("- %s", c.getApproverName(approver)))
				}
				resp, err = cc.GetRequest(requestId)
			}
		}
		if resp.Status == "REJECTED" {
			logger.Error(fmt.Sprintf("\nUnseal operation is %s", resp.Status))
			logger.Error(fmt.Sprintf("Rejected by:"))
			for _, approver := range resp.RejectedBy {
				logger.Error(fmt.Sprintf("- %s\n", c.getApproverName(approver)))
			}
			logger.Error(fmt.Sprintf("Application will be closed. Vault remains sealed."))
			os.Exit(1)
		}
		if len(resp.NotYetApprovedBy) > 0 {
			logger.Info(fmt.Sprintf("Waiting for %d approval:", len(resp.NotYetApprovedBy)))
		} else {
			logger.Info("All approval collected!")
		}

		for _, approver := range resp.NotYetApprovedBy {
			logger.Info(fmt.Sprintf("- %s", c.getApproverName(approver)))
		}

		return []byte(resp.Result), nil
	}
	return nil, err
}
func (c *SecurosysHSMClient) getApproverName(publicKey string) string {
	policy, err := securosyshsm.MapToPolicy(c.key.GetKeyAttributes().ProviderSpecific)
	if err != nil {
		return ""
	}
	if len(policy.RuleUse.Tokens) > 0 {
		for _, token := range policy.RuleUse.Tokens {
			if len(token.Groups) > 0 {
				for _, group := range token.Groups {
					if len(group.Approvals) > 0 {
						for _, approval := range group.Approvals {
							if publicKey == *approval.Value {
								return *approval.Name
							}
							cert, err := ReadCertificate(*approval.Value)
							if err == nil {

								key := BytesToPublicKey([]byte("-----BEGIN RSA PUBLIC KEY-----\n" + publicKey + "\n-----END RSA PUBLIC KEY-----"))
								if cert.PublicKey.(*rsa.PublicKey).N.Cmp(key.N) == 0 && key.E == cert.PublicKey.(*rsa.PublicKey).E {
									return *approval.Name
								}
							}
						}
					}
				}
			}
		}
	}
	return ""
}

func BytesToPublicKey(pub []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			logger.Error(err.Error())
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		logger.Error(err.Error())
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		logger.Error("not ok")
	}
	return key
}
