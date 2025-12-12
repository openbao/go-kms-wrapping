// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"context"

	"github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

const SECUROSYS_HSM_TEST_KEY_LABEL = "rsa_openbao_wrapper_test_key"
const SECUROSYS_HSM_TEST_AUTH_TYPE = "TOKEN"
const SECUROSYS_HSM_TEST_BEARER_TOKEN = ""
const SECUROSYS_HSM_TEST_TSB_URL = "tsb_url"

func NewSecurosysHSMTestWrapper() *Wrapper {
	ctx := context.Background()
	s := NewWrapper()
	provider := map[string]interface{}{
		"restapi": SECUROSYS_HSM_TEST_TSB_URL,
		"auth":    SECUROSYS_HSM_TEST_AUTH_TYPE,
	}
	var wrapperConfig *Configurations = new(Configurations)
	wrapperConfig.Settings.RestApi = SECUROSYS_HSM_TEST_TSB_URL
	wrapperConfig.Settings.Auth = SECUROSYS_HSM_TEST_AUTH_TYPE
	wrapperConfig.Settings.BearerToken = SECUROSYS_HSM_TEST_BEARER_TOKEN
	wrapperConfig.Key.RSALabel = SECUROSYS_HSM_TEST_KEY_LABEL
	wrapperConfig.Settings.CheckEvery = 5
	wrapperConfig.Settings.ApprovalTimeout = 60
	configuration = wrapperConfig

	keystore, err := securosyshsm.NewKeyStore(provider)
	if err != nil {
		return nil
	}
	client := &SecurosysHSMClient{
		keystore: keystore,
	}
	client.config = wrapperConfig
	key, err := client.keystore.GetKeyByName(ctx, SECUROSYS_HSM_TEST_KEY_LABEL)

	if key == nil {
		newKey, _, _ := keystore.GenerateKeyPair(ctx, &kms.KeyAttributes{
			ProviderSpecific: nil,
			KeyType:          kms.KeyType_RSA_Private,
			Name:             SECUROSYS_HSM_TEST_KEY_LABEL,
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
		client.key = newKey
	} else {
		client.key = key
	}

	s.hsmClient = client
	return s
}
