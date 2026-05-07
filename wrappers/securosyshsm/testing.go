// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"context"
	"os"

	securosyskms "github.com/openbao/go-kms-wrapping/kms/securosyshsm/v2"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

var SECUROSYS_HSM_RESTAPI_ENV_VAR = "SECUROSYS_HSM_RESTAPI"
var SECUROSYS_BEARER_TOKEN_ENV_VAR = "SECUROSYS_BEARER_TOKEN"

const SECUROSYS_HSM_TEST_KEY_LABEL = "rsa_openbao_wrapper_test_key"
const SECUROSYS_HSM_TEST_AUTH_TYPE = "TOKEN"

// NewSecurosysHSMTestWrapper opens a wrapper backed by the configured test HSM
// key. It returns nil when the HSM cannot be opened or the test key does not
// exist.
func NewSecurosysHSMTestWrapper() *Wrapper {
	ctx := context.Background()
	s := NewWrapper()

	wrapperConfig := new(Configurations)
	wrapperConfig.Settings.RestApi = os.Getenv(SECUROSYS_HSM_RESTAPI_ENV_VAR)
	wrapperConfig.Settings.Auth = SECUROSYS_HSM_TEST_AUTH_TYPE
	wrapperConfig.Settings.BearerToken = os.Getenv(SECUROSYS_BEARER_TOKEN_ENV_VAR)
	wrapperConfig.Key.RSALabel = SECUROSYS_HSM_TEST_KEY_LABEL
	wrapperConfig.Settings.CheckEvery = 5
	wrapperConfig.Settings.ApprovalTimeout = 60
	configuration = wrapperConfig

	providerKMS := securosyskms.New()
	if err := providerKMS.Open(ctx, &kms.OpenOptions{ConfigMap: securosysKMSConfigMap(wrapperConfig)}); err != nil {
		return nil
	}
	key, err := providerKMS.GetKey(ctx, &kms.KeyOptions{
		ConfigMap: kms.ConfigMap{
			"name": SECUROSYS_HSM_TEST_KEY_LABEL,
		},
	})
	if err != nil {
		_ = providerKMS.Close(ctx)
		return nil
	}

	client := &SecurosysHSMClient{
		kms:      providerKMS,
		key:      key,
		keyLabel: SECUROSYS_HSM_TEST_KEY_LABEL,
		config:   wrapperConfig,
	}
	s.hsmClient = client
	s.client = client
	return s
}
