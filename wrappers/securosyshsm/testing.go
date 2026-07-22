// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"context"
	"os"
	"strings"

	securosyskms "github.com/openbao/go-kms-wrapping/kms/securosyshsm/v2"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

var (
	SECUROSYS_HSM_RESTAPI_ENV_VAR  = "SECUROSYS_HSM_RESTAPI"
	SECUROSYS_BEARER_TOKEN_ENV_VAR = "SECUROSYS_BEARER_TOKEN"
)

const (
	SECUROSYS_HSM_TEST_KEY_LABEL = "rsa_openbao_wrapper_test_key"
	SECUROSYS_HSM_TEST_AUTH_TYPE = "TOKEN"
)

// NewSecurosysHSMTestWrapper opens a wrapper backed by the configured test HSM
// key. It returns nil when the HSM cannot be opened or the test key does not
// exist.
func NewSecurosysHSMTestWrapper() *Wrapper {
	ctx := context.Background()
	s := NewWrapper()

	config := map[string]string{
		"tsb_api_endpoint": wrapperTestEnv(SECUROSYS_HSM_RESTAPI_ENV_VAR),
		"auth":             SECUROSYS_HSM_TEST_AUTH_TYPE,
		"bearer_token":     wrapperTestEnv(SECUROSYS_BEARER_TOKEN_ENV_VAR),
		"check_every":      "5",
		"approval_timeout": "60",
	}
	opts, err := getOpts(wrapping.WithConfigMap(config))
	if err != nil {
		return nil
	}

	providerKMS := securosyskms.New()
	if err := providerKMS.Open(ctx, &kms.OpenOptions{ConfigMap: securosysKMSConfigMap(opts)}); err != nil {
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
	}
	s.hsmClient = client
	s.client = client
	return s
}

func wrapperTestEnv(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}
