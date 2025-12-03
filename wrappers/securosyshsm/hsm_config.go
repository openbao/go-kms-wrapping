// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package securosyshsm

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hashicorp/go-hclog"
	securosyskms "github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2"
)

const (
	NONE  string = "NONE"
	TOKEN string = "TOKEN"
	CERT  string = "CERT"
)

var logger hclog.Logger = hclog.New(&hclog.LoggerOptions{
	Name: fmt.Sprintf("securosys-hsm-seal")})

var Logs Logging

// Variable that stores entire configuration from yaml file
var configuration *Configurations

// This function validating a config_hsm.yml file
func (config *Configurations) checkConfigFile() bool {
	var valid bool = true
	var errors []string
	if config.Settings.CheckEvery == 0 {
		valid = false
		errors = append(errors, "check_every must be bigger then 0")
	}
	if config.Settings.ApprovalTimeout == 0 {
		valid = false
		errors = append(errors, "approval_timeout must be bigger then 0 and lower then VAULT_CLIENT_TIMEOUT. Default is 60 (seconds)\nYou can override this value by setting environment variable VAULT_CLIENT_TIMEOUT")
	}
	if config.Settings.ApprovalTimeout <= config.Settings.CheckEvery {
		valid = false
		errors = append(errors, "approval_timeout must be bigger then check_every")
	}
	if config.Settings.Auth == "" {
		valid = false
		errors = append(errors, "auth is empty. Must be the one of this values [TOKEN,CERT,NONE]")
	}
	if config.Settings.Auth != TOKEN && config.Settings.Auth != CERT && config.Settings.Auth != NONE {
		valid = false
		errors = append(errors, "auth must be the one of this values [TOKEN,CERT,NONE]")
	}
	if config.Settings.Auth == TOKEN {
		if config.Settings.BearerToken == "" {
			valid = false
			errors = append(errors, "bearer_token is empty")
		}
	}
	if config.Settings.Auth == CERT {
		if config.Settings.CertPath == "" {
			valid = false
			errors = append(errors, "cert_path is empty")
		} else {
			_, err := os.ReadFile(config.Settings.CertPath)
			if err != nil {
				valid = false
				errors = append(errors, "cert_path error on "+err.Error())
			}
		}
		if config.Settings.KeyPath == "" {
			valid = false
			errors = append(errors, "key_path is empty")
		} else {
			_, err := os.ReadFile(config.Settings.KeyPath)
			if err != nil {
				valid = false
				errors = append(errors, "key_path error on "+err.Error())
			}
		}
	}
	jsonBytes, _ := json.Marshal(config.Settings.ApiKeys)
	jsonStr := string(jsonBytes)
	provider := map[string]interface{}{
		"restapi":     config.Settings.RestApi,
		"auth":        config.Settings.Auth,
		"bearertoken": config.Settings.BearerToken,
		"certpath":    config.Settings.CertPath,
		"keypath":     config.Settings.KeyPath,
		"apikeys":     jsonStr,
	}
	_, err := securosyskms.NewKeyStore(provider)
	if err != nil {
		logger.Error("Can't initialize securosy kms provider: %s", err.Error())
		return false
	}

	if !valid {
		for _, element := range errors {
			logger.Error(fmt.Sprintf("ERROR: %s\n", element))
		}
		logger.Error("Seal Configuration [securosys-hsm] is not valid:")

		for _, element := range errors {
			logger.Error("Seal Configuration [securosys-hsm] is not valid:")
			logger.Error(fmt.Sprintf(" - %s\n", element))
		}
	}
	return valid
}
