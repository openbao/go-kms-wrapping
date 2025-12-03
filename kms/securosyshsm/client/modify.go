// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package client

import (
	"bytes"
	"encoding/json"
	"net/http"

	helpers "github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/helpers"
)

// Function thats send request modify key to TSB
func (c *TSBClient) Modify(label string, password string, policy helpers.Policy) (int, error) {
	policyJson, _ := json.Marshal(policy)
	policyString := string(`,"policy":` + string(policyJson))

	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"modifyRequest":{
			` + passwordString + `
			"modifyKeyName": "` + label + `"
			` + policyString + `}
		}`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/synchronousModify", bytes.NewBuffer(jsonStr))
	if err != nil {
		return 500, err
	}
	_, code, errRes := c.doRequest(req, KeyManagementTokenName)
	if errRes != nil {
		return code, errRes
	}
	return code, nil

}

// Function thats send asynchronous request modify key to TSB
func (c *TSBClient) AsyncModify(label string, password string, policy helpers.Policy, customMetaData map[string]string) (string, int, error) {
	var additionalMetaDataInfo map[string]string = make(map[string]string)
	metaDataB64, metaDataSignature, err := c.PrepareMetaData("Modify", additionalMetaDataInfo, customMetaData)
	if err != nil {
		return "", 500, err
	}
	policyJson, _ := json.Marshal(policy)
	policyString := string(`,"policy":` + string(policyJson))

	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}
	metaDataSignatureString := "null"
	if metaDataSignature != nil {
		metaDataSignatureString = `"` + *metaDataSignature + `"`

	}
	requestJson := `{"modifyKeyName": "` + label + `",
		` + passwordString + `
		"metaData": "` + metaDataB64 + `",
		"metaDataSignature": ` + metaDataSignatureString + `
		  ` + policyString + `}`
	var jsonStr = []byte(helpers.MinifyJson(`{
		"modifyRequest":` + requestJson + `,
		"requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `
		}`))
	req, err := http.NewRequest("POST", c.HostURL+"/v1/modify", bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", 500, err
	}
	body, code, errRes := c.doRequest(req, KeyManagementTokenName)
	if errRes != nil {
		return "", code, errRes
	}
	var result map[string]interface{}
	errJSON := json.Unmarshal(body, &result)
	if errJSON != nil {
		return "", code, errJSON
	}
	return result["modifyKeyRequestId"].(string), code, nil

}
