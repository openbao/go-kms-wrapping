// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	helpers "github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/helpers"
)

// Function thats send wrap request to TSB
func (c *TSBClient) Wrap(wrapKeyName string, wrapKeyPassword string, keyToBeWrapped string, keyToBeWrappedPassword string, wrapMethod string) (*helpers.WrapResponse, int, error) {
	keyToBeWrappedPasswordJson, _ := json.Marshal(helpers.StringToCharArray(keyToBeWrappedPassword))
	wrapKeyPasswordJson, _ := json.Marshal(helpers.StringToCharArray(wrapKeyPassword))
	keyToBeWrappedPasswordString := ""
	if len(keyToBeWrappedPasswordJson) > 2 {
		keyToBeWrappedPasswordString = `"keyToBeWrappedPassword": ` + string(keyToBeWrappedPasswordJson) + `,`

	}
	wrapKeyPasswordString := ""
	if len(wrapKeyPasswordJson) > 2 {
		wrapKeyPasswordString = `"wrapKeyPassword": ` + string(wrapKeyPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"wrapKeyRequest": {
		"keyToBeWrapped": "` + keyToBeWrapped + `",
		` + keyToBeWrappedPasswordString + `
		  "wrapKeyName": "` + wrapKeyName + `",
		  ` + wrapKeyPasswordString + `
		  "wrapMethod":"` + wrapMethod + `"
		}
	  }`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/wrap", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var response helpers.WrapResponse
	// response.KeyID = signKeyName
	// response.CertificateRequest = string(body)
	json.Unmarshal(body, &response)
	return &response, code, nil

}

// Function thats sends asynchronous unwrap request to TSB
func (c *TSBClient) AsyncUnWrap(wrappedKey string, label string, attributes map[string]bool, unwrapKeyName string, unwrapKeyPassword string, wrapMethod string, policy *helpers.Policy, customMetaData map[string]string) (string, int, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(unwrapKeyPassword))
	var additionalMetaDataInfo map[string]string = make(map[string]string)
	additionalMetaDataInfo["wrapped key"] = wrappedKey
	additionalMetaDataInfo["new key label"] = label
	additionalMetaDataInfo["wrap method"] = wrapMethod
	additionalMetaDataInfo["attributes"] = fmt.Sprintf("%v", attributes)
	var policyString string
	if policy == nil {
		policyString = string(`,"policy":null`)
	} else {
		policyJson, _ := json.Marshal(*policy)
		policyString = string(`,"policy":` + string(policyJson))
	}

	if attributes["extractable"] {
		policyString = string(`,"policy":null`)
	}
	//Only for asychronous unwrap
	policyString = string(``)
	metaDataB64, metaDataSignature, err := c.PrepareMetaData("UnWrap", additionalMetaDataInfo, customMetaData)
	if err != nil {
		return "", 500, err
	}
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"unwrapKeyPassword": ` + string(charsPasswordJson) + `,`

	}
	metaDataSignatureString := "null"
	if metaDataSignature != nil {
		metaDataSignatureString = `"` + *metaDataSignature + `"`

	}
	requestJson := `{
		"wrappedKey": "` + wrappedKey + `",
		"label": "` + label + `",
		"unwrapKeyName": "` + unwrapKeyName + `",
		` + passwordString + `
		"wrapMethod": "` + wrapMethod + `",
		"attributes": ` + helpers.PrepareAttributes(attributes) + `,
		"metaData": "` + metaDataB64 + `",
		"metaDataSignature": ` + metaDataSignatureString + `` + policyString + `
		}`
	var jsonStr = []byte(helpers.MinifyJson(`{
			"unwrapKeyRequest": ` + requestJson + `,
			"requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `
		}`))
	req, err := http.NewRequest("POST", c.HostURL+"/v1/unwrap", bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return "", code, errRes
	}
	var result map[string]interface{}
	errJSON := json.Unmarshal(body, &result)
	if errJSON != nil {
		return "", code, errJSON
	}
	return result["unwrapRequestId"].(string), code, nil
}

// Function thats sends unwrap request to TSB
func (c *TSBClient) UnWrap(wrappedKey string, label string, attributes map[string]bool, unwrapKeyName string, unwrapKeyPassword string, wrapMethod string, policy *helpers.Policy) (int, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(unwrapKeyPassword))
	var policyString string
	if policy == nil {
		policyString = string(`,"policy":null`)
	} else {
		policyJson, _ := json.Marshal(policy)
		policyString = string(`,"policy":` + string(policyJson))
	}
	if attributes["extractable"] {
		policyString = string(`,"policy":null`)
	}
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"unwrapKeyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"unwrapKeyRequest": {
		"wrappedKey": "` + wrappedKey + `",
		"label": "` + label + `",
		"unwrapKeyName": "` + unwrapKeyName + `",
		` + passwordString + `
		"wrapMethod": "` + wrapMethod + `",
		"attributes": ` + helpers.PrepareAttributes(attributes) + policyString + `
		}}`)
	req, err := http.NewRequest("POST", c.HostURL+"/v1/synchronousUnwrap", bytes.NewBuffer(jsonStr))
	if err != nil {
		return 500, err
	}
	_, code, err := c.doRequest(req, KeyOperationTokenName)
	return code, err
}
