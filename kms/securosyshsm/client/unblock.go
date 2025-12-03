// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package client

import (
	"bytes"
	"encoding/json"
	"net/http"

	helpers "github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/helpers"
)

// Function thats send unblock request to TSB
func (c *TSBClient) UnBlock(label string, password string) (int, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"unblockRequest": {
		` + passwordString + `
		  "unblockKeyName": "` + label + `"
		}
	  }`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/synchronousUnblock", bytes.NewBuffer(jsonStr))
	if err != nil {
		return 500, err
	}
	_, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return code, errRes
	}
	return code, nil

}

// Function thats send asynchronous unblock request to TSB
func (c *TSBClient) AsyncUnBlock(label string, password string, customMetaData map[string]string) (string, int, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	var additionalMetaDataInfo map[string]string = make(map[string]string)
	metaDataB64, metaDataSignature, err := c.PrepareMetaData("UnBlock", additionalMetaDataInfo, customMetaData)
	if err != nil {
		return "", 500, err
	}
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}
	metaDataSignatureString := "null"
	if metaDataSignature != nil {
		metaDataSignatureString = `"` + *metaDataSignature + `"`

	}
	requestJson := `{
		"unblockKeyName": "` + label + `",
		` + passwordString + `
		"metaData": "` + metaDataB64 + `",
		"metaDataSignature": ` + metaDataSignatureString + `
	  }`
	var jsonStr = []byte(helpers.MinifyJson(`{
		"unblockRequest": ` + requestJson + `,
		"requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `
	  }`))

	req, err := http.NewRequest("POST", c.HostURL+"/v1/unblock", bytes.NewBuffer(jsonStr))
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
	return result["unblockKeyRequestId"].(string), code, nil
}
