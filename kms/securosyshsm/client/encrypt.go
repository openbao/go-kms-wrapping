// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package client

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"

	helpers "github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/helpers"
)

// Function thats sends asynchronous decrypt request to TSB
func (c *TSBClient) AsyncDecrypt(label string, password string, cipertext string, vector string, cipherAlgorithm string, tagLength int, additionalAuthenticationData string, customMetaData map[string]string) (string, int, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))

	var additionalMetaDataInfo map[string]string = make(map[string]string)

	metaDataB64, metaDataSignature, err := c.PrepareMetaData("Decrypt", additionalMetaDataInfo, customMetaData)
	if err != nil {
		return "", 500, err
	}
	vectorString := `"` + vector + `"`
	if vector == "" {
		vectorString = "null"
	}
	additionalAuthenticationDataString := `"` + additionalAuthenticationData + `"`
	if additionalAuthenticationData == "" {
		additionalAuthenticationDataString = "null"
	}
	tagLengthString := ""
	if tagLength != -1 && cipherAlgorithm == "AES_GCM" {
		tagLengthString = `"tagLength":` + strconv.Itoa(tagLength) + `,`
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
		"encryptedPayload": "` + cipertext + `",
		` + passwordString + `
		"decryptKeyName": "` + label + `",
		"metaData": "` + metaDataB64 + `",
		"metaDataSignature": ` + metaDataSignatureString + `,
		"cipherAlgorithm": "` + cipherAlgorithm + `",
		"initializationVector": ` + vectorString + `,
		` + tagLengthString + `
		"additionalAuthenticationData":` + additionalAuthenticationDataString + `
	  }`

	var jsonStr = []byte(helpers.MinifyJson(`{
		"decryptRequest": ` + helpers.MinifyJson(requestJson) + `,
		"requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `
	  }`))
	req, err := http.NewRequest("POST", c.HostURL+"/v1/decrypt", bytes.NewBuffer(jsonStr))
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
	return result["decryptRequestId"].(string), code, nil
	// return response, nil

}

// Function thats sends decrypt request to TSB
func (c *TSBClient) Decrypt(label string, password string, cipertext string, vector string, cipherAlgorithm string, tagLength int, additionalAuthenticationData string) (*helpers.DecryptResponse, int, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	vectorString := `"` + vector + `"`
	if vector == "" {
		vectorString = "null"
	}
	additionalAuthenticationDataString := `"` + additionalAuthenticationData + `"`
	if additionalAuthenticationData == "" {
		additionalAuthenticationDataString = "null"
	}
	tagLengthString := ""
	if tagLength != -1 && cipherAlgorithm == "AES_GCM" {
		tagLengthString = `"tagLength":` + strconv.Itoa(tagLength) + `,`
	}
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"decryptRequest": {
		  "encryptedPayload": "` + cipertext + `",
		  ` + passwordString + `	
		  "decryptKeyName": "` + label + `",
		  "cipherAlgorithm": "` + cipherAlgorithm + `",
		  "initializationVector": ` + vectorString + `,
		  ` + tagLengthString + `
		  "additionalAuthenticationData":` + additionalAuthenticationDataString + `
		}
	  }`)
	req, err := http.NewRequest("POST", c.HostURL+"/v1/synchronousDecrypt", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var decryptResponse helpers.DecryptResponse
	errJSON := json.Unmarshal(body, &decryptResponse)
	if errJSON != nil {
		return nil, code, errJSON
	}
	return &decryptResponse, code, nil

}

// Function thats send encrypt request to TSB
func (c *TSBClient) Encrypt(label string, password string, payload string, cipherAlgorithm string, tagLength int, additionalAuthenticationData string) (*helpers.EncryptResponse, int, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	additionalAuthenticationDataString := `"` + additionalAuthenticationData + `"`
	if additionalAuthenticationData == "" {
		additionalAuthenticationDataString = "null"
	}
	tagLengthString := ""
	if tagLength != -1 && cipherAlgorithm == "AES_GCM" {
		tagLengthString = `"tagLength":` + strconv.Itoa(tagLength) + `,`
	}
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"encryptRequest": {
		  "payload": "` + payload + `",
		  ` + passwordString + `
		  "encryptKeyName": "` + label + `",
		  "cipherAlgorithm": "` + cipherAlgorithm + `",
		  ` + tagLengthString + `
		  "additionalAuthenticationData":` + additionalAuthenticationDataString + `
		}
	  }`)
	req, err := http.NewRequest("POST", c.HostURL+"/v1/encrypt", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var encryptResponse helpers.EncryptResponse
	errJSON := json.Unmarshal(body, &encryptResponse)
	if errJSON != nil {
		return nil, code, errJSON
	}
	return &encryptResponse, code, nil

}
