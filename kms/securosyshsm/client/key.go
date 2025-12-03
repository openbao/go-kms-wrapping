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

// Function thats sends update key password request to TSB
func (c *TSBClient) UpdateKeyPassword(label string, password string, newPassword string) (string, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	charsNewPasswordJson, _ := json.Marshal(helpers.StringToCharArray(newPassword))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"password": ` + string(charsPasswordJson) + `,`

	}
	newPasswordString := ""
	if len(charsNewPasswordJson) > 2 {
		newPasswordString = `"newPassword": ` + string(charsNewPasswordJson) + `,`

	}
	var jsonStr = []byte(`{
			` + passwordString + newPasswordString + `
			"label": "` + label + `"
		}`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/key/changePassword", bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", err
	}
	_, _, errRes := c.doRequest(req, KeyManagementTokenName)
	if errRes != nil {
		return "", errRes
	}
	return label, nil

}

// CreateOrUpdateKey Function thats sends create key request to TSB
func (c *TSBClient) CreateOrUpdateKey(label string, password string, attributes map[string]bool, keytype string, keySize float64, policy *helpers.Policy, curveOid string, modify bool) (string, error) {

	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	policyJson, _ := json.Marshal(&policy)
	policyString := string(`,"policy":` + string(policyJson))
	if attributes["extractable"] {
		policyString = string(`,"policy":null`)
	}
	var keySizeAttr string
	if keySize == 0 {
		keySizeAttr = ""
	} else {
		keySizeAttr = `"keySize": ` + fmt.Sprintf("%g", keySize) + `,`
	}
	var curveOidString string
	if curveOid == "" {
		curveOidString = ""
	} else {
		curveOidString = `"curveOid": "` + curveOid + `",`
	}
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"password": ` + string(charsPasswordJson) + `,`

	}
	var jsonStr = []byte(`{
	"label": "` + label + `",
    "algorithm": "` + keytype + `",	
    ` + passwordString + `
	` + keySizeAttr + `
	` + curveOidString + `
	"attributes": ` + helpers.PrepareAttributes(attributes) + policyString + `}`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/key", bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", err
	}
	body, _, err := c.doRequest(req, KeyManagementTokenName)
	if err != nil {
		var result map[string]interface{}
		errJSON := json.Unmarshal(body, &result)
		if errJSON != nil {
			return "", errJSON
		}
		return "", err
	}
	return label, nil
}

// Function thats sends delete key request to TSB
func (c *TSBClient) RemoveKey(keyLabel string) error {
	req, _ := http.NewRequest("DELETE", c.HostURL+"/v1/key/"+keyLabel, nil)
	_, _, err := c.doRequest(req, KeyManagementTokenName)
	if err != nil {
		return err
	}
	return nil

}

// Function thats sends import key request to TSB
func (c *TSBClient) ImportKey(label string, privateKey string, publicKey string, secretKey string, certificate string, attributes map[string]bool, keytype string, policy helpers.Policy) (map[string]interface{}, error) {
	policyJson, _ := json.Marshal(policy)
	policyString := string(`,"policy":` + string(policyJson))
	if attributes["extractable"] {
		policyString = string(`,"policy":null`)
	}
	var privateKeyString string
	if privateKey == "" {
		privateKeyString = ""
	} else {
		privateKeyString = `"privateKey": "` + privateKey + `",`
	}
	var publicKeyString string
	if publicKey == "" {
		publicKeyString = ""
	} else {
		publicKeyString = `"publicKey": "` + publicKey + `",`
	}
	var secretKeyString string
	if secretKey == "" {
		secretKeyString = ""
	} else {
		secretKeyString = `"secretKey": "` + secretKey + `",`
	}
	var certificateString string
	if certificate == "" {
		certificateString = ""
	} else {
		certificateString = `"certificate": "` + certificate + `",`
	}
	var jsonStr = []byte(`{
	"label": "` + label + `",
    "algorithm": "` + keytype + `",	
	` + privateKeyString + `
	` + publicKeyString + `
	` + secretKeyString + `
	` + certificateString + `
	"attributes": ` + helpers.PrepareAttributes(attributes) + policyString + `}`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/key/import/plain", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	body, _, errRes := c.doRequest(req, KeyManagementTokenName)
	if errRes != nil {
		return nil, errRes
	}
	var response map[string]interface{}
	json.Unmarshal(body, &response)
	return response, nil

}

// Function thats sends export request to TSB
func (c *TSBClient) ExportKey(label string, password string) (map[string]interface{}, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"password": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		` + passwordString + `
		  "label": "` + label + `"
		  
	  }`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/key/export/plain", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	body, _, errRes := c.doRequest(req, KeyManagementTokenName)
	if errRes != nil {
		return nil, errRes
	}

	var response map[string]interface{}
	json.Unmarshal(body, &response)

	return response, nil

}

// Function thats sends get key attribute request to TSB
func (c *TSBClient) GetKey(label string, password string) (helpers.KeyAttributes, error) {

	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"password": ` + string(charsPasswordJson) + `,`

	}
	var jsonStr = []byte(`{
			` + passwordString + `
			"label":"` + label + `"		
		}`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/key/attributes", bytes.NewBuffer(jsonStr))
	var key helpers.KeyAttributes
	if err != nil {
		return key, err
	}
	body, _, errRes := c.doRequest(req, KeyManagementTokenName)
	if errRes != nil {
		return key, errRes
	}
	var response interface{}
	json.Unmarshal(body, &response)
	data := response.(map[string]interface{})
	jsonData := data["json"].(map[string]interface{})
	key.Algorithm = jsonData["algorithm"].(string)
	key.AlgorithmOid = jsonData["algorithmOid"].(string)
	key.CurveOid = ""
	if jsonData["derivedAttributes"] != nil {
		key.DerivedAttributes = jsonData["derivedAttributes"].(map[string]interface{})
	}
	if jsonData["id"] != nil {
		key.Id = jsonData["id"].(*string)
	}
	if fmt.Sprintf("%T", jsonData["curveOid"]) == "string" {
		key.CurveOid = jsonData["curveOid"].(string)
	}
	key.Attributes = map[string]bool{}
	attributes := jsonData["attributes"].(map[string]interface{})
	for k, e := range attributes {
		if fmt.Sprintf("%T", e) == "bool" {
			key.Attributes[k] = e.(bool)
		}
	}
	if fmt.Sprintf("%T", jsonData["keySize"]) == "float64" {
		key.KeySize = jsonData["keySize"].(float64)
	}
	key.Xml = data["xml"].(string)
	key.XmlSignature = data["xmlSignature"].(string)
	key.AttestationKeyName = data["attestationKeyName"].(string)
	key.Label = jsonData["label"].(string)
	policyString, _ := json.Marshal(jsonData["policy"])
	json.Unmarshal(policyString, &key.Policy)
	if fmt.Sprintf("%T", jsonData["publicKey"]) == "string" {
		key.PublicKey = jsonData["publicKey"].(string)
	}
	return key, nil

}

// Function thats sends get key attribute request to TSB
func (c *TSBClient) GetKeys() ([]string, error) {

	req, err := http.NewRequest("GET", c.HostURL+"/v1/key", bytes.NewBuffer(nil))
	keys := []string{}
	if err != nil {
		return keys, err
	}
	body, _, errRes := c.doRequest(req, KeyManagementTokenName)
	if errRes != nil {
		return keys, errRes
	}
	json.Unmarshal(body, &keys)
	return keys, nil

}
