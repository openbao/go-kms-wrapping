// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	helpers "github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/helpers"
)

// Function thats create a certificate request to TSB
func (c *TSBClient) CreateCertificate(signKeyName string, keyPassword string, signatureAlgorithm string, validity int, certAttributes helpers.CertificateAttributes, keyUsage []string, extendedKeyUsage []string) (*helpers.GenerateCertificateRequestResponse, int, error) {

	var jsonStr []byte

	if keyPassword == "" {
		certAttributesJson, _ := json.Marshal(certAttributes)
		jsonStr = []byte(`{
		  "signKeyName": "` + signKeyName + `",
		  "signatureAlgorithm": "` + signatureAlgorithm + `",
		  "validity": ` + fmt.Sprint(validity) + `,
		  "standardCertificateAttributes":` + string(certAttributesJson) + `,
		  "keyUsage": ["` + strings.Join(keyUsage[:], ",") + `"],
		  "extendedKeyUsage": ["` + strings.Join(extendedKeyUsage[:], ",") + `"]
	  }`)

	} else {
		keyPasswordJson, _ := json.Marshal(helpers.StringToCharArray(keyPassword))
		certAttributesJson, _ := json.Marshal(certAttributes)

		jsonStr = []byte(`{
		  "signKeyName": "` + signKeyName + `",
		  "keyPassword": ` + string(keyPasswordJson) + `,
		  "signatureAlgorithm": "` + signatureAlgorithm + `",
		  "validity": ` + fmt.Sprint(validity) + `,
		  "standardCertificateAttributes":` + string(certAttributesJson) + `,
		  "keyUsage": ["` + strings.Join(keyUsage[:], ",") + `"],
		  "extendedKeyUsage": ["` + strings.Join(extendedKeyUsage[:], ",") + `"]
	  }`)
	}

	req, err := http.NewRequest("POST", c.HostURL+"/v1/certificate/synchronous/request", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var response helpers.GenerateCertificateRequestResponse
	// response.KeyID = signKeyName
	// response.CertificateRequest = string(body)
	json.Unmarshal(body, &response)
	return &response, code, nil

}

func (c *TSBClient) CreateSelfSignedCertificate(signKeyName string, keyPassword string, signatureAlgorithm string, validity int, commonName string, keyUsage []string, extendedKeyUsage []string, certificateAuthority bool) (*helpers.GenerateSelfSignedCertificateResponse, int, error) {

	var jsonStr []byte
	keyUsageJson, _ := json.Marshal(keyUsage)
	extendedKeyUsageJson, _ := json.Marshal(extendedKeyUsage)
	if keyPassword == "" {
		jsonStr = []byte(`{
		  "signKeyName": "` + signKeyName + `",
		  "signatureAlgorithm": "` + signatureAlgorithm + `",
		  "validity": ` + fmt.Sprint(validity) + `,
		  "commonName": "` + commonName + `",
		  "keyUsage": ` + string(keyUsageJson) + `,
		  "extendedKeyUsage": ` + string(extendedKeyUsageJson) + `,
		  "certificateAuthority": ` + fmt.Sprint(certificateAuthority) + `
	  }`)

	} else {
		keyPasswordJson, _ := json.Marshal(helpers.StringToCharArray(keyPassword))

		jsonStr = []byte(`{
		  "signKeyName": "` + signKeyName + `",
		  "keyPassword": ` + string(keyPasswordJson) + `,
		  "signatureAlgorithm": "` + signatureAlgorithm + `",
		  "validity": ` + fmt.Sprint(validity) + `,
		  "commonName": "` + commonName + `",
		  "keyUsage": ` + string(keyUsageJson) + `,
		  "extendedKeyUsage": ` + string(extendedKeyUsageJson) + `,
		  "certificateAuthority": ` + fmt.Sprint(certificateAuthority) + `
	  }`)
	}
	req, err := http.NewRequest("POST", c.HostURL+"/v1/certificate/synchronous/selfsign", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var response helpers.GenerateSelfSignedCertificateResponse
	// response.KeyID = signKeyName
	// response.CertificateRequest = string(body)
	json.Unmarshal(body, &response)
	return &response, code, nil

}

func (c *TSBClient) SignCertificate(signKeyName string, keyPassword string, signatureAlgorithm string, certificateSigningRequest string, commonName string, keyUsage []string, extendedKeyUsage []string, certificateAuthority bool) (*helpers.GenerateSelfSignedCertificateResponse, int, error) {

	var jsonStr []byte
	if keyPassword == "" {

		jsonStr = []byte(`{
		  "signKeyName": "` + signKeyName + `",
		  "signatureAlgorithm": "` + signatureAlgorithm + `",
		  "commonName": "` + commonName + `",
		  "certificateSigningRequest": "` + certificateSigningRequest + `",
		  "keyUsage": ["` + strings.Join(keyUsage[:], ",") + `"],
		  "extendedKeyUsage": ["` + strings.Join(extendedKeyUsage[:], ",") + `"],
		  "certificateAuthority": ` + fmt.Sprint(certificateAuthority) + `

	  }`)

	} else {
		keyPasswordJson, _ := json.Marshal(helpers.StringToCharArray(keyPassword))

		jsonStr = []byte(`{
		  "signKeyName": "` + signKeyName + `",
		  "keyPassword": ` + string(keyPasswordJson) + `,
		  "signatureAlgorithm": "` + signatureAlgorithm + `",
		  "commonName": "` + commonName + `",
		  "certificateSigningRequest": "` + certificateSigningRequest + `",
		  "keyUsage": ["` + strings.Join(keyUsage[:], ",") + `"],
		  "extendedKeyUsage": ["` + strings.Join(extendedKeyUsage[:], ",") + `"],
		  "certificateAuthority": ` + fmt.Sprint(certificateAuthority) + `
	  }`)
	}

	req, err := http.NewRequest("POST", c.HostURL+"/v1/certificate/synchronous/sign", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var response helpers.GenerateSelfSignedCertificateResponse
	// response.KeyID = signKeyName
	// response.CertificateRequest = string(body)
	json.Unmarshal(body, &response)
	return &response, code, nil

}

// Function thats create a certificate request to TSB
func (c *TSBClient) AsyncCreateCertificate(signKeyName string, keyPassword string, signatureAlgorithm string, validity int, certAttributes helpers.CertificateAttributes, keyUsage []string, extendedKeyUsage []string, userMetaData map[string]string) (string, int, error) {

	var jsonStr []byte
	var additionalMetaDataInfo map[string]string = make(map[string]string)

	for index, value := range userMetaData {
		additionalMetaDataInfo[index] = value
	}

	metaDataB64, metaDataSignature, _ := c.PrepareMetaData("CertificateSigningRequest", additionalMetaDataInfo, map[string]string{})
	metaDataSignatureString := "null"
	if metaDataSignature != nil {
		metaDataSignatureString = `"` + *metaDataSignature + `"`

	}

	if keyPassword == "" {
		certAttributesJson, _ := json.Marshal(certAttributes)
		requestJson := `{
			"signKeyName": "` + signKeyName + `",
			"signatureAlgorithm": "` + signatureAlgorithm + `",
			"validity": ` + fmt.Sprint(validity) + `,
			"standardCertificateAttributes":` + string(certAttributesJson) + `,
			"keyUsage": ["` + strings.Join(keyUsage[:], ",") + `"],
			"extendedKeyUsage": ["` + strings.Join(extendedKeyUsage[:], ",") + `"],
			"metaData": "` + metaDataB64 + `",
			"metaDataSignature": ` + metaDataSignatureString + `
		}`
		jsonStr = []byte(helpers.MinifyJson(`{
			"csrSignRequest": ` + requestJson + ` ,
	  "requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `}`))

	} else {
		keyPasswordJson, _ := json.Marshal(helpers.StringToCharArray(keyPassword))
		certAttributesJson, _ := json.Marshal(certAttributes)
		requestJson := `{
			"signKeyName": "` + signKeyName + `",
			"keyPassword": ` + string(keyPasswordJson) + `,
			"signatureAlgorithm": "` + signatureAlgorithm + `",
			"validity": ` + fmt.Sprint(validity) + `,
			"standardCertificateAttributes":` + string(certAttributesJson) + `,
			"keyUsage": ["` + strings.Join(keyUsage[:], ",") + `"],
			"extendedKeyUsage": ["` + strings.Join(extendedKeyUsage[:], ",") + `"],
			  "metaData": "` + metaDataB64 + `",
			"metaDataSignature": ` + metaDataSignatureString + `
		}`
		jsonStr = []byte(helpers.MinifyJson(`{ 
			"csrSignRequest": ` + requestJson + `,
	  "requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `}`))
	}

	req, err := http.NewRequest("POST", c.HostURL+"/v1/certificate/request", bytes.NewBuffer(jsonStr))
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
	return result["signRequestId"].(string), code, nil

}

func (c *TSBClient) AsyncSelfSignedCertificate(signKeyName string, keyPassword string, signatureAlgorithm string, validity int, commonName string, keyUsage []string, extendedKeyUsage []string, certificateAuthority bool, userMetaData map[string]string) (string, int, error) {

	var jsonStr []byte
	var additionalMetaDataInfo map[string]string = make(map[string]string)

	for index, value := range userMetaData {
		additionalMetaDataInfo[index] = value
	}

	metaDataB64, metaDataSignature, _ := c.PrepareMetaData("SelfSignCertificate", additionalMetaDataInfo, map[string]string{})
	metaDataSignatureString := "null"
	if metaDataSignature != nil {
		metaDataSignatureString = `"` + *metaDataSignature + `"`

	}

	if keyPassword == "" {
		requestJson := `{
			"signKeyName": "` + signKeyName + `",
			"signatureAlgorithm": "` + signatureAlgorithm + `",
			"validity": ` + fmt.Sprint(validity) + `,
			"commonName": "` + commonName + `",
			"keyUsage": ["` + strings.Join(keyUsage[:], ",") + `"],
			"extendedKeyUsage": ["` + strings.Join(extendedKeyUsage[:], ", ") + `"],
			"metaData": "` + metaDataB64 + `",
			"metaDataSignature": ` + metaDataSignatureString + `,
			"certificateAuthority": ` + fmt.Sprint(certificateAuthority) + `
		}`
		jsonStr = []byte(helpers.MinifyJson(`{
			"selfSignCertificateRequest":` + requestJson + `,
	  "requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `}`))

	} else {
		keyPasswordJson, _ := json.Marshal(helpers.StringToCharArray(keyPassword))
		requestJson := `{
			"signKeyName": "` + signKeyName + `",
			"keyPassword": ` + string(keyPasswordJson) + `,
			"signatureAlgorithm": "` + signatureAlgorithm + `",
			"validity": ` + fmt.Sprint(validity) + `,
			"commonName": "` + commonName + `",
			"keyUsage": ["` + strings.Join(keyUsage[:], ",") + `"],
			"extendedKeyUsage": ["` + strings.Join(extendedKeyUsage[:], ", ") + `"],
			"metaData": "` + metaDataB64 + `",
			"metaDataSignature": ` + metaDataSignatureString + `,
			"certificateAuthority": ` + fmt.Sprint(certificateAuthority) + `
		}`
		jsonStr = []byte(helpers.MinifyJson(`{
			"selfSignCertificateRequest":` + requestJson + `,
	  "requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `}`))
	}

	req, err := http.NewRequest("POST", c.HostURL+"/v1/certificate/selfsign", bytes.NewBuffer(jsonStr))
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
	return result["signRequestId"].(string), code, nil

}

func (c *TSBClient) AsyncSignCertificate(signKeyName string, keyPassword string, signatureAlgorithm string, certificateSigningRequest string, commonName string, keyUsage []string, extendedKeyUsage []string, certificateAuthority bool, userMetaData map[string]string) (string, int, error) {

	var jsonStr []byte

	var additionalMetaDataInfo map[string]string = make(map[string]string)

	for index, value := range userMetaData {
		additionalMetaDataInfo[index] = value
	}

	metaDataB64, metaDataSignature, _ := c.PrepareMetaData("Certificate", additionalMetaDataInfo, map[string]string{})
	metaDataSignatureString := "null"
	if metaDataSignature != nil {
		metaDataSignatureString = `"` + *metaDataSignature + `"`

	}

	if keyPassword == "" {
		requestJson := `{
			"signKeyName": "` + signKeyName + `",
			"signatureAlgorithm": "` + signatureAlgorithm + `",
			"commonName": "` + commonName + `",
			"certificateSigningRequest": "` + certificateSigningRequest + `",
			"keyUsage": ["` + strings.Join(keyUsage[:], ",") + `"],
			"extendedKeyUsage": ["` + strings.Join(extendedKeyUsage[:], ",") + `"],
			"metaData": "` + metaDataB64 + `",
			"metaDataSignature": ` + metaDataSignatureString + `,
			"certificateAuthority": ` + fmt.Sprint(certificateAuthority) + `
  
		}`
		jsonStr = []byte(helpers.MinifyJson(`{
			"signCertificateRequest": ` + requestJson + `,
	  		"requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `
	  }`))

	} else {
		keyPasswordJson, _ := json.Marshal(helpers.StringToCharArray(keyPassword))
		requestJson := `{
			"signKeyName": "` + signKeyName + `",
			"keyPassword": ` + string(keyPasswordJson) + `,
			"signatureAlgorithm": "` + signatureAlgorithm + `",
			"commonName": "` + commonName + `",
			"certificateSigningRequest": "` + certificateSigningRequest + `",
			"keyUsage": ["` + strings.Join(keyUsage[:], ",") + `"],
			"extendedKeyUsage": ["` + strings.Join(extendedKeyUsage[:], ",") + `"],
			"metaData": "` + metaDataB64 + `",
			"metaDataSignature": ` + metaDataSignatureString + `,
			"certificateAuthority": ` + fmt.Sprint(certificateAuthority) + `
		}`
		jsonStr = []byte(helpers.MinifyJson(`{
			"signCertificateRequest": ` + requestJson + `,
	  "requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `}`))
	}

	req, err := http.NewRequest("POST", c.HostURL+"/v1/certificate/sign", bytes.NewBuffer(jsonStr))
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
	return result["signRequestId"].(string), code, nil

}

// Function thats import a certificate request from TSB
func (c *TSBClient) ImportCertificate(label string, certificate string) (*helpers.RequestResponseImportCertificate, int, error) {

	var jsonStr = []byte(`{
		  "label": "` + label + `",
		  "certificate": "` + certificate + `",
	  }`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/certificate/import/plain", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var response helpers.RequestResponseImportCertificate
	json.Unmarshal(body, &response)
	return &response, code, nil

}

// Function thats sends get request to TSB
func (c *TSBClient) GetCertificate(label string) (*helpers.RequestResponseCertificate, int, error) {
	req, err := http.NewRequest("GET", c.HostURL+"/v1/certificate/"+label, bytes.NewBuffer(nil))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var requestResponse helpers.RequestResponseCertificate
	errJSON := json.Unmarshal(body, &requestResponse)
	if errJSON != nil {
		return nil, code, errJSON
	}

	return &requestResponse, code, nil
}

// Function thats delete certificate TSB
func (c *TSBClient) DeleteCertificate(label string) (int, error) {
	req, err := http.NewRequest("DELETE", c.HostURL+"/v1/certificate/"+label, nil)
	if err != nil {
		return 500, err
	}
	_, code, errReq := c.doRequest(req, KeyOperationTokenName)
	if errReq != nil {
		return code, errReq
	}
	return code, nil
}
