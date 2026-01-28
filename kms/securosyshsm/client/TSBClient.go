// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package client

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

// HostURL - Default Securosys TSB URL
const HostURL string = ""

// TSBClient struct
type TSBClient struct {
	HostURL    string
	HTTPClient *http.Client
	Auth       AuthStruct
}
type AuthStruct struct {
	AppName                string      `json:"appName"`
	AuthType               string      `json:"auth"`
	CertPath               string      `json:"certpath"`
	KeyPath                string      `json:"keypath"`
	BearerToken            string      `json:"bearertoken"`
	BasicToken             string      `json:"basictoken"`
	Username               string      `json:"username"`
	Password               string      `json:"password"`
	ApiKeys                ApiKeyTypes `json:"apikey"`
	ApplicationKeyPair     KeyPair     `json:"applicationKeyPair"`
	CurrentApiKeyTypeIndex ApiKeyTypesRetry
}
type KeyPair struct {
	PrivateKey *string `json:"privateKey,omitempty"`
	PublicKey  *string `json:"publicKey,omitempty"`
}

type ApiKeyTypes struct {
	KeyManagementToken         []string `json:"KeyManagementToken,omitempty"`
	KeyOperationToken          []string `json:"KeyOperationToken,omitempty"`
	ApproverToken              []string `json:"ApproverToken,omitempty"`
	ServiceToken               []string `json:"ServiceToken,omitempty"`
	ApproverKeyManagementToken []string `json:"ApproverKeyManagementToken,omitempty"`
}
type ApiKeyTypesRetry struct {
	KeyManagementTokenIndex         int
	KeyOperationTokenIndex          int
	ApproverTokenIndex              int
	ServiceTokenIndex               int
	ApproverKeyManagementTokenIndex int
}

const (
	KeyManagementTokenName         = "KeyManagementToken"
	KeyOperationTokenName          = "KeyOperationToken"
	ApproverTokenName              = "ApproverToken"
	ServiceTokenName               = "ServiceToken"
	ApproverKeyManagementTokenName = "ApproverKeyManagementToken"
)

// Function inicialize new client for accessing TSB
func NewTSBClient(restApi string, settings AuthStruct) (*TSBClient, error) {
	restApi = strings.TrimSuffix(restApi, "/")
	c := TSBClient{
		HTTPClient: &http.Client{Timeout: 9999999 * time.Second},
		HostURL:    restApi,
		Auth:       settings,
	}

	return &c, nil
}
func (a *TSBClient) RollOverApiKey(name string) error {
	switch name {
	case "KeyManagementToken":
		a.Auth.CurrentApiKeyTypeIndex.KeyManagementTokenIndex += 1
		return nil
	case "KeyOperationToken":
		if len(a.Auth.ApiKeys.KeyOperationToken) == 0 {
			return fmt.Errorf("no KeyOperationToken provided")
		}
		a.Auth.CurrentApiKeyTypeIndex.KeyOperationTokenIndex += 1
		return nil
	case "ApproverToken":
		if len(a.Auth.ApiKeys.ApproverToken) == 0 {
			return fmt.Errorf("no ApproverToken provided")
		}
		a.Auth.CurrentApiKeyTypeIndex.ApproverTokenIndex += 1
		return nil
	case "ServiceToken":
		if len(a.Auth.ApiKeys.ServiceToken) == 0 {
			return fmt.Errorf("no ServiceToken provided")
		}
		a.Auth.CurrentApiKeyTypeIndex.ServiceTokenIndex += 1
		return nil
	case "ApproverKeyManagementToken":
		if len(a.Auth.ApiKeys.ApproverKeyManagementToken) == 0 {
			return fmt.Errorf("no ApproverKeyManagementToken provided")
		}
		a.Auth.CurrentApiKeyTypeIndex.ApproverKeyManagementTokenIndex += 1
		return nil
	}
	return fmt.Errorf("apikey usign name %s does not exist", name)

}

func (a *TSBClient) CanGetNewApiKeyByName(name string) (bool, error) {
	switch name {
	case "KeyManagementToken":
		if len(a.Auth.ApiKeys.KeyManagementToken) == 0 {
			return false, nil
		}
		if len(a.Auth.ApiKeys.KeyManagementToken) > a.Auth.CurrentApiKeyTypeIndex.KeyManagementTokenIndex {
			return true, nil
		}
		return false, fmt.Errorf("no more apikeys")
	case "KeyOperationToken":
		if len(a.Auth.ApiKeys.KeyOperationToken) == 0 {
			return false, nil
		}
		if len(a.Auth.ApiKeys.KeyOperationToken) > a.Auth.CurrentApiKeyTypeIndex.KeyOperationTokenIndex {
			return true, nil
		}
		return false, fmt.Errorf("no more apikeys")
	case "ApproverToken":
		if len(a.Auth.ApiKeys.ApproverToken) == 0 {
			return false, nil
		}
		if len(a.Auth.ApiKeys.ApproverToken) > a.Auth.CurrentApiKeyTypeIndex.ApproverTokenIndex {
			return true, nil
		}
		return false, fmt.Errorf("no more apikeys")
	case "ServiceToken":
		if len(a.Auth.ApiKeys.ServiceToken) == 0 {
			return false, nil
		}
		if len(a.Auth.ApiKeys.ServiceToken) > a.Auth.CurrentApiKeyTypeIndex.ServiceTokenIndex {
			return true, nil
		}
		return false, fmt.Errorf("no more apikeys")
	case "ApproverKeyManagementToken":
		if len(a.Auth.ApiKeys.ApproverKeyManagementToken) == 0 {
			return false, nil
		}
		if len(a.Auth.ApiKeys.ApproverKeyManagementToken) > a.Auth.CurrentApiKeyTypeIndex.ApproverKeyManagementTokenIndex {
			return true, nil
		}
		return false, fmt.Errorf("no more apikeys")
	}
	return false, fmt.Errorf("no apikey exists usign name %s", name)

}

func (a *TSBClient) GetApiKeyByName(name string) *string {
	switch name {
	case "KeyManagementToken":
		return &a.Auth.ApiKeys.KeyManagementToken[a.Auth.CurrentApiKeyTypeIndex.KeyManagementTokenIndex]
	case "KeyOperationToken":
		return &a.Auth.ApiKeys.KeyOperationToken[a.Auth.CurrentApiKeyTypeIndex.KeyOperationTokenIndex]
	case "ApproverToken":
		return &a.Auth.ApiKeys.ApproverToken[a.Auth.CurrentApiKeyTypeIndex.ApproverTokenIndex]
	case "ServiceToken":
		return &a.Auth.ApiKeys.ServiceToken[a.Auth.CurrentApiKeyTypeIndex.ServiceTokenIndex]
	case "ApproverKeyManagementToken":
		return &a.Auth.ApiKeys.ApproverKeyManagementToken[a.Auth.CurrentApiKeyTypeIndex.ApproverKeyManagementTokenIndex]
	}
	return nil
}

// Function that making all requests. Using config for Authorization to TSB
func (c *TSBClient) doRequest(req *http.Request, apiKeyName string) ([]byte, int, error) {
	// req.Header.Set("Authorization", c.Token)
	if c.Auth.AuthType == "TOKEN" {
		req.Header.Set("Authorization", "Bearer "+c.Auth.BearerToken)
	}
	if c.Auth.AuthType == "BASIC" {
		if c.Auth.BasicToken == "" {
			req.SetBasicAuth(c.Auth.Username, c.Auth.Password)
		} else {
			req.Header.Set("Authorization", "Basic "+(c.Auth.BasicToken))
		}
	}
	if c.Auth.AuthType == "CERT" {

		caCert, _ := ioutil.ReadFile(c.Auth.CertPath)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		clientTLSCert, err := tls.LoadX509KeyPair(c.Auth.CertPath, c.Auth.KeyPath)
		if err != nil {
			log.Fatalf("Error loading certificate and key file: %v", err)
			return nil, 0, err
		}

		c.HTTPClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{clientTLSCert},
			},
		}
	}
	canGetApiKey, err := c.CanGetNewApiKeyByName(apiKeyName)
	if err != nil {
		return []byte(fmt.Sprintf("All apikeys in group %s are invalid", apiKeyName)), 401, fmt.Errorf("status: %d, body: All apikeys in group %s are invalid", 401, apiKeyName)
	}
	if canGetApiKey {
		req.Header.Set("X-API-KEY", *c.GetApiKeyByName(apiKeyName))
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, res.StatusCode, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, res.StatusCode, err
	}
	if canGetApiKey && res.StatusCode == http.StatusUnauthorized {
		var result map[string]interface{}
		json.Unmarshal(body, &result)
		errorCode := result["errorCode"].(float64)

		if errorCode == 631 {
			c.RollOverApiKey(apiKeyName)
			return c.doRequest(req, apiKeyName)

		}
	}

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return body, res.StatusCode, fmt.Errorf("status: %d, body: %s", res.StatusCode, body)
	}

	return body, res.StatusCode, err
}

func (c *TSBClient) GetApplicationPrivateKey() *rsa.PrivateKey {
	if c.Auth.ApplicationKeyPair.PrivateKey == nil {
		return nil
	}
	block, _ := pem.Decode(c.WrapPrivateKeyWithHeaders(false))
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	if key == nil {
		block, _ = pem.Decode(c.WrapPrivateKeyWithHeaders(true))
		parseResult, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
		key := parseResult.(*rsa.PrivateKey)
		return key
	}
	return key
}

func (c *TSBClient) WrapPrivateKeyWithHeaders(pkcs8 bool) []byte {
	if c.Auth.ApplicationKeyPair.PrivateKey == nil {
		return nil
	}
	if pkcs8 == false {
		return []byte("-----BEGIN RSA PRIVATE KEY-----\n" + *c.Auth.ApplicationKeyPair.PrivateKey + "\n-----END RSA PRIVATE KEY-----")
	} else {
		return []byte("-----BEGIN PRIVATE KEY-----\n" + *c.Auth.ApplicationKeyPair.PrivateKey + "\n-----END PRIVATE KEY-----")

	}

}
func (c *TSBClient) GenerateRequestSignature(requestData string) []byte {
	if c.Auth.ApplicationKeyPair.PrivateKey == nil || c.Auth.ApplicationKeyPair.PublicKey == nil {
		return []byte("null")
	}
	dst := &bytes.Buffer{}
	if err := json.Compact(dst, []byte(requestData)); err != nil {
		panic(err)
	}
	signature, _ := c.SignData([]byte(dst.String()))
	return []byte(`{
		"signature": "` + *signature + `",
		"digestAlgorithm": "SHA-256",
		"publicKey": "` + *c.Auth.ApplicationKeyPair.PublicKey + `"
		}
	`)
}
func (c *TSBClient) SignData(dataToSign []byte) (*string, error) {
	if c.Auth.ApplicationKeyPair.PrivateKey == nil || c.Auth.ApplicationKeyPair.PublicKey == nil {
		return nil, fmt.Errorf("No Application Private Key or Public Key provided!")
	}
	h := sha256.New()
	h.Write(dataToSign)
	bs := h.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.GetApplicationPrivateKey(), crypto.SHA256, bs)
	if err != nil {
		return nil, err
	}
	result := b64.StdEncoding.EncodeToString(signature)
	return &result, nil
}

// Function preparing MetaData, which We are send with all asynchronous requests
func (c *TSBClient) PrepareMetaData(requestType string, additionalMetaData map[string]string, customMetaData map[string]string) (string, *string, error) {
	now := time.Now().UTC()
	var metaData map[string]string = make(map[string]string)
	metaData["time"] = fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
	metaData["app"] = c.Auth.AppName
	metaData["type"] = requestType
	for key, value := range additionalMetaData {
		metaData[key] = value
	}
	for key, value := range customMetaData {
		metaData[key] = value
	}
	metaJsonStr, errMarshal := json.Marshal(metaData)
	if errMarshal != nil {
		return "", nil, errMarshal
	}
	result, err := c.SignData(metaJsonStr)
	if err != nil {
		return b64.StdEncoding.EncodeToString(metaJsonStr),
			nil, nil

	}
	return b64.StdEncoding.EncodeToString(metaJsonStr),
		result, nil
}
