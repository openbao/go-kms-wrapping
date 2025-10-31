// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package client

import (
	"bytes"
	"encoding/json"
	"net/http"

	helpers "github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/helpers"
)

// Function thats sends get request to TSB
func (c *TSBClient) GetRequest(id string) (*helpers.RequestResponse, int, error) {
	req, err := http.NewRequest("GET", c.HostURL+"/v1/request/"+id, bytes.NewBuffer(nil))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var requestResponse helpers.RequestResponse
	errJSON := json.Unmarshal(body, &requestResponse)
	if errJSON != nil {
		return nil, code, errJSON
	}
	return &requestResponse, code, nil
}

// Function thats sends delete request to TSB
func (c *TSBClient) RemoveRequest(id string) (int, error) {
	req, err := http.NewRequest("DELETE", c.HostURL+"/v1/request/"+id, nil)
	if err != nil {
		return 500, err
	}
	_, code, errReq := c.doRequest(req, KeyOperationTokenName)
	if code == 404 || code == 500 {
		return code, nil
	}
	if errReq != nil {
		return code, errReq
	}
	return code, nil

}
