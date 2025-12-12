// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package client

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2/helpers"
)

func (c *TSBClient) GenerateRandom(length int) (*helpers.RandomResponse, int, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/generateRandom/%d", c.HostURL, length), nil)
	if err != nil {
		return nil, 500, err
	}
	body, code, errReq := c.doRequest(req, ServiceTokenName)
	if errReq != nil {
		return nil, code, errReq
	}
	var randomResponse helpers.RandomResponse
	errJSON := json.Unmarshal(body, &randomResponse)
	if errJSON != nil {
		return nil, code, errJSON
	}
	return &randomResponse, code, nil

}
