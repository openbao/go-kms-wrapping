// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package client

import "net/http"

func (c *TSBClient) CheckConnection() (string, int, error) {
	req, err := http.NewRequest("GET", c.HostURL+"/v1/keystore/statistics", nil)
	if err != nil {
		return "", 500, err
	}
	body, code, errReq := c.doRequest(req, ServiceTokenName)
	if errReq != nil {
		return string(body[:]), code, errReq
	}
	return string(body[:]), code, nil

}
