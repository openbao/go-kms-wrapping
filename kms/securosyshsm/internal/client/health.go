// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"net/http"
)

func (c *TSBClient) CheckConnection(ctx context.Context) (string, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, "GET", c.HostURL+"/v1/keystore/statistics", nil)
	if err != nil {
		return "", 500, err
	}
	body, code, errReq := c.doRequest(req, ServiceTokenName)
	if errReq != nil {
		return string(body[:]), code, errReq
	}
	return string(body[:]), code, nil

}
