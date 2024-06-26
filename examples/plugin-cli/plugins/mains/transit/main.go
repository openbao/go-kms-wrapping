// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"os"

	gkwp "github.com/openbao/go-kms-wrapping/plugin/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/transit/v2"
)

func main() {
	if err := gkwp.ServePlugin(transit.NewWrapper()); err != nil {
		fmt.Println("Error serving plugin", err)
		os.Exit(1)
	}
	os.Exit(0)
}
