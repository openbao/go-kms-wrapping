// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package openstackbarbican

import (
	"context"
	"os"
	"reflect"
	"testing"
)

const (
	envOpenStackBarbicanSecretRef = "OPENSTACKBARBICAN_SECRET_REF"
	envOpenStackBarbicanEndpoint  = "OPENSTACKBARBICAN_ENDPOINT"
	envOpenStackBarbicanRegion    = "OPENSTACKBARBICAN_REGION"
)

// This test executes real calls against OpenStack Barbican.
//
// To run this test, the following env variables need to be set:
//   - VAULT_ACC or KMS_ACC_TESTS
//   - OS_CLOUD, or standard OS_* OpenStack auth environment variables
//   - OPENSTACKBARBICAN_SECRET_REF
//   - OPENSTACKBARBICAN_ENDPOINT (optional)
//   - OPENSTACKBARBICAN_REGION (optional)
func TestAccOpenStackBarbicanWrapper_Lifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}
	secretRef := os.Getenv(envOpenStackBarbicanSecretRef)
	if secretRef == "" {
		t.SkipNow()
	}

	s := NewWrapper()
	_, err := s.SetConfig(
		context.Background(),
		WithSecretRef(secretRef),
		WithEndpoint(os.Getenv(envOpenStackBarbicanEndpoint)),
		WithRegion(os.Getenv(envOpenStackBarbicanRegion)),
	)
	if err != nil {
		t.Fatalf("err : %s", err)
	}

	input := []byte("foo")
	swi, err := s.Encrypt(context.Background(), input)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	pt, err := s.Decrypt(context.Background(), swi)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}
}
