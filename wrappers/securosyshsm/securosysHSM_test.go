// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"context"
	"reflect"
	"testing"
)

func TestSecurosysHSMWrapper(t *testing.T) {
	NewSecurosysHSMTestWrapper()
}

func TestSecurosysHSMWrapper_Lifecycle(t *testing.T) {
	s := NewSecurosysHSMTestWrapper()
	testEncryptionRoundTrip(t, s)
}

func testEncryptionRoundTrip(t *testing.T, w *Wrapper) {
	w.SetConfig(context.Background())
	input := []byte("foo")
	swi, err := w.Encrypt(context.Background(), input, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	pt, err := w.Decrypt(context.Background(), swi, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}
}
