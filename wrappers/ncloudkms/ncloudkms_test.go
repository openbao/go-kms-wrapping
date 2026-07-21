// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package ncloudkms

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// TestCreateNaverSignature pins the ncp-apigw-signature-v2 message format and
// verifies the signing is deterministic and sensitive to the secret key. It
// needs no network access.
func TestCreateNaverSignature(t *testing.T) {
	method := "POST"
	uri := "/keys/v2/my-key/encrypt"
	ts := time.UnixMilli(1_700_000_000_000)
	accessKey := "access-key"
	secretKey := "secret-key"

	got := createNaverSignature(method, uri, ts, accessKey, secretKey)

	// Independently recompute the expected signature to lock the exact message
	// layout: "{method} {uri}\n{timestampMillis}\n{accessKey}".
	message := fmt.Sprintf("%s %s\n%d\n%s", method, uri, ts.UnixMilli(), accessKey)
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(message))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if got != want {
		t.Fatalf("signature mismatch:\n got: %s\nwant: %s", got, want)
	}

	// Deterministic for identical inputs.
	if again := createNaverSignature(method, uri, ts, accessKey, secretKey); again != got {
		t.Fatalf("signature not deterministic: %s != %s", again, got)
	}

	// A different secret must produce a different signature.
	if other := createNaverSignature(method, uri, ts, accessKey, "different-secret"); other == got {
		t.Fatal("signature did not change with a different secret key")
	}
}

// TestSetConfig exercises the credential/key-tag resolution and metadata output
// without touching the network. Env vars are disallowed so the host
// environment cannot influence the result.
func TestSetConfig(t *testing.T) {
	ctx := context.Background()

	t.Run("missing key tag", func(t *testing.T) {
		w := NewWrapper()
		_, err := w.SetConfig(
			ctx,
			wrapping.WithDisallowEnvVars(true),
			WithAccessKey("ak"), WithSecretKey("sk"),
		)
		if err == nil {
			t.Fatal("expected error when key tag is missing")
		}
	})

	t.Run("missing credentials", func(t *testing.T) {
		w := NewWrapper()
		_, err := w.SetConfig(
			ctx,
			wrapping.WithDisallowEnvVars(true),
			WithKeyTag("my-key"),
		)
		if err == nil {
			t.Fatal("expected error when credentials are missing")
		}
	})

	t.Run("valid config", func(t *testing.T) {
		w := NewWrapper()
		cfg, err := w.SetConfig(
			ctx,
			wrapping.WithDisallowEnvVars(true),
			WithKeyTag("my-key"),
			WithAccessKey("ak"), WithSecretKey("sk"),
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Metadata["key_tag"] != "my-key" {
			t.Errorf("key_tag = %q, want my-key", cfg.Metadata["key_tag"])
		}
		if cfg.Metadata["domain"] != defaultDomain {
			t.Errorf("domain = %q, want %q", cfg.Metadata["domain"], defaultDomain)
		}
		if w.client == nil {
			t.Error("client was not initialized")
		}
		if id, _ := w.KeyId(ctx); id != "my-key" {
			t.Errorf("KeyId() = %q, want my-key", id)
		}
	})

	t.Run("custom domain via config map", func(t *testing.T) {
		w := NewWrapper()
		cfg, err := w.SetConfig(
			ctx,
			wrapping.WithDisallowEnvVars(true),
			wrapping.WithConfigMap(map[string]string{
				"key_tag":    "my-key",
				"domain":     "kms.example.com",
				"access_key": "ak",
				"secret_key": "sk",
			}),
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Metadata["domain"] != "kms.example.com" {
			t.Errorf("domain = %q, want kms.example.com", cfg.Metadata["domain"])
		}
	})
}

// TestDecryptInvalidInput covers the missing-key-info guard, which needs no
// network.
func TestDecryptInvalidInput(t *testing.T) {
	w := NewWrapper()

	if _, err := w.Decrypt(context.Background(), &wrapping.BlobInfo{}); err == nil {
		t.Fatal("expected error for missing key info")
	}
}

func TestType(t *testing.T) {
	w := NewWrapper()
	typ, err := w.Type(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if typ != Type {
		t.Fatalf("Type() = %q, want %q", typ, Type)
	}
	if string(Type) != "ncloudkms" {
		t.Fatalf("Type constant = %q, want ncloudkms", Type)
	}
}
