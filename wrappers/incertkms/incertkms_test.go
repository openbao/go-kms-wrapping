package incertkms

import (
	"context"
	"reflect"
	"strings"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

func TestIncertKmsWrapper(t *testing.T) {
	_, srv := NewIncertKmsTestWrapper()
	defer srv.Close()
}

func TestIncertKmsWrapper_Type(t *testing.T) {
	w, srv := NewIncertKmsTestWrapper()
	defer srv.Close()

	typ, err := w.Type(context.Background())
	if err != nil {
		t.Fatalf("Type: %v", err)
	}
	if typ != wrapping.WrapperTypeIncertKms {
		t.Errorf("Type = %q, want %q", typ, wrapping.WrapperTypeIncertKms)
	}
}

func TestIncertKmsWrapper_Lifecycle(t *testing.T) {
	w, srv := NewIncertKmsTestWrapper()
	defer srv.Close()
	testEncryptionRoundTrip(t, w)
}

func TestIncertKmsWrapper_SetConfig_RequiredFields(t *testing.T) {
	cases := []struct {
		name    string
		options []wrapping.Option
		wantErr string
	}{
		{
			name:    "missing kms_username",
			options: nil,
			wantErr: "kms_username is required",
		},
		{
			name: "missing kms_password",
			options: []wrapping.Option{
				WithKmsUrl("http://localhost:3000"),
				WithKmsUsername("opo"),
			},
			wantErr: "kms_password is required",
		},
		{
			name: "invalid kms_vslot uuid",
			options: []wrapping.Option{
				WithKmsUrl("http://localhost:3000"),
				WithKmsUsername("opo"),
				WithKmsPassword("Parizer1!"),
				WithKmsVSlot("not-a-uuid"),
			},
			wantErr: "invalid kms_vslot format",
		},
		{
			name: "invalid kms_key uuid",
			options: []wrapping.Option{
				WithKmsUrl("http://localhost:3000"),
				WithKmsUsername("opo"),
				WithKmsPassword("Parizer1!"),
				WithKmsKey("not-a-uuid"),
			},
			wantErr: "invalid kms_key format",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := NewWrapper()
			_, err := w.SetConfig(context.Background(), tc.options...)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestIncertKmsWrapper_Encrypt_NilPlaintext(t *testing.T) {
	w, srv := NewIncertKmsTestWrapper()
	defer srv.Close()

	if _, err := w.Encrypt(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil plaintext")
	}
}

func TestIncertKmsWrapper_Decrypt_NilInput(t *testing.T) {
	w, srv := NewIncertKmsTestWrapper()
	defer srv.Close()

	if _, err := w.Decrypt(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil input")
	}
}

func TestIncertKmsWrapper_Unconfigured(t *testing.T) {
	w := NewWrapper()

	if _, err := w.Encrypt(context.Background(), []byte("foo")); err == nil {
		t.Fatal("expected error when wrapper is unconfigured")
	}

	if _, err := w.Decrypt(context.Background(), &wrapping.BlobInfo{}); err == nil {
		t.Fatal("expected error when wrapper is unconfigured")
	}
}

func testEncryptionRoundTrip(t *testing.T, w *Wrapper) {
	t.Helper()
	ctx := context.Background()
	input := []byte("foo")
	swi, err := w.Encrypt(ctx, input, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	pt, err := w.Decrypt(ctx, swi, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}
}
