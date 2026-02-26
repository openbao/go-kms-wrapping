// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package awskms

import (
	"context"
	"encoding/base64"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

const awsTestKeyId = "foo"

func NewAwsKmsTestWrapper() *Wrapper {
	s := NewWrapper()
	s.client = &mockClient{
		keyId: aws.String(awsTestKeyId),
	}
	return s
}

type mockClient struct {
	keyId *string
}

// Encrypt is a mocked call that returns a base64 encoded string.
func (m *mockClient) Encrypt(_ context.Context, input *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	m.keyId = input.KeyId

	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(input.Plaintext)))
	base64.StdEncoding.Encode(encoded, input.Plaintext)

	return &kms.EncryptOutput{
		CiphertextBlob: encoded,
		KeyId:          input.KeyId,
	}, nil
}

// Decrypt is a mocked call that returns a decoded base64 string.
func (m *mockClient) Decrypt(_ context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	decLen := base64.StdEncoding.DecodedLen(len(input.CiphertextBlob))
	decoded := make([]byte, decLen)
	len, err := base64.StdEncoding.Decode(decoded, input.CiphertextBlob)
	if err != nil {
		return nil, err
	}

	if len < decLen {
		decoded = decoded[:len]
	}

	return &kms.DecryptOutput{
		KeyId:     m.keyId,
		Plaintext: decoded,
	}, nil
}
