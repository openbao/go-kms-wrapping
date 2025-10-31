// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
)

const (
	NameAttr  string = "name"
	IdAttr    string = "id"
	TypeAttr  string = "type"
	GroupAttr string = "group"
)

// KeyStore represents the keys life-cycle management interface that must be
// implemented by any crypto provider. This is the entry point for creating Key
// objects.
type KeyStore interface {
	// Close terminates the keystore
	Close(ctx context.Context) error

	// Login logs in a user or application to this keystore
	Login(ctx context.Context, credentials *Credentials) error

	// ListKeys lists all keys managed by the current keystore
	// TODO: add list filters/criteria: symmetric keys, public keys, private keys, etc.
	ListKeys(ctx context.Context) ([]Key, error)
	GenerateSecretKey(ctx context.Context, keyAttributes *KeyAttributes) (secret Key, err error)
	GenerateKeyPair(ctx context.Context, keyPairAttributes *KeyAttributes) (privKey Key, pubKey Key, err error)

	// GetKeyById searches for the key with the specified Id
	// TODO: Id should be unique (UUId) throughout  a keystore ?
	GetKeyById(ctx context.Context, keyId string) (Key, error)

	// GetKeyByName searches for the key with the specified name
	GetKeyByName(ctx context.Context, keyName string) (Key, error)

	// GetKeyByAttrs searches for the key with the specified attributes.
	GetKeyByAttrs(ctx context.Context, attrs map[string]interface{}) (Key, error)

	// GetInfo returns information about the provider to the caller for
	// end-user display purposes.
	GetInfo() map[string]string
	RemoveKey(ctx context.Context, key Key) error
}

// AssumableKeyStore provides additional methods that [KeyStore] can implement
// to support one-shot operations.
type AssumableKeyStore interface {
	// AssumeKeyById returns an unresolved key which can be used on subsequent
	// requests but without fully resolving all details; this allows one-shot
	// sign/encrypt operations without first looking up the key attributes.
	AssumeKeyById(keyId string) (Key, error)

	// AssumeKeyByName returns an unresolved key which can be used on subsequent
	// requests but without fully resolving all details; this allows one-shot
	// sign/encrypt operations without first looking up the key attributes.
	AssumeKeyByName(keyName string) (Key, error)

	// AssumeKeyByAttrs returns an unresolved key which can be used on subsequent
	// requests but without fully resolving all details; this allows one-shot
	// sign/encrypt operations without first looking up the key attributes.
	AssumeKeyByAttrs(attrs map[string]interface{}) (Key, error)
}
