// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kms

const (
	NameAttr string = "name"
	IdAttr   string = "id"
)

// KeyStore represents the keys life-cycle management interface that must be implemented by any crypto provider.
// This is the entry point for creating  Key objects.
type KeyStore interface {
	// Close terminates the keystore
	Close() error

	// Login logs in a user or application to this keystore
	Login(credentials *Credentials) error

	// ListKeys lists all keys managed by the current keystore
	// TODO: add list filters/criteria: symmetric keys, public keys, private keys, etc.
	ListKeys() ([]Key, error)

	// GetKeyById searches for the key with the specified Id
	// TODO: Id should be unique (UUId) throughout  a keystore ?
	GetKeyById(keyId string) (Key, error)

	// GetKeyByName searches for the key with the specified name
	GetKeyByName(keyName string) (Key, error)

	// GetKeyByAttrs searches for the key with the specified attributes.
	GetKeyByAttrs(attrs map[string]interface{}) (Key, error)
}
