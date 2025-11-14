// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// package module provides PKCS#11 library lifecycle management.
package module

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
)

type module struct {
	*pkcs11.Ctx

	path string // Original dynamic library path.
	refs int    // Reference count.
}

var (
	// cache globally tracks modules.
	cache = make(map[string]*module)

	// cacheLock guards cache.
	cacheLock sync.Mutex
)

// Ref is a shared reference to an initialized PKCS#11 module.
type Ref struct {
	*module

	_       noCopy
	dropped atomic.Bool
}

type noCopy struct{}

func (noCopy) Lock()   {}
func (noCopy) Unlock() {}

// Open returns a module reference, either by loading a new dynamic library from
// path or by reusing one from a global cache.
func Open(path string) (*Ref, error) {
	// Don't allow dynamic library loading via search paths. This makes it hard
	// to track which file is ultimately opened by dlopen. For more context, see
	// the dlopen(3).
	if !strings.Contains(path, "/") {
		return nil, errors.New("module loading via search paths is not allowed")
	}

	// Best-effort path deduplication.
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute module path: %w", err)
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("failed to eval symlinks in module path: %w", err)
	}

	cacheLock.Lock()
	defer cacheLock.Unlock()

	if m, ok := cache[path]; ok {
		// Module is already in cache, just increment the refcount.
		m.refs++
		return &Ref{module: m}, nil
	}

	ctx := pkcs11.New(path)
	if ctx == nil {
		return nil, errors.New("failed to load dynamic library")
	}

	if err := ctx.Initialize(); err != nil {
		// If we can't initialize, just drop the entire dynamic library again.
		ctx.Destroy()
		return nil, fmt.Errorf("failed to pkcs#11 Initialize: %w", err)
	}

	m := &module{Ctx: ctx, path: path, refs: 1}
	cache[path] = m

	return &Ref{module: m}, nil
}

// Drop decrements the module's reference count. If the module has no other
// remaining references, it will be finalized and destroyed. Dropping a
// reference multiple times will not compromise the module's reference count,
// however, any continued usage of the dropped reference is undefined behavior.
func (r *Ref) Drop() error {
	if !r.dropped.CompareAndSwap(false, true) {
		return errors.New("reference was already dropped")
	}

	cacheLock.Lock()
	defer cacheLock.Unlock()

	r.refs--
	if r.refs != 0 {
		// Drop the reference only.
		return nil
	}

	err := r.Finalize()
	if err != nil {
		// Finalize is best-effort, we don't return without destroying the module.
		err = fmt.Errorf("failed to pkcs#11 Finalize: %w", err)
	}

	r.Destroy()
	delete(cache, r.path)

	return err
}

// TestOpen is a test helper that opens and automatically drops a module on test
// completion, handling all errors.
func TestOpen(t *testing.T, path string) *Ref {
	t.Helper()

	mod, err := Open(path)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, mod.Drop())
	})

	return mod
}

// Path returns the module's dynamic library path.
func (m *module) Path() string {
	return m.path
}

// Token holds token information, including the associated slot ID.
type Token struct {
	ID   uint // ID is the slot ID the token is present in.
	Info pkcs11.TokenInfo
}

// TokenSelector is used to select a specific token.
type TokenSelector func(slot uint, info *pkcs11.TokenInfo) bool

// SelectID matches a token by slot ID.
func SelectID(id uint) TokenSelector {
	return func(slot uint, info *pkcs11.TokenInfo) bool {
		return slot == id
	}
}

// SelectLabel matches a token by label.
func SelectLabel(label string) TokenSelector {
	return func(slot uint, info *pkcs11.TokenInfo) bool {
		return info.Label != "" && info.Label == label
	}
}

// GetToken finds a token by applying a set of selectors to each slot.
// The first token that matches all selectors is returned.
func (m *module) GetToken(selectors ...TokenSelector) (*Token, error) {
	if len(selectors) == 0 {
		return nil, errors.New("need at least one selector")
	}

	list, err := m.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 GetSlotList: %w", err)
	}

	for _, slot := range list {
		info, err := m.GetTokenInfo(slot)
		if err != nil {
			return nil, fmt.Errorf("failed to pkcs#11 GetTokenInfo: %w", err)
		}

		match := true

		for _, selector := range selectors {
			if !selector(slot, &info) {
				match = false
				break
			}
		}

		if match {
			return &Token{ID: slot, Info: info}, nil
		}
	}

	return nil, errors.New("no matching token")
}
