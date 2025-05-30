// Copyright The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

// Module is a reference-counted PKCS#11 context.
type Module struct {
	ctx  *pkcs11.Ctx
	refs int
	path string
}

// Slot is a PKCS#11 slot with pre-fetched TokenInfo.
type Slot struct {
	ctx  *pkcs11.Ctx
	info *pkcs11.TokenInfo
	id   uint
}

var (
	// moduleCache caches modules by path.
	moduleCache = make(map[string]*Module)
	// moduleCacheLock guards moduleCache.
	moduleCacheLock = sync.Mutex{}
)

// OpenModule opens and initializes a PKCS#11 module, incrementing its reference count.
func OpenModule(path string) (*Module, error) {
	if path == "" {
		return nil, fmt.Errorf("module path must be set")
	}

	if !strings.Contains(path, "/") {
		// Don't allow dynamic library loading via search paths.
		// This makes it hard for us to track which file is ultimately opened by dlopen.
		// For more context, see the dlopen(3).
		return nil, fmt.Errorf("module loading via search paths is not allowed")
	}

	// Best-effort path-deduplication.
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute module path: %w", err)
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("failed to eval symlinks in module path: %w", err)
	}

	moduleCacheLock.Lock()
	defer moduleCacheLock.Unlock()
	if module, ok := moduleCache[path]; ok {
		module.refs++
		return module, nil
	}

	ctx := pkcs11.New(path)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load module %q", path)
	}

	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return nil, fmt.Errorf("failed to initialize module %q: %w", path, err)
	}

	module := &Module{ctx: ctx, refs: 1, path: path}
	moduleCache[path] = module
	return module, nil
}

// Close decrements the module's reference count, freeing it if the count reaches zero.
func (m *Module) Close() {
	moduleCacheLock.Lock()
	defer moduleCacheLock.Unlock()

	_, ok := moduleCache[m.path]
	if !ok {
		panic("internal error: closing module that is not known to module cache")
	}

	if updated := m.refs - 1; updated == 0 {
		m.ctx.Destroy()
		delete(moduleCache, m.path)
	} else {
		m.refs = updated
	}
}

// FindSlot finds the slot corresponding to slotNumber and tokenLabel.
func (m *Module) FindSlot(slotNumber *uint, tokenLabel string) (*Slot, error) {
	if slotNumber == nil && tokenLabel == "" {
		return nil, fmt.Errorf("at least one of slot number, token label must be set")
	}

	ids, err := m.ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("failed to list slots: %w", err)
	}

	for _, id := range ids {
		info, err := m.ctx.GetTokenInfo(id)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch token info for slot %d: %w",
				id, err)
		}
		if (slotNumber != nil && id == *slotNumber) || info.Label == tokenLabel {
			return &Slot{ctx: m.ctx, id: id, info: &info}, err
		}
	}

	return nil, fmt.Errorf("no matching token slot found")
}
