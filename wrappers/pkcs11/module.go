// Copyright The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

// module is a PKCS#11 context wrapper that keeps track of:
//   - path of origin
//   - slots in use (-> enables reference counting and finalization)
type module struct {
	// Handle to the PKCS#11 library
	ctx *pkcs11.Ctx
	// Path the PKCS#11 library was opened from
	path string
	// Marks slots that are in use (and may have login state!)
	slots map[uint]bool
	// Guards the state of the module
	lock sync.Mutex
}

// tokenInfo is a pkcs11.TokenInfo that additionally includes the
// associated slot number/ID.
type tokenInfo struct {
	pkcs11.TokenInfo
	ID uint
}

var (
	// modules holds global references to modules, by path.
	modules = make(map[string]*module)
	// modulesLock guards modules.
	modulesLock = sync.Mutex{}
)

func acquireSlot(path string, number *uint, label string) (*module, *tokenInfo, error) {
	var err error
	path, err = resolveModulePath(path)
	if err != nil {
		return nil, nil, err
	}

	modulesLock.Lock()
	m, ok := modules[path]

	// Load the module
	if !ok {
		ctx := pkcs11.New(path)
		if ctx == nil {
			modulesLock.Unlock()
			return nil, nil, fmt.Errorf("failed to load module %q", path)
		}

		if err := ctx.Initialize(); err != nil {
			ctx.Destroy()
			modulesLock.Unlock()
			return nil, nil, fmt.Errorf("failed to initialize module %q: %w", path, err)
		}

		m = &module{
			ctx:   ctx,
			path:  path,
			slots: make(map[uint]bool),
		}
	}

	m.lock.Lock()
	defer m.lock.Unlock()
	modules[path] = m

	// Release global lock, we have the per-module lock now.
	modulesLock.Unlock()

	info, err := m.findSlot(number, label)
	if err != nil {
		return nil, nil, errors.Join(err, m.finalize())
	}

	// Use of a slot is exclusive, hence acquireSlot. This ensures that PKCS#11 login state
	// (which is global per slot) is not shared between tenants.
	if _, occupied := m.slots[info.ID]; occupied {
		return nil, nil, fmt.Errorf("slot %d of module %q is already in use", info.ID, path)
	}
	m.slots[info.ID] = true

	return m, info, nil
}

func (m *module) releaseSlot(slot uint) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, occupied := m.slots[slot]; !occupied {
		return fmt.Errorf("tried to release slot that was not occupied")
	}

	delete(m.slots, slot)
	return m.finalize()
}

func (m *module) finalize() error {
	// Someone else is still using a slot on the module, keep it.
	if len(m.slots) != 0 {
		return nil
	}

	modulesLock.Lock()
	defer modulesLock.Unlock()

	delete(modules, m.path)

	err := m.ctx.Finalize()
	if err != nil {
		err = fmt.Errorf("failed to pkcs#11 Finalize: %w", err)
	}
	// Destroy even if Finalize failed. If Finalize failed because some network
	// connection is broken, chances are the HSM has already forgotten about us anyways.
	m.ctx.Destroy()
	return err
}

func (m *module) findSlot(number *uint, label string) (*tokenInfo, error) {
	if number == nil && label == "" {
		return nil, fmt.Errorf("at least one of slot number, token label must be set")
	}

	ids, err := m.ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 GetSlotList: %w", err)
	}

	for _, id := range ids {
		info, err := m.ctx.GetTokenInfo(id)
		if err != nil {
			return nil, fmt.Errorf("failed to pkcs#11 GetTokenInfo on slot %d: %w",
				id, err)
		}
		if (number != nil && id == *number) || info.Label == label {
			return &tokenInfo{TokenInfo: info, ID: id}, err
		}
	}

	return nil, fmt.Errorf("no matching token slot found")
}

func resolveModulePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("module path must be set")
	}

	if !strings.Contains(path, "/") {
		// Don't allow dynamic library loading via search paths.
		// This makes it hard for us to track which file is ultimately opened by dlopen.
		// For more context, see the dlopen(3).
		return "", fmt.Errorf("module loading via search paths is not allowed")
	}

	// Best-effort path-deduplication.
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("failed to resolve absolute module path: %w", err)
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("failed to eval symlinks in module path: %w", err)
	}

	return path, nil
}
