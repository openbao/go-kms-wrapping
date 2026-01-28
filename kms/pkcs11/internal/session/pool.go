// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// package session provides pooled PKCS#11 session management.
package session

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/module"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/softhsm"
	"github.com/stretchr/testify/require"
)

// pool manages a token slot's sessions. Assuming that sessions are cheap and
// client-sided, it skips the complexity of storing and recycling sessions. A
// single persistent session is created and logged in to maintain login state
// across all temporary sessions.
type pool struct {
	mod   *module.Ref
	token *module.Token

	// A single long-lived session that is initially logged in.
	persistent pkcs11.SessionHandle

	// pinHash is the SHA-256 digest of the pin value that was used to log in.
	pinHash []byte

	// The pool's reference count. A value of zero implies a closed pool that
	// has already shut down or is currently doing so.
	refs atomic.Uint32

	// live is closed after successfully logging in the persistent session.
	live chan struct{}
	// dead is closed after removing the pool from the global cache.
	dead chan struct{}

	// sema enforces the maximum session count and tracks active sessions.
	sema *semaphoreCloser
}

// PoolRef is a shared reference to a live session pool.
type PoolRef struct {
	*pool

	_       noCopy
	dropped atomic.Bool
}

type noCopy struct{}

func (noCopy) Lock()   {}
func (noCopy) Unlock() {}

var (
	// cache globally tracks pools.
	cache = make(map[cacheKey]*pool)

	// cacheLock guards cache.
	cacheLock sync.Mutex
)

// cacheKey is used to uniquely identify a pool in the global cache.
type cacheKey struct {
	// slot is the token slot ID.
	slot uint
	// path is the module path.
	path string
}

// Login creates a new session pool and logs it in, or attempts to reuse an
// existing pool from a global cache.
func Login(ctx context.Context, mod *module.Ref, token *module.Token, pin string) (*PoolRef, error) {
	// This avoids keeping the PIN value around in plaintext and enables
	// constant time comparisons. Probably overkill, but why not?
	h := sha256.New()
	if _, err := h.Write([]byte(pin)); err != nil {
		return nil, fmt.Errorf("failed to hash pin: %w", err)
	}

	k := cacheKey{token.ID, mod.Path()}

	for {
		cacheLock.Lock()
		p, ok := cache[k]
		if !ok {
			// Keep the lock and break out to insert our own value.
			break
		}
		cacheLock.Unlock()

		select {
		case <-p.live:
		case <-p.dead:
			continue // Try again.
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		if subtle.ConstantTimeCompare(h.Sum(nil), p.pinHash) == 0 {
			return nil, errors.New("inconsistent pin values")
		}

		if _, ok := p.incRefs(); !ok {
			// Too bad, the pool closed just now, wait for it to die.
			select {
			case <-p.dead:
				continue // Then try again.
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		// Pool sharing is successful!
		return &PoolRef{pool: p}, nil
	}

	var maxSessions uint
	switch token.Info.MaxSessionCount {
	case pkcs11.CK_UNAVAILABLE_INFORMATION, pkcs11.CK_EFFECTIVELY_INFINITE:
		maxSessions = math.MaxUint
	default:
		maxSessions = token.Info.MaxRwSessionCount
	}

	if maxSessions < 2 {
		cacheLock.Unlock()
		return nil, fmt.Errorf("need to create at least 2 sessions, but max session count is %d", maxSessions)
	}

	p := &pool{
		mod:     mod,
		token:   token,
		pinHash: h.Sum(nil),
		live:    make(chan struct{}),
		dead:    make(chan struct{}),
		sema: &semaphoreCloser{
			size: maxSessions - 1, // Minus the persistent session.
			err:  errors.New("session pool is closed"),
		},
	}
	p.refs.Store(1)

	// Optimistically insert the pool into the global cache. Other callers can
	// now wait until login is finished by selecting on live/dead.
	cache[k] = p
	cacheLock.Unlock()

	defer func() {
		select {
		case <-p.live:
			// We're okay.
		default:
			// Rollback the optimistic cache insertion.
			cacheLock.Lock()
			delete(cache, k)
			cacheLock.Unlock()
			close(p.dead)
		}
	}()

	// Create our initial persistent session.
	session, err := mod.OpenSession(token.ID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, mapErr(err, "OpenSession")
	}

	// Then log it in.
	if err := mod.Login(session, pkcs11.CKU_USER, pin); err != nil {
		return nil, errors.Join(
			mapErr(err, "Login"),
			mapErr(mod.CloseSession(session), "CloseSession"),
		)
	}

	p.persistent = session
	close(p.live)

	return &PoolRef{pool: p}, nil
}

// Get a new session, waiting for available capacity if needed. Note that this
// method supports context cancellation such that requests can time out on
// highly constrained pool sizes.
func (p *pool) Get(ctx context.Context) (*Handle, error) {
	if err := p.sema.Acquire(ctx); err != nil {
		return nil, err
	}

	var h *Handle
	defer func() {
		// Checking err != nil would not catch a panic.
		if h == nil {
			p.sema.Release()
		}
	}()

	// Open a new session and grow the pool.
	session, err := p.mod.OpenSession(p.token.ID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, mapErr(err, "OpenSession")
	}

	h = &Handle{pool: p, session: session}
	return h, nil
}

// put returns a session to the pool, closing it and reducing the pool's size.
// Callers must ensure not to return a session multiple times.
func (p *pool) put(session pkcs11.SessionHandle) error {
	defer p.sema.Release()
	return mapErr(p.mod.CloseSession(session), "CloseSession")
}

// Drop decrements the pool's reference count. If the pool's reference count
// reaches zero, it will permanently close, log out the persistent session and
// remove itself from the global cache.
func (p *PoolRef) Drop(ctx context.Context) error {
	if !p.dropped.CompareAndSwap(false, true) {
		return errors.New("reference was already dropped")
	}

	if refs, ok := p.decRefs(); !ok || refs != 0 {
		// Other references remain, bail here.
		return nil
	}

	defer func() {
		// Remove ourselves from the global cache:
		cacheLock.Lock()
		delete(cache, cacheKey{p.token.ID, p.mod.Path()})
		cacheLock.Unlock()

		// Notify waiters in Login() that we've made our exit.
		close(p.dead)
	}()

	return errors.Join(
		// Drain the pool. If context times out here, the caller must handle
		// not dropping the PKCS#11 module before ceasing usage of any remaining
		// sessions to avoid risking undefined behavior.
		p.sema.Close(ctx),
		// Then log out and close all sessions regardless of the above
		// potentially failing to collect all outstanding sessions. If sessions
		// remain, the caller must ensure not to close the underlying PKCS#11
		// module until no more session handles are in use to avoid undefined
		// behavior.
		mapErr(p.mod.Logout(p.persistent), "Logout"),
		mapErr(p.mod.CloseAllSessions(p.token.ID), "CloseAllSessions"),
	)
}

// incRefs atomically increments the pool's reference count and returns
// (refcount, true). If a reference count of zero is seen, this fails and
// returns (0, false).
func (p *pool) incRefs() (uint, bool) {
	for {
		refs := p.refs.Load()
		if refs == 0 {
			return 0, false
		}
		if p.refs.CompareAndSwap(refs, refs+1) {
			return uint(refs) + 1, true
		}
	}
}

// decRefs atomically decrements the pool's reference count and returns
// (refcount, true). If a reference count of zero is seen, this fails and
// returns (0, false).
func (p *pool) decRefs() (uint, bool) {
	for {
		refs := p.refs.Load()
		if refs == 0 {
			return 0, false
		}
		if p.refs.CompareAndSwap(refs, refs-1) {
			return uint(refs) - 1, true
		}
	}
}

// Scope calls f with a session handle that is valid only within f's scope.
func (p *pool) Scope(ctx context.Context, f func(s *Handle) (err error)) error {
	s, err := p.Get(ctx)
	if err != nil {
		return err
	}

	// Don't break the pool's integrity even if the callback panics.
	defer func() {
		err = errors.Join(err, s.Close())
	}()

	err = f(s)
	return err
}

// Scope wraps pool.Scope and adds a generic return value to make returning
// results from cryptographic operations easy.
func Scope[T any](ctx context.Context, p *PoolRef, f func(s *Handle) (T, error)) (T, error) {
	var ret T
	err := p.Scope(ctx, func(s *Handle) (err error) {
		ret, err = f(s)
		return err
	})
	return ret, err
}

// mapErr adds the respective PKCS#11 operation to an error if it is non-nil.
func mapErr(err error, op string) error {
	if err == nil {
		return nil
	} else {
		return fmt.Errorf("failed to pkcs#11 %s: %w", op, err)
	}
}

// Module returns the pool's module reference.
func (p *pool) Module() *module.Ref {
	return p.mod
}

// Token returns the pool's token reference.
func (p *pool) Token() *module.Token {
	return p.token
}

// TestLogin is a test helper that logs into a pool and automatically drops it
// on test completion, handling all errors.
func TestLogin(t *testing.T, mod *module.Ref, token *module.Token, pin string) *PoolRef {
	t.Helper()

	pool, err := Login(t.Context(), mod, token, pin)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, pool.Drop(context.Background()))
	})

	return pool
}

// TestPool is a test helper that creates a SoftHSM test & token, loads a module
// and logs a pool into the token. This is a convenient shortcuts for tests that
// don't concern themselves with multi-slot testing.
func TestPool(t *testing.T) *PoolRef {
	t.Helper()

	softhsm := softhsm.New(t)
	label, pin := softhsm.InitToken()

	mod := module.TestOpen(t, softhsm.Path)
	token, err := mod.GetToken(module.SelectLabel(label))
	require.NoError(t, err)

	return TestLogin(t, mod, token, pin)
}

// TestSession calls TestPool and returns a session that is automatically closed
// on test completion.
func TestSession(t *testing.T) (*Handle, *PoolRef) {
	t.Helper()

	p := TestPool(t)
	s, err := p.Get(t.Context())
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, s.Close())
	})

	return s, p
}
