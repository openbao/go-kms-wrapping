// Copyright The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/miekg/pkcs11"
)

// sessionPool lends out sessions to a slot, ensuring the amount of concurrent sessions never
// exceeds a maximum number of sessions. sessionPool assumes that sessions are cheap (as they
// should be in a sane PKCS#11 implementation) and thus skips the hassle of storing sessions:
// we only keep a single persistent session to maintain login state (OpenSession should be
// cheap, Login should be expensive), all "working sessions" are short-lived and closed once
// the caller returns it.
type sessionPool struct {
	// Associated pkcs11.Ctx
	ctx *pkcs11.Ctx
	// HSM slot that the pool manages
	slot uint
	// Handle to persistently logged in session
	persistent pkcs11.SessionHandle
	// Maximum amount of sessions
	max uint
	// Amount of currently allocated sessions
	size uint
	// Guards and waits for size
	cond *sync.Cond
	// Marks the pool as closed
	closed bool
}

// DefaultMaxParallel is the maximum amount of sessions allowed by a Pool
// when the HSM is unable to report a MaxSessionCount (CK_UNAVAILABLE_INFORMATION)
// or the reported MaxSessionCount exceeds DefaultMaxParallel.
const DefaultMaxParallel = 1024

// newSessionPool creates a new session pool for a slot.
// A maxSessions value may be specified to override DefaultMaxSessions,
// or set to a value less than 1 to use DefaultMaxSessions.
func newSessionPool(slot *slot, pin string, maxParallel uint) (*sessionPool, error) {
	if maxParallel == 0 {
		maxParallel = DefaultMaxParallel
	}

	switch slot.info.MaxSessionCount {
	case pkcs11.CK_UNAVAILABLE_INFORMATION, pkcs11.CK_EFFECTIVELY_INFINITE:
	default:
		maxParallel = min(maxParallel, slot.info.MaxSessionCount)
	}

	if maxParallel < 2 {
		return nil, fmt.Errorf("session pool: need to create at least 2 sessions, but max_parallel is %d",
			maxParallel)
	}

	// Create our persistent session to keep the the application logged in.
	session, err := slot.ctx.OpenSession(slot.id, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, fmt.Errorf("session pool: failed to create new session for slot %d: %w",
			slot.id, err)
	}
	if loginErr := slot.ctx.Login(session, pkcs11.CKU_USER, pin); loginErr != nil {
		loginErr = fmt.Errorf("session pool: failed to log into slot %d: %w", slot.id, loginErr)
		closeErr := slot.ctx.CloseSession(session)
		return nil, errors.Join(loginErr, closeErr)
	}

	var m sync.Mutex
	p := &sessionPool{
		ctx:        slot.ctx,
		slot:       slot.id,
		persistent: session,
		max:        maxParallel - 1, // Minus the persistent session.
		cond:       sync.NewCond(&m),
	}

	return p, nil
}

// Get takes a fresh session from the pool, waiting for available capacity.
// Context cancellation is respected when waiting for session capacity.
func (p *sessionPool) Get(ctx context.Context) (pkcs11.SessionHandle, error) {
	// Wait for available capacity.
	p.cond.L.Lock()
	defer p.cond.L.Unlock()
	if p.closed {
		return 0, fmt.Errorf("session pool is closed")
	}
	for p.size == p.max {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
			p.cond.Wait()
		}
		if p.closed {
			return 0, fmt.Errorf("session pool is closed")
		}
	}
	// Open a new session, a read-only session is enough for our purposes.
	session, err := p.ctx.OpenSession(p.slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return 0, fmt.Errorf("failed to pkcs#11 OpenSession: %w", err)
	}
	p.size += 1
	return session, nil
}

// Put returns a session to the pool, closing it.
// The caller must ensure that a session is only ever returned once.
func (p *sessionPool) Put(session pkcs11.SessionHandle) error {
	p.cond.L.Lock()
	p.size--
	p.cond.L.Unlock()
	// The best thing we can do if CloseSession fails is assume that is is closed regardless.
	defer p.cond.Signal()
	if err := p.ctx.CloseSession(session); err != nil {
		return fmt.Errorf("failed to pkcs#11 CloseSession: %w", err)
	}
	return nil
}

// Close marks the pool as closed and waits for all sessions to return.
// Once the the closing process begins, no further sessions can be acquired.
func (p *sessionPool) Close() error {
	p.cond.L.Lock()
	defer p.cond.L.Unlock()
	p.closed = true
	for p.size != 0 {
		p.cond.Wait()
	}

	logoutErr := p.ctx.Logout(p.persistent)
	if logoutErr != nil {
		logoutErr = fmt.Errorf("failed to pkcs#11 Logout: %w", logoutErr)
	}
	// Use CloseAllSessions rather than closing just the persistent session for good measure.
	// PKCS#11 says this should also cause a logout but in practice that isn't the case,
	// see Google KMS (https://github.com/GoogleCloudPlatform/kms-integrations) for example.
	closeErr := p.ctx.CloseAllSessions(p.slot)
	if closeErr != nil {
		closeErr = fmt.Errorf("failed to pkcs#11 CloseAllSessions: %w", closeErr)
	}
	return errors.Join(logoutErr, closeErr)
}
