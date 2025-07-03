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

// sessionPool creates sessions for a slot, ensuring the amount of concurrent
// sessions never exceeds the given maximum. sessionPool assumes that sessions
// are cheap (modern PKCS#11 implementations handle sessions only on the
// "library side") and thus skips the complexity storing and reusing sessions.
// We do keep a single persistent session to maintain login state (OpenSession
// should be cheap and local, but Login likely requires a remote call)
type sessionPool struct {
	// Associated pkcs11.Ctx
	ctx *pkcs11.Ctx
	// Slot number that the pool manages
	slot uint
	// Handle to persistently logged in session
	persistent pkcs11.SessionHandle
	// Maximum sessions
	max uint
	// Number of allocated sessions
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

// newSessionPool creates a new session pool for a slot. The maxParallel value
// may be lowered to the MaxSessionCount reported by the HSM if necessary. A
// maxParallel value of 0 defaults to DefaultMaxParallel.
func newSessionPool(
	ctx *pkcs11.Ctx, info *tokenInfo, pin string, maxParallel uint,
) (*sessionPool, error) {
	if maxParallel == 0 {
		maxParallel = DefaultMaxParallel
	}

	switch info.MaxSessionCount {
	case pkcs11.CK_UNAVAILABLE_INFORMATION, pkcs11.CK_EFFECTIVELY_INFINITE:
	default:
		maxParallel = min(maxParallel, info.MaxSessionCount)
	}

	if maxParallel < 2 {
		return nil, fmt.Errorf("need to create at least 2 sessions, but only allowed to create %d",
			maxParallel)
	}

	// Create our persistent session to keep the the application logged in.
	session, err := ctx.OpenSession(info.ID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to pkcs#11 OpenSession: %w", err)
	}
	if err := ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
		return nil, errors.Join(
			wrapErr(err, "failed to pkcs#11 Login"),
			wrapErr(ctx.CloseSession(session), "failed to pkcs#11 CloseSession"),
		)
	}

	var m sync.Mutex
	p := &sessionPool{
		ctx:        ctx,
		slot:       info.ID,
		persistent: session,
		max:        maxParallel - 1, // Minus the persistent session.
		cond:       sync.NewCond(&m),
	}
	return p, nil
}

// create a new session, waiting for available capacity if needed.
func (p *sessionPool) create(ctx context.Context) (pkcs11.SessionHandle, error) {
	p.cond.L.Lock()
	defer p.cond.L.Unlock()
	if p.closed {
		return 0, fmt.Errorf("session pool is closed")
	}
	// Wait for available capacity.
	for p.size == p.max {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
			p.cond.Wait()
		}
		// Since we called Wait(), the pool might have closed.
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

// done closes the session, freeing pool capacity.
// The caller must ensure that this function is only called once per session.
func (p *sessionPool) done(session pkcs11.SessionHandle) error {
	p.cond.L.Lock()
	p.size--
	p.cond.L.Unlock()
	// The best thing we can do if CloseSession fails is assume that it is closed regardless.
	defer p.cond.Signal()
	if err := p.ctx.CloseSession(session); err != nil {
		return fmt.Errorf("failed to pkcs#11 CloseSession: %w", err)
	}
	return nil
}

// close marks the pool as closed and waits for all sessions
// to be returned via [sessionPool.put].
func (p *sessionPool) close() error {
	// Close and drain the pool:
	p.cond.L.Lock()
	defer p.cond.L.Unlock()
	p.closed = true
	for p.size != 0 {
		p.cond.Wait()
	}

	return errors.Join(
		wrapErr(p.ctx.Logout(p.persistent), "failed to pkcs#11 Logout"),
		// Use CloseAllSessions rather than closing just the persistent session for
		// good measure. PKCS#11 says this should also cause a logout but in
		// practice that isn't the case, for example see Google's PKCS#11 library:
		// https://github.com/GoogleCloudPlatform/kms-integrations
		wrapErr(p.ctx.CloseAllSessions(p.slot), "failed to pkcs#11 CloseAllSessions"),
	)
}
