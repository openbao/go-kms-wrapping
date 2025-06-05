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

// sessionPool lends out sessions to a slot, ensuring the amount of
// concurrent sessions never exceeds a maximum number of sessions.
// New sessions are opened on demand, but only closed once the
// entire pool is closed.
type sessionPool struct {
	// Associated pkcs11.Ctx
	ctx *pkcs11.Ctx
	// HSM slot that the pool manages
	slot uint
	// Maximum amount of sessions
	cap int
	// Amount of allocated sessions
	size int
	// Guards size
	lock sync.Mutex
	// Session buffer
	sessions chan pkcs11.SessionHandle
}

// DefaultMaxSessions is the maximum amount of sessions allowed by a Pool
// when the HSM is unable to report a MaxSessionCount (CK_UNAVAILABLE_INFORMATION)
// or the reported MaxSessionCount exceeds DefaultMaxSessions.
const DefaultMaxSessions = 1024

// newSessionPool creates a new session pool for a slot.
// A maxSessions value may be specified to override DefaultMaxSessions,
// or set to a value less than 1 to use DefaultMaxSessions.
func newSessionPool(slot *slot, pin string, cap int) (*sessionPool, error) {
	if cap < 1 {
		cap = DefaultMaxSessions
	}

	switch slot.info.MaxSessionCount {
	case pkcs11.CK_UNAVAILABLE_INFORMATION, pkcs11.CK_EFFECTIVELY_INFINITE:
	default:
		cap = int(min(uint(cap), slot.info.MaxSessionCount))
	}

	if cap < 1 {
		return nil, fmt.Errorf("session pool: max sessions for slot %d must be at least one", slot.id)
	}

	// Create an initial session to log the application in.
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

	p := &sessionPool{
		ctx:      slot.ctx,
		slot:     slot.id,
		cap:      cap,
		size:     1,
		sessions: make(chan pkcs11.SessionHandle, cap),
	}
	// Buffer the initial session
	p.sessions <- session

	return p, nil
}

// Get takes a session from the pool, growing the pool if necessary and possible.
// Context cancellation is respected when waiting for a session to free up.
func (p *sessionPool) Get(ctx context.Context) (pkcs11.SessionHandle, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if p.size == 0 {
		return 0, fmt.Errorf("session pool is closed")
	}

	// Fast path, take right from the buffer.
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case session := <-p.sessions:
		return session, nil
	default:
	}

	// We may create a new session!
	if p.size < p.cap {
		// Open a new session, a read-only session is enough for our purposes.
		session, err := p.ctx.OpenSession(p.slot, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			return 0, fmt.Errorf("session pool: failed to create new session for slot %d: %w",
				p.slot, err)
		}
		p.size++
		return session, nil
	}

	// We can't create our own session, wait for someone to return one back.
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case session, ok := <-p.sessions:
		if !ok {
			return 0, fmt.Errorf("session pool is closed")
		}
		return session, nil
	}
}

// Put returns a session to the pool.
// The caller must ensure that a session is only ever returned once.
func (p *sessionPool) Put(session pkcs11.SessionHandle) {
	p.sessions <- session
}

// Close marks the pool as closed and closes all sessions.
// Once the pool is closed, no further sessions can be acquired.
func (p *sessionPool) Close(ctx context.Context) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	// Drain the pool, waiting for sessions to return.
	for range p.size {
		select {
		case <-p.sessions:
		case <-ctx.Done():
			// Size 0 marks a closed session pool.
			p.size = 0
			// Forcefully close sessions:
			err := p.ctx.CloseAllSessions(p.slot)
			return errors.Join(ctx.Err(), err)
		}
	}

	// Size 0 marks a closed session pool.
	p.size = 0
	// Closing all sessions also causes a logout.
	return p.ctx.CloseAllSessions(p.slot)
}
