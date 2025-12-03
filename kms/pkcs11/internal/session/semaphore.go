// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package session

import (
	"container/list"
	"context"
	"sync"
)

// semaphoreCloser is a a semaphore closely modeled after
// golang.org/x/sync/semaphore, with the following differences:
//
//   - The semaphore is not weighted; it's always one token in, one token out.
//   - Tokens are tracked as uint instead of int64, this aligns better with
//     PKCS#11's MaxSessionCount value.
//   - The semaphore may be "closed". This cancels all waiters and waits for all
//     missing tokens to return.
//
// I recommend referencing upstream's version to verify the correctness of the
// below here: https://github.com/golang/sync/tree/14be23e5b48bec28285f8a694875175ecacfddb3
type semaphoreCloser struct {
	// These fields are equal to upstream's:
	size, cur uint
	mu        sync.Mutex
	waiters   list.List // This can directly store channels as request size is constant.

	closed bool  // Marks the closed state.
	err    error // A custom error to return when a waiter was cancelled because of a closure.
}

// Acquire attempts acquisition of a single token.
func (s *semaphoreCloser) Acquire(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return s.err
	}
	return s.acquireInternal(ctx)
}

// Release releases a single token previously acquired via Acquire.
func (s *semaphoreCloser) Release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == 0 {
		panic("semaphore: released more than held")
	}
	s.cur--
	s.notify()
}

// Close permanently closes the semaphore and attempts to wait until all
// currently acquired tokens have been released.
func (s *semaphoreCloser) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return s.err
	}

	for elem := s.waiters.Front(); elem != nil; elem = elem.Next() {
		ready := elem.Value.(chan error)
		ready <- s.err
		close(ready)
	}

	s.waiters.Init()
	s.closed = true

	// By setting size = 1, any new calls to acquireInternal will wait until
	// all other outstanding tokens are released.
	s.size = 1

	return s.acquireInternal(ctx)
}

func (s *semaphoreCloser) acquireInternal(ctx context.Context) error {
	done := ctx.Done()
	select {
	case <-done:
		s.mu.Unlock()
		return ctx.Err()
	default:
	}

	if s.cur < s.size && s.waiters.Len() == 0 {
		s.cur++
		s.mu.Unlock()
		return nil
	}

	ready := make(chan error)
	elem := s.waiters.PushBack(ready)
	s.mu.Unlock()

	select {
	case <-done:
		s.mu.Lock()
		defer s.mu.Unlock()
		select {
		case err := <-ready:
			if err == nil {
				s.cur--
				s.notify()
			}
		default:
			isFront := s.waiters.Front() == elem
			s.waiters.Remove(elem)
			if isFront && s.size > s.cur {
				s.notify()
			}
		}
		return ctx.Err()

	case err := <-ready:
		select {
		case <-done:
			s.Release()
			return ctx.Err()
		default:
			return err
		}
	}
}

func (s *semaphoreCloser) notify() {
	next := s.waiters.Front()
	if next == nil || s.cur >= s.size {
		return
	}
	s.cur++
	s.waiters.Remove(next)
	ready := next.Value.(chan error)
	close(ready)
}
