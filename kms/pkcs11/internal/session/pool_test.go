// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package session

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/module"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	module.TestSetup(m)
}

func Test(t *testing.T) {
	mod, tokens := module.TestTokens(t, 2)
	token1, token2 := tokens[0], tokens[1]

	t.Run("Login+Drop", func(t *testing.T) {
		t.Run("Cache", func(t *testing.T) {
			ctx := t.Context()

			p1, err := Login(ctx, mod, token1, module.TestPin+"foo")
			require.Error(t, err, "incorrect pin should not work")
			require.Nil(t, p1, "should not return a pool")
			require.Len(t, cache, 0, "cache should have zero entries")

			p1, err = Login(ctx, mod, token1, module.TestPin)
			require.NoError(t, err, "correct pin should work")
			require.NotNil(t, p1, "should return a pool")
			require.Len(t, cache, 1, "cache should have one entry")

			p2, err := Login(ctx, mod, token2, module.TestPin)
			require.NoError(t, err, "correct pin should work")
			require.NotNil(t, p2, "should return a pool")
			require.Len(t, cache, 2, "cache should two entries")

			require.NoError(t, p2.Drop(ctx), "pool should drop")
			require.Len(t, cache, 1, "cache should have one entry")

			require.NoError(t, p1.Drop(ctx), "pool should drop")
			require.Len(t, cache, 0, "cache should have no more entries")
		})

		t.Run("Sharing", func(t *testing.T) {
			ctx := t.Context()

			p1, err := Login(ctx, mod, token1, module.TestPin)
			require.NoError(t, err, "correct pin should work")
			require.NotNil(t, p1, "should return a pool")
			require.Len(t, cache, 1, "cache should have one entry")
			require.Equal(t, uint32(1), p1.refs.Load(), "pool should have one reference")

			p2, err := Login(ctx, mod, token1, "foo")
			require.ErrorContains(t, err, "inconsistent pin values", "existing pool should reject inconsistent pin")
			require.Nil(t, p2, "should not return a pool")
			require.Equal(t, uint32(1), p1.refs.Load(), "pool should still have one reference")

			p2, err = Login(ctx, mod, token1, module.TestPin)
			require.NoError(t, err, "correct pin should work")
			require.NotNil(t, p2, "should return a pool")
			require.Len(t, cache, 1, "cache should still have one entry")
			require.Equal(t, uint32(2), p2.refs.Load(), "pool should have two references")
			require.Equal(t, p1.pool, p2.pool, "referenced pools should be equal")

			require.NoError(t, p2.Drop(ctx), "reference should drop")
			require.Equal(t, uint32(1), p1.refs.Load(), "pool should have one reference")
			require.Len(t, cache, 1, "cache should still have one entry")

			require.Error(t, p2.Drop(ctx), "should error dropping previously dropped reference")
			require.Equal(t, uint32(1), p1.refs.Load(), "pool should still have one reference")
			require.Len(t, cache, 1, "cache should still have one entry")

			require.NoError(t, p1.Drop(ctx), "reference should drop")
			require.Equal(t, uint32(0), p1.refs.Load(), "pool should have no more references")
			require.Len(t, cache, 0, "cache should have no more entries")

			pinHash := p1.pinHash
			k := cacheKey{token1.ID, mod.Path()}

			// Test that a shared pool acquisition will successfully wait for
			// the "live" channel to close before incrementing the reference
			// count.
			synctest.Test(t, func(t *testing.T) {
				fake := &pool{
					live:    make(chan struct{}),
					dead:    make(chan struct{}),
					pinHash: pinHash,
				}

				fake.refs.Store(1)
				cache[k] = fake

				timeoutCtx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
				defer cancel()
				_, err := Login(timeoutCtx, mod, token1, module.TestPin)
				require.Error(t, err, "should time out waiting for pool to go live")

				errs := make([]error, 10)
				for i := range errs {
					go func(i int) {
						_, errs[i] = Login(t.Context(), mod, token1, module.TestPin)
					}(i)
				}

				synctest.Wait()

				for _, err := range errs {
					require.NoError(t, err, "login should not already fail")
				}
				require.Equal(t, uint32(1), fake.refs.Load(), "pool should still have one reference")

				close(fake.live)
				synctest.Wait()

				for _, err := range errs {
					require.NoError(t, err, "login should not have failed")
				}
				require.Equal(t, uint32(len(errs)+1), fake.refs.Load(), "each job should have incremented the reference count")

				delete(cache, k)
			})

			// Test that a shared pool acquisition will create its own pool if
			// the dead channel is closed.
			synctest.Test(t, func(t *testing.T) {
				fake := &pool{
					live:    make(chan struct{}),
					dead:    make(chan struct{}),
					pinHash: pinHash,
				}

				cache[k] = fake

				// We split jobs into two groups, the first 5 will start before
				// closing live, others will start after closing live.
				errs := make([]error, 10)
				refs := make([]*PoolRef, len(errs))

				for i := range len(errs) / 2 {
					go func(i int) {
						refs[i], errs[i] = Login(t.Context(), mod, token1, module.TestPin)
					}(i)
				}

				synctest.Wait()

				for _, err := range errs {
					require.NoError(t, err, "login should not already fail")
				}
				require.Equal(t, uint32(0), fake.refs.Load(), "pool should still have no references")

				close(fake.live)
				synctest.Wait()

				// Because we've closed live and have zero references, existing
				// jobs should now wait for dead to close.
				for _, err := range errs {
					require.NoError(t, err, "login should not already fail")
				}
				require.Equal(t, uint32(0), fake.refs.Load(), "pool should still have no references")

				// Start the remaining jobs
				for i := range len(errs) / 2 {
					go func(i int) {
						refs[i], errs[i] = Login(t.Context(), mod, token1, module.TestPin)
					}(i + len(errs)/2)
				}

				timeoutCtx, cancel := context.WithTimeout(ctx, time.Millisecond)
				defer cancel()
				_, err := Login(timeoutCtx, mod, token1, module.TestPin)
				require.Error(t, err, "should time out waiting for pool to go dead")

				// Closing dead implies the pool was removed from cache, so
				// mirror that behavior.
				delete(cache, k)
				close(fake.dead)
				synctest.Wait()

				for _, err := range errs {
					require.NoError(t, err, "login should not have failed")
				}

				p := cache[k]
				require.NotNil(t, p, "cache should have a new pool")
				require.Equal(t, uint32(len(errs)), p.refs.Load(), "pool should have as many references as jobs")

				for _, p := range refs {
					require.NoError(t, p.Drop(ctx), "reference should drop")
				}

				require.Equal(t, uint32(0), p.refs.Load(), "pool should have no more references")
				require.Len(t, cache, 0, "cache should be empty")
			})
		})
	})

	t.Run("Get+Close", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := t.Context()
			p := TestLogin(t, mod, token1)

			// Simulate a low MaxSessionCount.
			p.pool.sema.size = 2

			s1, err := p.Get(ctx)
			require.NoError(t, err, "pool should have available sessions")

			_, err = s1.GenerateRandom(1)
			require.NoError(t, err, "session should work")

			s2, err := p.Get(ctx)
			require.NoError(t, err, "pool should have available sessions")

			// The third session should block, assert this via synctest.
			var s3 *Handle
			go func() {
				s3, err = p.Get(ctx)
			}()

			synctest.Wait()

			require.NoError(t, err, "should not error yet")
			require.Nil(t, s3, "should not have a handle yet")

			require.NoError(t, s1.Close(), "session should close")
			require.Error(t, s1.Close(), "session should not close twice")
			synctest.Wait()

			require.NoError(t, err, "should not error getting session handle")
			require.NotNil(t, s3, "should have a session handle")

			// The session pool now exhausted again, check that an acquisition
			// is also cancelable via context.
			cancelCtx, cancel := context.WithCancel(ctx)
			var s4 *Handle
			go func() {
				s4, err = p.Get(cancelCtx)
			}()

			synctest.Wait()

			require.NoError(t, err, "should not error yet")
			require.Nil(t, s4, "should not have a session handle")

			cancel()
			synctest.Wait()

			require.ErrorIs(t, err, context.Canceled, "should get a context canceled error")
			require.NotNil(t, s3, "should not have a session handle")

			require.NoError(t, s2.Close(), "session should close")
			require.NoError(t, s3.Close(), "session should close")
		})

		t.Run("Drop", func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := t.Context()

				p, err := Login(ctx, mod, token1, module.TestPin)
				require.NoError(t, err, "correct pin should work")

				// Simulate a low MaxSessionCount.
				p.pool.sema.size = 2

				s1, err := p.Get(ctx)
				require.NoError(t, err, "pool should have available sessions")

				s2, err := p.Get(ctx)
				require.NoError(t, err, "pool should have available sessions")

				go func() {
					_, err := p.Get(ctx)
					if err == nil {
						// This is queued before dropping the pool, and should
						// never acquire a session.
						panic("did not expect a session")
					}
				}()

				synctest.Wait()

				go func() {
					// This should block until sessions are closed at the end of
					// the test.
					if err := p.Drop(ctx); err != nil {
						panic(err)
					}
				}()

				synctest.Wait()
				require.Len(t, cache, 1, "pool should still be live")

				_, err = s1.GenerateRandom(1)
				require.NoError(t, err, "session should still work")

				require.NoError(t, s1.Close(), "session should close")
				require.NoError(t, s2.Close(), "session should close")

				synctest.Wait()
				require.Len(t, cache, 0, "pool should be dead")

				_, err = p.Get(ctx)
				require.Error(t, err, "pool should not create new sessions")
			})
		})

		t.Run("Scope", func(t *testing.T) {
			ctx := t.Context()
			p := TestLogin(t, mod, token1)

			var escaped *Handle

			p.Scope(ctx, func(s *Handle) error {
				escaped = s
				_, err := s.GenerateRandom(1)
				require.NoError(t, err, "session should work inside scope")
				return nil
			})

			_, err := escaped.GenerateRandom(1)
			require.Error(t, err, "session should not work outside of scope")

			defer func() {
				if r := recover(); r != nil {
					// The session should have closed even on panic.
					_, err = escaped.GenerateRandom(1)
					require.Error(t, err, "session was not closed by panic")
				} else {
					require.FailNow(t, "expected panic")
				}
			}()

			p.Scope(t.Context(), func(s *Handle) error {
				escaped = s
				panic("catch me")
			})
		})
	})
}
