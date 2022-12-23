/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"

	apiutils "github.com/gravitational/teleport/api/utils"
)

func TestFnCache_New(t *testing.T) {
	cases := []struct {
		desc      string
		config    FnCacheConfig
		assertion require.ErrorAssertionFunc
	}{
		{
			desc:      "invalid ttl",
			config:    FnCacheConfig{TTL: 0},
			assertion: require.Error,
		},

		{
			desc:      "valid ttl",
			config:    FnCacheConfig{TTL: time.Second},
			assertion: require.NoError,
		},
	}

	for _, tt := range cases {
		t.Run(tt.desc, func(t *testing.T) {
			_, err := NewFnCache(tt.config)
			tt.assertion(t, err)
		})
	}
}

type result struct {
	val any
	err error
}

func TestFnCacheGet(t *testing.T) {
	cache, err := NewFnCache(FnCacheConfig{
		TTL:     time.Second,
		Clock:   clockwork.NewFakeClock(),
		Context: context.Background(),
	})
	require.NoError(t, err)

	value, err := cache.get(context.Background(), "test", func(ctx context.Context) (any, error) {
		return 123, nil
	})
	require.NoError(t, err)
	require.Equal(t, 123, value)

	value2, err := FnCacheGet(context.Background(), cache, "test", func(ctx context.Context) (int, error) {
		return value.(int), nil
	})
	require.NoError(t, err)
	require.Equal(t, value2, 123)

	value3, err := FnCacheGet(context.Background(), cache, "test", func(ctx context.Context) (string, error) {
		return "123", nil
	})
	require.ErrorIs(t, err, trace.BadParameter("value retrieved was int, expected string"))
	require.Empty(t, value3)
}

// TestFnCacheConcurrentReads verifies that many concurrent reads result in exactly one
// value being actually loaded via loadfn if a reasonably long TTL is used.
func TestFnCacheConcurrentReads(t *testing.T) {
	const workers = 100
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// set up a chage that won't ttl out values during the test
	cache, err := NewFnCache(FnCacheConfig{TTL: time.Hour})
	require.NoError(t, err)

	results := make(chan result, workers)

	for i := 0; i < workers; i++ {
		go func(n int) {
			val, err := cache.get(ctx, "key", func(context.Context) (any, error) {
				// return a unique value for each worker so that we can verify whether
				// the values we get come from the same loadfn or not.
				return fmt.Sprintf("val-%d", n), nil
			})
			results <- result{val, err}
		}(i)
	}

	first := <-results
	require.NoError(t, first.err)

	val := first.val.(string)
	require.NotZero(t, val)

	for i := 0; i < (workers - 1); i++ {
		r := <-results
		require.NoError(t, r.err)
		require.Equal(t, val, r.val.(string))
	}
}

// TestFnCacheExpiry verfies basic expiry.
func TestFnCacheExpiry(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := clockwork.NewFakeClock()

	cache, err := NewFnCache(FnCacheConfig{TTL: time.Millisecond, Clock: clock})
	require.NoError(t, err)

	// get is helper for checking if we hit/miss
	get := func() (load bool) {
		val, err := FnCacheGet(ctx, cache, "key", func(context.Context) (string, error) {
			load = true
			return "val", nil
		})
		require.NoError(t, err)
		require.Equal(t, "val", val)
		return
	}

	// first get runs the loadfn
	require.True(t, get())

	// subsequent gets use the cached value
	for i := 0; i < 20; i++ {
		require.False(t, get())
	}

	clock.Advance(time.Millisecond * 2)

	// value has ttl'd out, loadfn is run again
	require.True(t, get())

	// and now we're back to hitting a cached value
	require.False(t, get())
}

// TestFnCacheFuzzy runs basic FnCache test cases that rely on fuzzy logic and timing to detect
// success/failure. This test isn't really suitable for running in our CI env due to its sensitivery
// to fluxuations in perf, but is arguably a *better* test in that it more accurately simulates real
// usage. This test should be run locally with TEST_FNCACHE_FUZZY=yes when making changes.
func TestFnCacheFuzzy(t *testing.T) {
	if run, _ := apiutils.ParseBool(os.Getenv("TEST_FNCACHE_FUZZY")); !run {
		t.Skip("Test disabled in CI. Enable it by setting env variable TEST_FNCACHE_FUZZY=yes")
	}

	tts := []struct {
		ttl   time.Duration
		delay time.Duration
		desc  string
	}{
		{ttl: time.Millisecond * 40, delay: time.Millisecond * 20, desc: "long ttl, short delay"},
		{ttl: time.Millisecond * 20, delay: time.Millisecond * 40, desc: "short ttl, long delay"},
		{ttl: time.Millisecond * 40, delay: time.Millisecond * 40, desc: "long ttl, long delay"},
		{ttl: time.Millisecond * 40, delay: 0, desc: "non-blocking"},
	}

	for _, tt := range tts {
		t.Run(tt.desc, func(t *testing.T) {
			testFnCacheFuzzy(t, tt.ttl, tt.delay)
		})
	}
}

// testFnCacheFuzzy runs a basic test case which spams concurrent request against a cache
// and verifies that the resulting hit/miss numbers roughly match our expectation.
func testFnCacheFuzzy(t *testing.T, ttl time.Duration, delay time.Duration) {
	const rate = int64(20)     // get attempts per worker per ttl period
	const workers = int64(100) // number of concurrent workers
	const rounds = int64(10)   // number of full ttl cycles to go through

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cache, err := NewFnCache(FnCacheConfig{TTL: ttl})
	require.NoError(t, err)

	// readCounter is incremented upon each cache miss.
	readCounter := atomic.NewInt64(0)

	// getCounter is incremented upon each get made against the cache, hit or miss.
	getCounter := atomic.NewInt64(0)

	readTime := make(chan time.Time, 1)

	var wg sync.WaitGroup

	// spawn workers
	for w := int64(0); w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(ttl / time.Duration(rate))
			defer ticker.Stop()
			done := time.After(ttl * time.Duration(rounds))
			lastValue := int64(0)
			for {
				select {
				case <-ticker.C:
				case <-done:
					return
				}
				vi, err := FnCacheGet(ctx, cache, "key", func(context.Context) (int64, error) {
					if delay > 0 {
						<-time.After(delay)
					}

					select {
					case readTime <- time.Now():
					default:
					}

					val := readCounter.Inc()
					return val, nil
				})
				require.NoError(t, err)
				require.GreaterOrEqual(t, vi, lastValue)
				lastValue = vi
				getCounter.Inc()
			}
		}()
	}

	startTime := <-readTime

	// wait for workers to finish
	wg.Wait()

	elapsed := time.Since(startTime)

	// approxReads is the approximate expected number of reads
	approxReads := float64(elapsed) / float64(ttl+delay)

	// verify that number of actual reads is within +/- 2 of the number of expected reads.
	require.InDelta(t, approxReads, readCounter.Load(), 2)
}

// TestFnCacheCancellation verifies expected cancellation behavior.  Specifically, we expect that
// in-progress loading continues, and the entry is correctly updated, even if the call to Get
// which happened to trigger the load needs to be unblocked early.
func TestFnCacheCancellation(t *testing.T) {
	t.Parallel()

	const longTimeout = time.Second * 10 // should never be hit

	cache, err := NewFnCache(FnCacheConfig{TTL: time.Minute})
	require.NoError(t, err)

	// used to artificially block the load function
	blocker := make(chan struct{})

	// set up a context that we can cancel from within the load function to
	// simulate a scenario where the calling context is canceled or times out.
	// if we actually hit the timeout, that is a bug.
	ctx, cancel := context.WithTimeout(context.Background(), longTimeout)
	defer cancel()

	v, err := FnCacheGet(ctx, cache, "key", func(context.Context) (string, error) {
		cancel()
		<-blocker
		return "val", nil
	})

	require.Empty(t, v)
	require.Equal(t, context.Canceled, trace.Unwrap(err), "context should have been canceled immediately")

	// unblock the loading operation which is still in progress
	close(blocker)

	// since we unblocked the loadfn, we expect the next Get to return almost
	// immediately.  we still use a fairly long timeout just to ensure that failure
	// is due to an actual bug and not due to resource constraints in the test env.
	ctx, cancel = context.WithTimeout(context.Background(), longTimeout)
	defer cancel()

	loadFnWasRun := atomic.NewBool(false)
	v, err = FnCacheGet(ctx, cache, "key", func(context.Context) (string, error) {
		loadFnWasRun.Store(true)
		return "", nil
	})

	require.False(t, loadFnWasRun.Load(), "loadfn should not have been run")

	require.NoError(t, err)
	require.Equal(t, "val", v)
}

func TestFnCacheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cache, err := NewFnCache(FnCacheConfig{
		TTL:     time.Minute,
		Context: ctx,
	})
	require.NoError(t, err)

	_, err = cache.get(context.Background(), "key", func(context.Context) (any, error) {
		return "val", nil
	})
	require.NoError(t, err)

	cancel()

	_, err = cache.get(context.Background(), "key", func(context.Context) (any, error) {
		return "val", nil
	})
	require.ErrorIs(t, err, ErrFnCacheClosed)
}

func TestFnCacheReloadOnErr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cache, err := NewFnCache(FnCacheConfig{
		TTL:         time.Minute,
		ReloadOnErr: true,
	})
	require.NoError(t, err)

	happy := atomic.NewInt64(0)
	sad := atomic.NewInt64(0)

	// test synchronous case, all sad path loads should result in
	// calls to loadfn.
	for i := 0; i < 100; i++ {
		FnCacheGet(ctx, cache, "happy", func(ctx context.Context) (string, error) {
			happy.Inc()
			return "yay!", nil
		})

		FnCacheGet(ctx, cache, "sad", func(ctx context.Context) (string, error) {
			sad.Inc()
			return "", fmt.Errorf("uh-oh")
		})
	}
	require.Equal(t, int64(1), happy.Load())
	require.Equal(t, int64(100), sad.Load())

	// test concurrent case. some "sad" loads should overlap now.
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			FnCacheGet(ctx, cache, "happy", func(ctx context.Context) (string, error) {
				happy.Inc()
				return "yay!", nil
			})
		}()

		go func() {
			defer wg.Done()
			FnCacheGet(ctx, cache, "sad", func(ctx context.Context) (string, error) {
				sad.Inc()
				return "", fmt.Errorf("uh-oh")
			})
		}()
	}
	require.Equal(t, int64(1), happy.Load())
	require.Greater(t, int64(200), sad.Load())
}
