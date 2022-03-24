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

package prompt

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/term"
)

func TestContextReader(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() { pr.Close() })
	t.Cleanup(func() { pw.Close() })

	write := func(t *testing.T, s string) {
		_, err := pw.Write([]byte(s))
		assert.NoError(t, err, "Write failed")
	}

	ctx := context.Background()
	cr := NewContextReader(pr)

	t.Run("simple read", func(t *testing.T) {
		go write(t, "hello")
		buf, err := cr.ReadContext(ctx)
		require.NoError(t, err)
		require.Equal(t, string(buf), "hello")
	})

	t.Run("reclaim abandoned read", func(t *testing.T) {
		done := make(chan struct{})
		cancelCtx, cancel := context.WithCancel(ctx)
		go func() {
			time.Sleep(1 * time.Millisecond) // give ReadContext time to block
			cancel()
			write(t, "after cancel")
			close(done)
		}()
		buf, err := cr.ReadContext(cancelCtx)
		require.ErrorIs(t, err, context.Canceled)
		require.Empty(t, buf)

		<-done // wait for write
		buf, err = cr.ReadContext(ctx)
		require.NoError(t, err)
		require.Equal(t, string(buf), "after cancel")
	})

	t.Run("close ContextReader", func(t *testing.T) {
		go func() {
			time.Sleep(1 * time.Millisecond) // give ReadContext time to block
			assert.NoError(t, cr.Close(), "Close errored")
		}()
		_, err := cr.ReadContext(ctx)
		require.ErrorIs(t, err, ErrReaderClosed)

		// Subsequent reads fail.
		_, err = cr.ReadContext(ctx)
		require.ErrorIs(t, err, ErrReaderClosed)

		// Ongoing read after Close is dropped.
		write(t, "unblock goroutine")
		buf, err := cr.ReadContext(ctx)
		assert.ErrorIs(t, err, ErrReaderClosed)
		assert.Empty(t, buf, "buf not empty")

		// Multiple closes are fine.
		assert.NoError(t, cr.Close(), "2nd Close failed")
	})

	// Re-creating is safe because the tests above leave no "pending" reads.
	cr = NewContextReader(pr)

	t.Run("close underlying reader", func(t *testing.T) {
		go func() {
			write(t, "before close")
			pw.CloseWithError(io.EOF)
		}()

		// Read the last chunk of data successfully.
		buf, err := cr.ReadContext(ctx)
		require.NoError(t, err)
		require.Equal(t, string(buf), "before close")

		// Next read fails because underlying reader is closed.
		buf, err = cr.ReadContext(ctx)
		require.ErrorIs(t, err, io.EOF)
		require.Empty(t, buf)
	})
}

func TestContextReader_ReadPassword(t *testing.T) {
	resetTermAfterTests(t)

	pr, pw := io.Pipe()
	write := func(t *testing.T, s string) {
		_, err := pw.Write([]byte(s))
		assert.NoError(t, err, "Write failed")
	}

	restoreCalled := false
	termIsTerminal = func(fd int) bool {
		return true
	}
	termGetState = func(fd int) (*term.State, error) {
		return &term.State{}, nil
	}
	termReadPassword = func(fd int) ([]byte, error) {
		const bufLen = 1024 // arbitrary, big enough for our data
		data := make([]byte, bufLen)
		n, err := pr.Read(data)
		data = data[:n]
		return data, err
	}
	termRestore = func(fd int, oldState *term.State) error {
		restoreCalled = true
		return nil
	}

	cr := NewContextReader(pr)
	cr.fd = 15 // arbitrary, doesn't matter because term functions are mocked.

	ctx := context.Background()
	t.Run("read password", func(t *testing.T) {
		const want = "llama45"
		go write(t, want)

		got, err := cr.ReadPassword(ctx)
		require.NoError(t, err, "ReadPassword failed")
		assert.Equal(t, want, string(got), "ReadPassword mismatch")
	})

	t.Run("intertwine reads", func(t *testing.T) {
		const want1 = "hello, world"
		go write(t, want1)
		got, err := cr.ReadPassword(ctx)
		require.NoError(t, err, "ReadPassword failed")
		assert.Equal(t, want1, string(got), "ReadPassword mismatch")

		const want2 = "goodbye, world"
		go write(t, want2)
		got, err = cr.ReadContext(ctx)
		require.NoError(t, err, "ReadContext failed")
		assert.Equal(t, want2, string(got), "ReadContext mismatch")
	})

	t.Run("password read turned clean", func(t *testing.T) {
		require.False(t, restoreCalled, "restoreCalled sanity check failed")

		cancelCtx, cancel := context.WithCancel(ctx)
		go func() {
			time.Sleep(1 * time.Millisecond) // give ReadPassword time to block
			cancel()
		}()
		got, err := cr.ReadPassword(cancelCtx)
		require.ErrorIs(t, err, context.Canceled, "ReadPassword returned unexpected error")
		require.Empty(t, got, "ReadPassword mismatch")

		// Reclaim as clean read.
		const want = "abandoned pwd read"
		go func() {
			// Once again, give ReadContext time to block.
			// This way we force a restore.
			time.Sleep(1 * time.Millisecond)
			write(t, want)
		}()
		got, err = cr.ReadContext(ctx)
		require.NoError(t, err, "ReadContext failed")
		assert.Equal(t, want, string(got), "ReadContext mismatch")
	})

	t.Run("Close", func(t *testing.T) {
		require.NoError(t, cr.Close(), "Close errored")

		_, err := cr.ReadPassword(ctx)
		require.ErrorIs(t, err, ErrReaderClosed, "ReadPassword returned unexpected error")
	})
}

func resetTermAfterTests(t *testing.T) {
	oldIsTerm := termIsTerminal
	oldGetState := termGetState
	oldReadPwd := termReadPassword
	oldRestore := termRestore
	t.Cleanup(func() {
		termIsTerminal = oldIsTerm
		termGetState = oldGetState
		termReadPassword = oldReadPwd
		termRestore = oldRestore
	})
}
