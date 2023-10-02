/*
Copyright 2022 Gravitational, Inc.

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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLocks(t *testing.T) {
	t.Parallel()

	tmpFile, err := os.CreateTemp("", "teleport-lock-test")
	fp := tmpFile.Name()
	t.Cleanup(func() {
		_ = os.Remove(fp)
	})
	require.NoError(t, err)

	// Can take read lock
	unlock, err := FSTryReadLock(fp)
	require.NoError(t, err)

	require.NoError(t, unlock())

	// Can take write lock
	unlock, err = FSTryWriteLock(fp)
	require.NoError(t, err)

	// Can't take read lock while write lock is held.
	unlock2, err := FSTryReadLock(fp)
	require.ErrorIs(t, err, ErrUnsuccessfulLockTry)
	require.Nil(t, unlock2)

	// Can't take write lock while another write lock is held.
	unlock2, err = FSTryWriteLock(fp)
	require.ErrorIs(t, err, ErrUnsuccessfulLockTry)
	require.Nil(t, unlock2)

	require.NoError(t, unlock())

	unlock, err = FSTryReadLock(fp)
	require.NoError(t, err)

	// Can take second read lock on the same file.
	unlock2, err = FSTryReadLock(fp)
	require.NoError(t, err)

	require.NoError(t, unlock())
	require.NoError(t, unlock2())

	// Can take read lock with timeout
	unlock, err = FSTryReadLockTimeout(context.Background(), fp, time.Second)
	require.NoError(t, err)
	require.NoError(t, unlock())

	// Can take write lock with timeout
	unlock, err = FSTryWriteLockTimeout(context.Background(), fp, time.Second)
	require.NoError(t, err)

	// Fails because timeout is exceeded, since file is already locked.
	unlock2, err = FSTryWriteLockTimeout(context.Background(), fp, time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, unlock2)

	// Fails because context is expired while waiting for timeout.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now())
	defer cancel()
	unlock2, err = FSTryWriteLockTimeout(ctx, fp, time.Hour*1000)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, unlock2)

	require.NoError(t, unlock())
}

func TestOverwriteFile(t *testing.T) {
	have := []byte("Sensitive Information")
	fName := filepath.Join(t.TempDir(), "teleport-overwrite-file-test")

	require.NoError(t, os.WriteFile(fName, have, 0600))
	f, err := os.OpenFile(fName, os.O_WRONLY, 0)
	require.NoError(t, err)
	defer f.Close()
	fi, err := os.Stat(fName)
	require.NoError(t, err)
	require.NoError(t, overwriteFile(f, fi))

	contents, err := os.ReadFile(fName)
	require.NoError(t, err)
	require.NotContains(t, contents, have, "File contents were not overwritten")
}

func TestRemoveAllSecure(t *testing.T) {
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "teleport-remove-all-secure-test")
	f, err := os.Create(tempFile)
	symlink := filepath.Join(tempDir, "teleport-remove-secure-symlink")
	require.NoError(t, os.Symlink(tempFile, symlink))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	require.NoError(t, RemoveAllSecure(""))
	require.NoError(t, RemoveAllSecure(tempDir))
	_, err = os.Stat(tempDir)
	require.True(t, os.IsNotExist(err), "Directory should be removed: %v", err)
}

func TestRemoveSecure(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), "teleport-remove-secure-test")
	f, err := os.Create(tempFile)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	require.NoError(t, RemoveSecure(f.Name()))
	_, err = os.Stat(tempFile)
	require.True(t, os.IsNotExist(err), "File should be removed: %v", err)
}

func TestRemoveSecure_symlink(t *testing.T) {
	symlink := filepath.Join(t.TempDir(), "teleport-remove-secure-symlink")
	require.NoError(t, os.Symlink("/tmp", symlink))

	require.NoError(t, RemoveSecure(symlink))
	_, err := os.Stat(symlink)
	require.True(t, os.IsNotExist(err), "Symlink should be removed: %v", err)
}
