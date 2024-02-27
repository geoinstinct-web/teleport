// Teleport
// Copyright (C) 2024 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package resumption

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/multiplexer"
	"github.com/gravitational/teleport/lib/utils"
)

const sockSuffix = ".sock"

func sockPath(dataDir string, token resumptionToken) string {
	hash := sha256.Sum256(token[:])
	// unix domain sockets are limited to 108 or 104 characters, so the full
	// sha256 hash is a bit too much (64 bytes in hex or 44 in b64); truncating
	// the hash to 128 bits still gives us more than enough headroom to just
	// assume that we'll have no collisions (a probability of one in a
	// quintillion with 26 billion concurrent connections)
	return filepath.Join(dataDir, "handover", base64.RawURLEncoding.EncodeToString(hash[:16])+sockSuffix)
}

func sockDir(dataDir string) string {
	return filepath.Join(dataDir, "handover")
}

var errNoDataDir error = &trace.NotFoundError{Message: "data dir not configured"}

func (r *SSHServerWrapper) attemptHandover(conn *multiplexer.Conn, token resumptionToken) {
	handoverConn, err := r.dialHandover(token)
	if err != nil {
		if trace.IsNotFound(err) {
			r.log.Debug("Resumable connection not found or already deleted.")
			_, _ = conn.Write([]byte{notFoundServerExchangeTag})
			return
		}
		r.log.WithError(err).Error("Error while connecting to handover socket.")
		return
	}
	defer handoverConn.Close()

	var remoteIP netip.Addr
	if t, _ := conn.RemoteAddr().(*net.TCPAddr); t != nil {
		remoteIP, _ = netip.AddrFromSlice(t.IP)
	}
	remoteIP16 := remoteIP.As16()

	if _, err := handoverConn.Write(remoteIP16[:]); err != nil {
		if !utils.IsOKNetworkError(err) {
			r.log.WithError(err).Error("Error while forwarding remote address to handover socket.")
		}
		return
	}

	r.log.Debug("Forwarding resuming connection to handover socket.")
	_ = utils.ProxyConn(context.Background(), conn, handoverConn)
}

func (r *SSHServerWrapper) dialHandover(token resumptionToken) (net.Conn, error) {
	if r.dataDir == "" {
		return nil, trace.Wrap(errNoDataDir)
	}

	c, err := net.DialTimeout("unix", sockPath(r.dataDir, token), time.Second)
	if err != nil {
		return nil, trace.ConvertSystemError(err)
	}
	return c, nil
}

func (r *SSHServerWrapper) startHandoverListener(ctx context.Context, token resumptionToken, entry *connEntry) error {
	l, err := r.createHandoverListener(token)
	if err != nil {
		return trace.Wrap(err)
	}

	go r.runHandoverListener(l, entry)
	context.AfterFunc(ctx, func() { _ = l.Close() })

	return nil
}

func (r *SSHServerWrapper) createHandoverListener(token resumptionToken) (net.Listener, error) {
	if r.dataDir == "" {
		return nil, trace.Wrap(errNoDataDir)
	}

	_ = os.MkdirAll(sockDir(r.dataDir), teleport.PrivateDirMode)
	l, err := net.Listen("unix", sockPath(r.dataDir, token))
	if err != nil {
		return nil, trace.ConvertSystemError(err)
	}
	return l, nil
}

func (r *SSHServerWrapper) runHandoverListener(l net.Listener, entry *connEntry) {
	defer l.Close()

	var tempDelay time.Duration
	for {
		// the logic for this Accept loop is copied from [net/http.Server]
		c, err := l.Accept()
		if err == nil {
			tempDelay = 0
			go r.handleHandoverConnection(c, entry)
			continue
		}

		if tempErr, ok := err.(interface{ Temporary() bool }); !ok || !tempErr.Temporary() {
			if !utils.IsOKNetworkError(err) {
				r.log.WithError(err).Warn("Accept error in handover listener.")
			}
			return
		}

		tempDelay = max(5*time.Millisecond, min(2*tempDelay, time.Second))
		r.log.WithError(err).WithField("delay", tempDelay).Warn("Temporary accept error in handover listener, continuing after delay.")
		time.Sleep(tempDelay)
	}
}

func (r *SSHServerWrapper) handleHandoverConnection(conn net.Conn, entry *connEntry) {
	defer conn.Close()

	var remoteIP16 [16]byte
	if _, err := io.ReadFull(conn, remoteIP16[:]); err != nil {
		if !utils.IsOKNetworkError(err) {
			r.log.WithError(err).Error("Error while reading remote address from handover socket.")
		}
		return
	}
	remoteIP := netip.AddrFrom16(remoteIP16).Unmap()

	r.resumeConnection(entry, conn, remoteIP)
}

// HandoverCleanup deletes hand-over sockets that were left over from previous
// runs of Teleport that failed to clean up after themselves (because of an
// uncatchable signal or a system crash). It will exhaustively clean up the
// current left over sockets, so it's sufficient to call it once per process.
func (r *SSHServerWrapper) HandoverCleanup(ctx context.Context) error {
	const cleanupDelay = time.Second
	return trace.Wrap(r.handoverCleanup(ctx, cleanupDelay))
}

func (r *SSHServerWrapper) handoverCleanup(ctx context.Context, cleanupDelay time.Duration) error {
	if r.dataDir == "" {
		return nil
	}

	dir := sockDir(r.dataDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return trace.ConvertSystemError(err)
	}

	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), sockSuffix) {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}

	paths, firstErr := retainNonConnectableSockets(ctx, paths)

	if len(paths) < 1 {
		return trace.Wrap(firstErr)
	}

	// unix domain sockets exist on disk between bind() and listen() but
	// connecting before listen() results in ECONNREFUSED, so we just wait a
	// little bit before testing them again; the first check lets us be done
	// with the check immediately in the happy case where there's no
	// unconnectable sockets
	r.log.WithField("sockets", len(paths)).Debug("Found some unconnectable handover sockets, waiting before checking them again.")

	select {
	case <-ctx.Done():
		return trace.NewAggregate(firstErr, ctx.Err())
	case <-time.After(cleanupDelay):
	}

	paths, secondErr := retainNonConnectableSockets(ctx, paths)

	if len(paths) < 1 {
		r.log.Debug("Found no unconnectable handover socket after waiting.")
		return trace.NewAggregate(firstErr, secondErr)
	}

	r.log.WithField("sockets", len(paths)).Info("Cleaning up some non-connectable handover sockets, left over from previous Teleport instances.")

	errs := []error{firstErr, secondErr}
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, trace.ConvertSystemError(err))
		}
	}

	return trace.NewAggregate(errs...)
}

// retainNonConnectableSockets attempts to connect to the given UNIX domain
// sockets, returning all and only the ones that exist and that refuse the
// connection.
func retainNonConnectableSockets(ctx context.Context, paths []string) (filtered []string, lastErr error) {
	filtered = paths[:0]

	var d net.Dialer
	for _, path := range paths {
		c, err := d.DialContext(ctx, "unix", path)
		if err == nil {
			_ = c.Close()
			continue
		}

		if errors.Is(err, os.ErrNotExist) {
			continue
		}

		if errors.Is(err, syscall.ECONNREFUSED) {
			filtered = append(filtered, path)
			continue
		}

		lastErr = err
	}

	return filtered, trace.ConvertSystemError(lastErr)
}
