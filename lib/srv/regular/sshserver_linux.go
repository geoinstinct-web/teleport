//go:build linux
// +build linux

/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package regular

import (
	"net"
	"os"
	"os/user"
	"strconv"

	"github.com/gravitational/trace"
	"golang.org/x/sys/unix"

	"github.com/gravitational/teleport/lib/srv"
)

// validateListenerSocket checks that the socket and listener file descriptor
// sent from the forwarding process have the expected properties.
func validateListenerSocket(scx *srv.ServerContext, controlConn *net.UnixConn, listenerFD *os.File) error {
	// Get the credentials of the client connected to the socket.
	var cred *unix.Ucred
	var err error
	if err := controlSyscallConn(controlConn, func(fd uintptr) error {
		cred, err = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		return err
	}); err != nil {
		return trace.Wrap(err)
	}

	// Check that the user connected to the socket is who we expect.
	usr, err := user.Lookup(scx.Identity.Login)
	if err != nil {
		return trace.Wrap(err)
	}
	if expectedUid, err := strconv.Atoi(usr.Uid); err != nil {
		return trace.Wrap(err)
	} else if int(cred.Uid) != expectedUid {
		return trace.AccessDenied("unexpected user UID for the socket: %v", cred.Uid)
	}
	if expectedGid, err := strconv.Atoi(usr.Gid); err != nil {
		return trace.Wrap(err)
	} else if int(cred.Gid) != expectedGid {
		return trace.AccessDenied("unexpected user GID for the socket: %v", cred.Gid)
	}

	if err := controlSyscallConn(listenerFD, func(fd uintptr) error {
		// Verify the socket type
		if sockType, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE); err != nil {
			return trace.Wrap(err)
		} else if sockType != unix.SOCK_STREAM {
			return trace.AccessDenied("socket is not of the expected type (STREAM)")
		}

		// Verify that reuse is not enabled on the socket
		if reuseAddr, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR); err != nil {
			return trace.Wrap(err)
		} else if reuseAddr != 0 {
			return trace.AccessDenied("SO_REUSEADDR is enabled on the socket")
		}
		if reusePort, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT); err != nil {
			// Some systems may not support SO_REUSEPORT, so we ignore the error here
		} else if reusePort != 0 {
			return trace.AccessDenied("SO_REUSEPORT is enabled on the socket")
		}

		// Verify that the listener is already listening.
		if acceptConn, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ACCEPTCONN); err != nil {
			return trace.Wrap(err)
		} else if acceptConn == 0 {
			return trace.AccessDenied("SO_ACCEPTCONN is not set, socket is not listening")
		}

		return nil
	}); err != nil {
		return trace.Wrap(err)
	}
	return nil
}
