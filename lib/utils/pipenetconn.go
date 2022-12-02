/*
Copyright 2015-2021 Gravitational, Inc.

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
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/gravitational/trace"
)

// PipeNetConn implements net.Conn from a provided io.Reader,io.Writer and
// io.Closer
type PipeNetConn struct {
	// Locks writing and closing the connection. If both writer & closer refer
	// to the same underlying object, simultaneous write and close operations
	// introduce a data race (*especially* if that object is a
	// `x/crypto/ssh.channel`), so we will use this mutex to serialize write
	// and close operations.
	mu sync.Mutex

	reader     io.Reader
	writer     io.Writer
	closer     io.Closer
	localAddr  net.Addr
	remoteAddr net.Addr
}

// NewPipeNetConn constructs a new PipeNetConn, providing a net.Conn
// implementation synthesized from the supplied io.Reader, io.Writer &
// io.Closer.
func NewPipeNetConn(reader io.Reader,
	writer io.Writer,
	closer io.Closer,
	fakelocalAddr net.Addr,
	fakeRemoteAddr net.Addr) *PipeNetConn {

	return &PipeNetConn{
		reader:     reader,
		writer:     writer,
		closer:     closer,
		localAddr:  fakelocalAddr,
		remoteAddr: fakeRemoteAddr,
	}
}

func (nc *PipeNetConn) Read(buf []byte) (n int, e error) {
	return nc.reader.Read(buf)
}

func (nc *PipeNetConn) Write(buf []byte) (n int, e error) {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	return nc.writer.Write(buf)
}

func (nc *PipeNetConn) Close() error {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	if nc.closer != nil {
		return nc.closer.Close()
	}
	return nil
}

func (nc *PipeNetConn) LocalAddr() net.Addr {
	return nc.localAddr
}

func (nc *PipeNetConn) RemoteAddr() net.Addr {
	return nc.remoteAddr
}

func (nc *PipeNetConn) SetDeadline(t time.Time) error {
	return nil
}

func (nc *PipeNetConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (nc *PipeNetConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// DualPipeNetConn creates a pipe to connect a client and a server. The
// two net.Conn instances are wrapped in an PipeNetConn which holds the source and
// destination addresses.
//
// The pipe is constructed from a syscall.Socketpair instead of a net.Pipe because
// the synchronous nature of net.Pipe causes it to deadlock when attempting to perform
// TLS or SSH handshakes.
func DualPipeNetConn(srcAddr net.Addr, dstAddr net.Addr) (net.Conn, net.Conn, error) {
	// File descriptor ownership is transfer to the net.FileConn created below.
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	f1 := os.NewFile(uintptr(fds[0]), srcAddr.String())
	client, err := net.FileConn(f1)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	f2 := os.NewFile(uintptr(fds[1]), dstAddr.String())
	server, err := net.FileConn(f2)
	if err != nil {
		return nil, nil, trace.NewAggregate(err, client.Close())
	}

	// By passing the net.FileConn as closers we are ensuring that when
	// the connection is closed the file descriptors will be cleaned up.
	serverConn := NewPipeNetConn(server, server, server, dstAddr, srcAddr)
	clientConn := NewPipeNetConn(client, client, client, srcAddr, dstAddr)

	return serverConn, clientConn, nil
}
