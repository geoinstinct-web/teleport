/*
Copyright 2015 Gravitational, Inc.

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
	"sync"
	"time"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
)

// PipeNetConn implemetns net.Conn from io.Reader,io.Writer and io.Closer
type PipeNetConn struct {
	reader     io.Reader
	writer     io.Writer
	closer     io.Closer
	localAddr  net.Addr
	remoteAddr net.Addr
}

// NewPipeNetConn returns a net.Conn like object
// using Pipe as an underlying implementation over reader, writer and closer
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
	return nc.writer.Write(buf)
}

func (nc *PipeNetConn) Close() error {
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

// DualPipeAddrConn creates a net.Pipe to connect a client and a server. The
// two net.Conn instances are wrapped in an addrConn which holds the source and
// destination addresses.
func DualPipeNetConn(srcAddr net.Addr, dstAddr net.Addr) (*PipeNetConn, *PipeNetConn) {
	server, client := net.Pipe()

	serverConn := NewPipeNetConn(server, server, server, dstAddr, srcAddr)
	clientConn := NewPipeNetConn(client, client, client, srcAddr, dstAddr)

	return serverConn, clientConn
}

func SplitReaders(r1 io.Reader, r2 io.Reader) io.Reader {
	reader, writer := io.Pipe()
	go io.Copy(writer, r1)
	go io.Copy(writer, r2)
	return reader
}

// NewChConn returns a new net.Conn implemented over
// SSH channel
func NewChConn(conn ssh.Conn, ch ssh.Channel) *ChConn {
	c := &ChConn{}
	c.Channel = ch
	c.conn = conn
	return c
}

// NewExclusiveChConn returns a new net.Conn implemented over
// SSH channel, whenever this connection closes
func NewExclusiveChConn(conn ssh.Conn, ch ssh.Channel) *ChConn {
	c := &ChConn{
		exclusive: true,
	}
	c.Channel = ch
	c.conn = conn
	return c
}

// ChConn is a net.Conn like object
// that uses SSH channel
type ChConn struct {
	mu sync.Mutex

	ssh.Channel
	conn ssh.Conn
	// exclusive indicates that whenever this channel connection
	// is getting closed, the underlying connection is closed as well
	exclusive bool
}

// Close closes channel and if the ChConn is exclusive, connection as well
func (c *ChConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	err := c.Channel.Close()
	if !c.exclusive {
		return trace.Wrap(err)
	}
	err2 := c.conn.Close()
	return trace.NewAggregate(err, err2)
}

// LocalAddr returns a local address of a connection
// Uses underlying net.Conn implementation
func (c *ChConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns a remote address of a connection
// Uses underlying net.Conn implementation
func (c *ChConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets a connection deadline
// ignored for the channel connection
func (c *ChConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets a connection read deadline
// ignored for the channel connection
func (c *ChConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets write deadline on a connection
// ignored for the channel connection
func (c *ChConn) SetWriteDeadline(t time.Time) error {
	return nil
}
