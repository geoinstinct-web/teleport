/*
Copyright 2017-2021 Gravitational, Inc.

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

package multiplexer

import (
	"bufio"
	"context"
	"net"

	"github.com/gravitational/trace"
)

// Conn is a connection wrapper that supports
// communicating remote address from proxy protocol
// and replays first several bytes read during
// protocol detection
type Conn struct {
	net.Conn
	protocol  Protocol
	proxyLine *ProxyLine
	reader    *bufio.Reader
}

// NewConn returns a net.Conn wrapper that supports peeking into the connection.
func NewConn(conn net.Conn) *Conn {
	return &Conn{
		Conn:   conn,
		reader: bufio.NewReader(conn),
	}
}

// NetConn returns the underlying net.Conn.
func (c *Conn) NetConn() net.Conn {
	return c.Conn
}

// Read reads from connection
func (c *Conn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// LocalAddr returns local address of the connection
func (c *Conn) LocalAddr() net.Addr {
	if c.proxyLine != nil {
		return &c.proxyLine.Destination
	}
	return c.Conn.LocalAddr()
}

// RemoteAddr returns remote address of the connection
func (c *Conn) RemoteAddr() net.Addr {
	if c.proxyLine != nil {
		return &c.proxyLine.Source
	}
	return c.Conn.RemoteAddr()
}

// Protocol returns the detected connection protocol
func (c *Conn) Protocol() Protocol {
	return c.protocol
}

// Detect detects the connection protocol by peeking into the first few bytes.
func (c *Conn) Detect() (Protocol, error) {
	proto, err := detectProto(c.reader)
	if err != nil && !trace.IsBadParameter(err) {
		return ProtoUnknown, trace.Wrap(err)
	}
	return proto, nil
}

// ReadProxyLine reads proxy-line from the connection.
func (c *Conn) ReadProxyLine() (*ProxyLine, error) {
	var proxyLine *ProxyLine
	protocol, err := c.Detect()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if protocol == ProtoProxyV2 {
		proxyLine, err = ReadProxyLineV2(c.reader)
	} else {
		proxyLine, err = ReadProxyLine(c.reader)
	}
	if err != nil {
		return nil, trace.Wrap(err)
	}
	c.proxyLine = proxyLine
	return proxyLine, nil
}

// returns a Listener that pretends to be listening on addr, closed whenever the
// parent context is done.
func newListener(parent context.Context, addr net.Addr) *Listener {
	context, cancel := context.WithCancel(parent)
	return &Listener{
		addr:    addr,
		connC:   make(chan net.Conn),
		cancel:  cancel,
		context: context,
	}
}

// Listener is a listener that receives
// connections from multiplexer based on the connection type
type Listener struct {
	addr    net.Addr
	connC   chan net.Conn
	cancel  context.CancelFunc
	context context.Context
}

// Addr returns listener addr, the address of multiplexer listener
func (l *Listener) Addr() net.Addr {
	return l.addr
}

// Accept accepts connections from parent multiplexer listener
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case <-l.context.Done():
		return nil, trace.ConnectionProblem(net.ErrClosed, "listener is closed")
	case conn := <-l.connC:
		return conn, nil
	}
}

// HandleConnection injects the connection into the Listener, blocking until the
// context expires, the connection is accepted or the Listener is closed.
func (l *Listener) HandleConnection(ctx context.Context, conn net.Conn) {
	select {
	case <-ctx.Done():
		conn.Close()
	case <-l.context.Done():
		conn.Close()
	case l.connC <- conn:
	}
}

// Close closes the listener.
func (l *Listener) Close() error {
	l.cancel()
	return nil
}
