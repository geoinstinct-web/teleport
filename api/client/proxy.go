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

package client

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"

	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

// DialProxy creates a connection to a server via an HTTP or SOCKS Proxy.
func DialProxy(ctx context.Context, proxyURL *url.URL, addr string) (net.Conn, error) {
	return DialProxyWithDialer(ctx, proxyURL, addr, &net.Dialer{})
}

// DialProxyWithDialer creates a connection to a server via an HTTP or SOCKS Proxy using a specified dialer.
func DialProxyWithDialer(
	ctx context.Context,
	proxyURL *url.URL,
	addr string,
	dialer *net.Dialer,
) (net.Conn, error) {
	switch proxyURL.Scheme {
	case "http", "https":
		return dialProxyWithHTTPDialer(ctx, proxyURL, addr, dialer)
	case "socks5":
		return dialProxyWithSOCKSDialer(ctx, proxyURL, addr, dialer)
	default:
		return nil, trace.BadParameter("proxy url scheme %q not supported", proxyURL.Scheme)
	}
}

// dialProxyWithHTTPDialer creates a connection to a server via an HTTP Proxy.
func dialProxyWithHTTPDialer(
	ctx context.Context,
	proxyURL *url.URL,
	addr string,
	dialer ContextDialer,
) (net.Conn, error) {
	if proxyURL == nil {
		return nil, trace.BadParameter("missing proxy url")
	}

	conn, err := dialer.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		log.Warnf("Unable to dial to proxy: %v: %v.", proxyURL.Host, err)
		return nil, trace.ConvertSystemError(err)
	}

	header := make(http.Header)
	if proxyURL.User != nil {
		// dont use User.String() because it performs url encoding (rfc 1738),
		// which we don't want in our header
		password, _ := proxyURL.User.Password()
		// empty user/pass is permitted by the spec. The minimum required is a single colon.
		// see: https://datatracker.ietf.org/doc/html/rfc1945#section-11
		creds := proxyURL.User.Username() + ":" + password
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
		header.Add("Proxy-Authorization", basicAuth)
	}
	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: header,
	}

	if err := connectReq.Write(conn); err != nil {
		log.Warnf("Unable to write to proxy: %v.", err)
		return nil, trace.Wrap(err)
	}

	// Read in the response. http.ReadResponse will read in the status line, mime
	// headers, and potentially part of the response body. the body itself will
	// not be read, but kept around so it can be read later.
	br := bufio.NewReader(conn)
	// Per the above comment, we're only using ReadResponse to check the status
	// and then hand off the underlying connection to the caller.
	// resp.Body.Close() would drain conn and close it, we don't need to do it
	// here. Disabling bodyclose linter for this edge case.
	//nolint:bodyclose
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		conn.Close()
		log.Warnf("Unable to read response: %v.", err)
		return nil, trace.Wrap(err)
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, trace.BadParameter("unable to proxy connection: %v", resp.Status)
	}

	// Return a bufferedConn that wraps a net.Conn and a *bufio.Reader. this
	// needs to be done because http.ReadResponse will buffer part of the
	// response body in the *bufio.Reader that was passed in. reads must first
	// come from anything buffered, then from the underlying connection otherwise
	// data will be lost.
	return &bufferedConn{
		Conn:   conn,
		reader: br,
	}, nil
}

// dialProxyWithSOCKSDialer creates a connection to a server via a SOCKS Proxy.
func dialProxyWithSOCKSDialer(
	ctx context.Context,
	proxyURL *url.URL,
	addr string,
	dialer *net.Dialer,
) (net.Conn, error) {
	if proxyURL == nil {
		return nil, trace.BadParameter("missing proxy url")
	}

	var proxyAuth *proxy.Auth
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		proxyAuth = &proxy.Auth{
			User:     proxyURL.User.Username(),
			Password: password,
		}
	}

	socksDialer, err := proxy.SOCKS5("tcp", proxyURL.Host, proxyAuth, dialer)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	conn, err := socksDialer.Dial("tcp", addr)
	if err != nil {
		log.Warnf("unable to proxy connection: %v", addr, err)
		return nil, trace.ConvertSystemError(err)
	}

	return conn, nil
}

// bufferedConn is used when part of the data on a connection has already been
// read by a *bufio.Reader. Reads will first try and read from the
// *bufio.Reader and when everything has been read, reads will go to the
// underlying connection.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

// Read first reads from the *bufio.Reader any data that has already been
// buffered. Once all buffered data has been read, reads go to the net.Conn.
func (bc *bufferedConn) Read(b []byte) (n int, err error) {
	if bc.reader.Buffered() > 0 {
		return bc.reader.Read(b)
	}
	return bc.Conn.Read(b)
}
