// Copyright 2022 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package helpers

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gravitational/trace"
)

type ProxyHandler struct {
	sync.Mutex
	count int
}

// ServeHTTP only accepts the CONNECT verb and will tunnel your connection to
// the specified host. Also tracks the number of connections that it proxies for
// debugging purposes.
func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Validate http connect parameters.
	if r.Method != http.MethodConnect {
		trace.WriteError(w, trace.BadParameter("%v not supported", r.Method))
		return
	}
	if r.Host == "" {
		trace.WriteError(w, trace.BadParameter("host not set"))
		return
	}

	// Dial to the target host, this is done before hijacking the connection to
	// ensure the target host is accessible.
	dconn, err := net.Dial("tcp", r.Host)
	if err != nil {
		trace.WriteError(w, err)
		return
	}
	defer dconn.Close()

	// Once the client receives 200 OK, the rest of the data will no longer be
	// http, but whatever protocol is being tunneled.
	w.WriteHeader(http.StatusOK)

	// Hijack request so we can get underlying connection.
	hj, ok := w.(http.Hijacker)
	if !ok {
		trace.WriteError(w, trace.AccessDenied("unable to hijack connection"))
		return
	}
	sconn, _, err := hj.Hijack()
	if err != nil {
		trace.WriteError(w, err)
		return
	}
	defer sconn.Close()

	// Success, we're proxying data now.
	p.Lock()
	p.count += 1
	p.Unlock()

	// Copy from src to dst and dst to src.
	errc := make(chan error, 2)
	replicate := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		errc <- err
	}
	go replicate(sconn, dconn)
	go replicate(dconn, sconn)

	// Wait until done, error, or 10 second.
	select {
	case <-time.After(10 * time.Second):
	case <-errc:
	}
}

// ResetCount resets the count of connections proxied.
func (p *ProxyHandler) ResetCount() {
	p.Lock()
	defer p.Unlock()
	p.count = 0
}

// Count returns the number of connections that have been proxied.
func (p *ProxyHandler) Count() int {
	p.Lock()
	defer p.Unlock()
	return p.count
}

type ProxyAuthorizer struct {
	next   http.Handler
	authDB map[string]string
	connC  chan struct{}
	errC   chan error
}

func NewProxyAuthorizer(handler http.Handler, authDB map[string]string) *ProxyAuthorizer {
	return &ProxyAuthorizer{
		next:   handler,
		authDB: authDB,
		connC:  make(chan struct{}),
		errC:   make(chan error),
	}
}

func (p *ProxyAuthorizer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// we detect if someone is waiting for a new connection to come in.
	var someoneWaiting bool
	var err error
	defer func() {
		if err != nil {
			trace.WriteError(w, err)
		}
		if someoneWaiting {
			p.notifyWaiter(err)
		}
	}()
	select {
	case p.connC <- struct{}{}:
		someoneWaiting = true
	default:
	}

	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		err = trace.AccessDenied("missing Proxy-Authorization header")
		return
	}
	user, password, ok := parseProxyAuth(auth)
	if !ok {
		err = trace.AccessDenied("bad Proxy-Authorization header")
		return
	}

	if !p.isAuthorized(user, password) {
		err = trace.AccessDenied("bad credentials")
		return
	}

	// request is authorized, send it to the next handler
	p.next.ServeHTTP(w, r)
}

// WaitForConnection waits (with a configured timeout) for a new connection to be handled and returns the error.
// This function makes no guarantees about which connection error will be returned, except that the connection
// error will have occurred after this function was called. For this reason, don't use this in multiple
// goroutines that expect different errors.
func (p *ProxyAuthorizer) WaitForConnection(timeout time.Duration) error {
	timeoutC := time.After(timeout)

	// wait for a new connection to come in.
	select {
	case <-timeoutC:
		return trace.BadParameter("timed out waiting for connection to proxy authorizer")
	case <-p.connC:
	}

	// get some error that occurred after the new connection came in.
	select {
	case <-timeoutC:
		return trace.BadParameter("timed out waiting for connection error")
	case err := <-p.errC:
		return err
	}
}

func (p *ProxyAuthorizer) notifyWaiter(err error) {
	// notify waiter, but don't block if they left already.
	select {
	case p.errC <- err:
	default:
	}
}

func (p *ProxyAuthorizer) isAuthorized(user, pass string) bool {
	expectedPass, ok := p.authDB[user]
	return ok && pass == expectedPass
}

// parse "Proxy-Authorization" header by leveraging the stdlib basic auth parsing for "Authorization" header
func parseProxyAuth(proxyAuth string) (user, password string, ok bool) {
	fakeHeader := make(http.Header)
	fakeHeader.Add("Authorization", proxyAuth)
	fakeReq := &http.Request{
		Header: fakeHeader,
	}
	return fakeReq.BasicAuth()
}

func MakeProxyAddr(user, pass, host string) string {
	userPass := url.UserPassword(user, pass).String()
	return fmt.Sprintf("%v@%v", userPass, host)
}
