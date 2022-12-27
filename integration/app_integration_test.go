/*
Copyright 2020-2022 Gravitational, Inc.

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

package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/gravitational/oxy/forward"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/breaker"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/integration/helpers"
	"github.com/gravitational/teleport/lib"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/httplib/csrf"
	"github.com/gravitational/teleport/lib/jwt"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/alpnproxy"
	alpncommon "github.com/gravitational/teleport/lib/srv/alpnproxy/common"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/web"
	"github.com/gravitational/teleport/lib/web/app"
)

// TestAppAccess runs the full application access integration test suite.
//
// It allows to make the entire cluster set up once, instead of per test,
// which speeds things up significantly.
func TestAppAccess(t *testing.T) {
	pack := setup(t)

	t.Run("TestAppAccessForward", pack.appAccessForward)
	t.Run("TestAppAccessWebsockets", pack.appAccessWebsockets)
	t.Run("TestAppAccessClientCert", pack.appAccessClientCert)
	t.Run("TestAppAccessFlush", pack.appAccessFlush)
	t.Run("TestAppAccessForwardModes", pack.appAccessForwardModes)
	t.Run("TestAppAccessRewriteHeadersRoot", pack.appAccessRewriteHeadersRoot)
	t.Run("TestAppAccessRewriteHeadersLeaf", pack.appAccessRewriteHeadersLeaf)
	t.Run("TestAppAccessLogout", pack.appAccessLogout)
	t.Run("TestAppAccessJWT", pack.appAccessJWT)
	t.Run("TestAppAccessNoHeaderOverrides", pack.appAccessNoHeaderOverrides)
	t.Run("TestAppAuditEvents", pack.appAuditEvents)
	t.Run("TestAppInvalidateAppSessionsOnLogout", pack.appInvalidateAppSessionsOnLogout)
	t.Run("TestAppAccessTCP", pack.appAccessTCP)

	// This test should go last because it stops/starts app servers.
	t.Run("TestAppServersHA", pack.appServersHA)
}

// appAccessForward tests that requests get forwarded to the target application
// within a single cluster and trusted cluster.
func (p *pack) appAccessForward(t *testing.T) {
	rootCookies := helpers.ParseCookies(t, p.CreateAppSession(t, p.rootAppPublicAddr, p.rootAppClusterName))
	leafCookies := helpers.ParseCookies(t, p.CreateAppSession(t, p.leafAppPublicAddr, p.leafAppClusterName))
	tests := []struct {
		desc          string
		inCookies     []*http.Cookie
		outStatusCode int
		outMessage    string
	}{
		{
			desc:          "root cluster, valid application session cookie, success",
			inCookies:     rootCookies.ToSlice(),
			outStatusCode: http.StatusOK,
			outMessage:    p.rootMessage,
		},
		{
			desc:          "leaf cluster, valid application session cookie, success",
			inCookies:     leafCookies.ToSlice(),
			outStatusCode: http.StatusOK,
			outMessage:    p.leafMessage,
		},
		{
			desc:          "missing root subject session cookie, redirect to login",
			inCookies:     rootCookies.WithSubjectCookie(nil).ToSlice(),
			outStatusCode: http.StatusFound,
			outMessage:    "",
		},
		{
			desc: "root subject session cookie invalid, redirect to login",
			inCookies: rootCookies.WithSubjectCookie(&http.Cookie{
				Name:  app.SubjectCookieName,
				Value: "letmeinplease",
			}).ToSlice(),
			outStatusCode: http.StatusFound,
		},
		{
			desc:          "missing leaf subject session cookie, redirect to login",
			inCookies:     leafCookies.WithSubjectCookie(nil).ToSlice(),
			outStatusCode: http.StatusFound,
		},
		{
			desc: "leaf subject session cookie invalid, redirect to login",
			inCookies: leafCookies.WithSubjectCookie(&http.Cookie{
				Name:  app.SubjectCookieName,
				Value: "letmeinplease",
			}).ToSlice(),
			outStatusCode: http.StatusFound,
		},
		{
			desc: "invalid application session cookie, redirect to login",
			inCookies: []*http.Cookie{{
				Name:  app.CookieName,
				Value: "D25C463CD27861559CC6A0A6AE54818079809AA8731CB18037B4B37A80C4FC6C"},
			},
			outStatusCode: http.StatusFound,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()
			status, body, err := p.MakeRequest(tt.inCookies, http.MethodGet, "/")
			require.NoError(t, err)
			require.Equal(t, tt.outStatusCode, status)
			require.Contains(t, body, tt.outMessage)
		})
	}
}

// appAccessWebsockets makes sure that websocket requests get forwarded.
func (p *pack) appAccessWebsockets(t *testing.T) {
	tests := []struct {
		desc       string
		inCookies  []*http.Cookie
		outMessage string
		err        error
	}{
		{
			desc:       "root cluster, valid application session cookie, successful websocket (ws://) request",
			inCookies:  p.CreateAppSession(t, p.rootWSPublicAddr, p.rootAppClusterName),
			outMessage: p.rootWSMessage,
		},
		{
			desc:       "root cluster, valid application session cookie, successful secure websocket (wss://) request",
			inCookies:  p.CreateAppSession(t, p.rootWSSPublicAddr, p.rootAppClusterName),
			outMessage: p.rootWSSMessage,
		},
		{
			desc:       "leaf cluster, valid application session cookie, successful websocket (ws://) request",
			inCookies:  p.CreateAppSession(t, p.leafWSPublicAddr, p.leafAppClusterName),
			outMessage: p.leafWSMessage,
		},
		{
			desc:       "leaf cluster, valid application session cookie, successful secure websocket (wss://) request",
			inCookies:  p.CreateAppSession(t, p.leafWSSPublicAddr, p.leafAppClusterName),
			outMessage: p.leafWSSMessage,
		},
		{
			desc: "valid application session cookie, invalid subject session cookie, websocket request fails to dial",
			inCookies: helpers.ParseCookies(t, p.CreateAppSession(t, p.rootWSPublicAddr, p.rootAppClusterName)).WithSubjectCookie(
				&http.Cookie{
					Name:  app.SubjectCookieName,
					Value: "foobarbaz",
				},
			).ToSlice(),
			err: errors.New(""),
		},
		{
			desc: "invalid application session cookie, websocket request fails to dial",
			inCookies: []*http.Cookie{
				{
					Name:  app.CookieName,
					Value: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
				},
			},
			err: errors.New(""),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()
			body, err := p.makeWebsocketRequest(tt.inCookies, "/")
			if tt.err != nil {
				require.IsType(t, tt.err, trace.Unwrap(err))
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.outMessage, body)
			}
		})
	}
}

// appAccessTCP tests proxying of plain TCP applications through app access.
func (p *pack) appAccessTCP(t *testing.T) {
	pack := setup(t)
	evilUser, _ := pack.createUser(t)

	rootWs, err := pack.tc.CreateAppSession(context.Background(), types.CreateAppSessionRequest{
		Username:    pack.tc.Username,
		PublicAddr:  pack.rootTCPPublicAddr,
		ClusterName: pack.rootAppClusterName,
	})
	require.NoError(t, err)
	leafWs, err := pack.tc.CreateAppSession(context.Background(), types.CreateAppSessionRequest{
		Username:    pack.tc.Username,
		PublicAddr:  pack.leafTCPPublicAddr,
		ClusterName: pack.leafAppClusterName,
	})
	require.NoError(t, err)

	tests := []struct {
		description string
		address     string
		outMessage  string
		wantReadErr error
	}{
		{
			description: "TCP app in root cluster",
			address: pack.startLocalProxy(t,
				pack.makeTLSConfig(t, rootWs.GetName(), rootWs.GetUser(), pack.rootTCPPublicAddr, pack.rootAppClusterName)),
			outMessage: pack.rootTCPMessage,
		},
		{
			description: "TCP app in leaf cluster",
			address: pack.startLocalProxy(t,
				pack.makeTLSConfig(t, leafWs.GetName(), leafWs.GetUser(), pack.leafTCPPublicAddr, pack.leafAppClusterName)),
			outMessage: pack.leafTCPMessage,
		},
		{
			description: "TCP app in root cluster, invalid session owner",
			address: pack.startLocalProxy(t,
				pack.makeTLSConfig(t, rootWs.GetName(), evilUser.GetName(), pack.rootTCPPublicAddr, pack.rootAppClusterName)),
			wantReadErr: io.EOF, // access denied errors should close the tcp conn
		},
		{
			description: "TCP app in leaf cluster, invalid session owner",
			address: pack.startLocalProxy(t,
				pack.makeTLSConfig(t, leafWs.GetName(), evilUser.GetName(), pack.leafTCPPublicAddr, pack.leafAppClusterName)),
			wantReadErr: io.EOF, // access denied errors should close the tcp conn
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.description, func(t *testing.T) {
			t.Parallel()
			conn, err := net.Dial("tcp", test.address)
			require.NoError(t, err)

			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if test.wantReadErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, test.wantReadErr)
				return
			}
			require.NoError(t, err)

			resp := strings.TrimSpace(string(buf[:n]))
			require.Equal(t, test.outMessage, resp)
		})
	}
}

func TestTCPLock(t *testing.T) {
	clock := clockwork.NewFakeClockAt(time.Now())
	mCloseChannel := make(chan struct{}, 1)
	pack := setupWithOptions(t, appTestOptions{
		clock:               clock,
		monitorCloseChannel: mCloseChannel,
	})

	msg := []byte(uuid.New().String())

	// Start the proxy to the two way communication app.
	rootWs, err := pack.tc.CreateAppSession(context.Background(), types.CreateAppSessionRequest{
		Username:    pack.tc.Username,
		PublicAddr:  pack.rootTCPTwoWayPublicAddr,
		ClusterName: pack.rootAppClusterName,
	})
	require.NoError(t, err)
	tlsConfig := pack.makeTLSConfig(t, rootWs.GetName(), rootWs.GetUser(), pack.rootTCPTwoWayPublicAddr, pack.rootAppClusterName)

	address := pack.startLocalProxy(t, tlsConfig)

	var conn net.Conn
	var n int
	buf := make([]byte, 1024)

	// Try to read for a short amount of time.
	require.Eventually(t, func() bool {
		conn, err = net.Dial("tcp", address)
		if err != nil {
			return false
		}

		// Try to read
		n, err = conn.Read(buf)
		return err == nil
	}, time.Second*5, time.Millisecond*100)

	resp := strings.TrimSpace(string(buf[:n]))
	require.Equal(t, pack.rootTCPTwoWayMessage, resp)

	// Once we've read successfully, write, and then read again to verify the connection
	_, err = conn.Write(msg)
	require.NoError(t, err)

	n, err = conn.Read(buf)
	require.NoError(t, err, buf)

	resp = strings.TrimSpace(string(buf[:n]))
	require.Equal(t, pack.rootTCPTwoWayMessage, resp)

	// Lock the user and try to write
	pack.LockUser(t)
	clock.Advance(10 * time.Second)

	// Wait for the channel closure signal
	select {
	case <-mCloseChannel:
	case <-time.After(time.Second * 10):
		require.Fail(t, "timeout waiting for monitor channel signal")
	}
	_, err = conn.Write(msg)
	require.NoError(t, err)

	_, err = conn.Read(buf)
	require.Error(t, err)

	// Close and re-open the connection
	require.NoError(t, conn.Close())

	conn, err = net.Dial("tcp", address)
	require.NoError(t, err)

	// Try to read again, expect a failure.
	_, err = conn.Read(buf)
	require.Error(t, err, buf)
}

// TestTCPCertExpiration tests TCP application with certs expiring.
func TestTCPCertExpiration(t *testing.T) {
	clock := clockwork.NewFakeClockAt(time.Now())
	mCloseChannel := make(chan struct{}, 1)
	pack := setupWithOptions(t, appTestOptions{
		clock:               clock,
		monitorCloseChannel: mCloseChannel,
	})

	msg := []byte(uuid.New().String())

	// Start the proxy to the two way communication app.
	rootWs, err := pack.tc.CreateAppSession(context.Background(), types.CreateAppSessionRequest{
		Username:    pack.tc.Username,
		PublicAddr:  pack.rootTCPTwoWayPublicAddr,
		ClusterName: pack.rootAppClusterName,
	})
	require.NoError(t, err)
	tlsConfig := pack.makeTLSConfig(t, rootWs.GetName(), rootWs.GetUser(), pack.rootTCPTwoWayPublicAddr, pack.rootAppClusterName)

	address := pack.startLocalProxy(t, tlsConfig)

	var conn net.Conn
	var n int
	buf := make([]byte, 1024)

	// Try to read for a short amount of time.
	require.Eventually(t, func() bool {
		conn, err = net.Dial("tcp", address)
		if err != nil {
			return false
		}

		// Read, write, and read again to make sure its working as expected.
		n, err = conn.Read(buf)
		return err == nil
	}, time.Second*5, time.Millisecond*100)

	resp := strings.TrimSpace(string(buf[:n]))
	require.Equal(t, pack.rootTCPTwoWayMessage, resp)

	// Once we've read successfully, write, and then read again to verify the connection
	_, err = conn.Write(msg)
	require.NoError(t, err)

	n, err = conn.Read(buf)
	require.NoError(t, err, buf)

	resp = strings.TrimSpace(string(buf[:n]))
	require.Equal(t, pack.rootTCPTwoWayMessage, resp)

	// Let the cert expire. We'll choose 24 hours to make sure we go above
	// any cert durations that could be chosen here.
	clock.Advance(24 * time.Hour)
	// Wait for the channel closure signal
	select {
	case <-mCloseChannel:
	case <-time.After(time.Second * 10):
		require.Fail(t, "timeout waiting for monitor channel signal")
	}
	_, err = conn.Write(msg)
	require.NoError(t, err)

	_, err = conn.Read(buf)
	require.Error(t, err)

	// Close and re-open the connection
	require.NoError(t, conn.Close())

	require.Eventually(t, func() bool {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			return false
		}

		// Try to read again, expect a failure.
		_, err = conn.Read(buf)
		return err != nil
	}, time.Second*5, time.Millisecond*100)
}

// appAccessClientCert tests mutual TLS authentication flow with application
// access typically used in CLI by curl and other clients.
func (p *pack) appAccessClientCert(t *testing.T) {
	evilUser, _ := p.createUser(t)

	rootWs, err := p.tc.CreateAppSession(context.Background(), types.CreateAppSessionRequest{
		Username:    p.user.GetName(),
		PublicAddr:  p.rootAppPublicAddr,
		ClusterName: p.rootAppClusterName,
	})
	require.NoError(t, err)

	leafWs, err := p.tc.CreateAppSession(context.Background(), types.CreateAppSessionRequest{
		Username:    p.user.GetName(),
		PublicAddr:  p.leafAppPublicAddr,
		ClusterName: p.leafAppClusterName,
	})
	require.NoError(t, err)

	tests := []struct {
		desc          string
		inTLSConfig   *tls.Config
		outStatusCode int
		outMessage    string
	}{
		{
			desc:          "root cluster, valid TLS config, success",
			inTLSConfig:   p.makeTLSConfig(t, rootWs.GetName(), rootWs.GetUser(), p.rootAppPublicAddr, p.rootAppClusterName),
			outStatusCode: http.StatusOK,
			outMessage:    p.rootMessage,
		},
		{
			desc:          "leaf cluster, valid TLS config, success",
			inTLSConfig:   p.makeTLSConfig(t, leafWs.GetName(), leafWs.GetUser(), p.leafAppPublicAddr, p.leafAppClusterName),
			outStatusCode: http.StatusOK,
			outMessage:    p.leafMessage,
		},
		{
			desc:          "root cluster, invalid session ID",
			inTLSConfig:   p.makeTLSConfigNoSession(t, p.rootAppPublicAddr, p.rootAppClusterName),
			outStatusCode: http.StatusFound,
		},
		{
			desc:          "root cluster, invalid session owner",
			inTLSConfig:   p.makeTLSConfig(t, rootWs.GetName(), evilUser.GetName(), p.rootAppPublicAddr, p.rootAppClusterName),
			outStatusCode: http.StatusFound,
			outMessage:    "",
		},
		{
			desc:          "leaf cluster, invalid session owner",
			inTLSConfig:   p.makeTLSConfig(t, leafWs.GetName(), evilUser.GetName(), p.leafAppPublicAddr, p.leafAppClusterName),
			outStatusCode: http.StatusFound,
			outMessage:    "",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()
			status, body, err := p.makeRequestWithClientCert(tt.inTLSConfig, http.MethodGet, "/")
			require.NoError(t, err)
			require.Equal(t, tt.outStatusCode, status)
			require.Contains(t, body, tt.outMessage)
		})
	}
}

// appAccessFlush makes sure that application access periodically flushes
// buffered data to the response.
func (p *pack) appAccessFlush(t *testing.T) {
	req, err := http.NewRequest("GET", p.assembleRootProxyURL("/"), nil)
	require.NoError(t, err)

	cookies := p.CreateAppSession(t, p.flushAppPublicAddr, p.flushAppClusterName)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// The "flush server" will send 2 messages, "hello" and "world", with a
	// 500ms delay between them. They should arrive as 2 different frames
	// due to the periodic flushing.
	frames := []string{"hello", "world"}
	for _, frame := range frames {
		buffer := make([]byte, 1024)
		n, err := resp.Body.Read(buffer)
		if err != nil {
			require.ErrorIs(t, err, io.EOF)
		}
		require.Equal(t, frame, strings.TrimSpace(string(buffer[:n])))
	}
}

// appAccessForwardModes ensures that requests are forwarded to applications
// even when the cluster is in proxy recording mode.
func (p *pack) appAccessForwardModes(t *testing.T) {
	// Create cluster, user, sessions, and credentials package.
	ctx := context.Background()

	// Update root and leaf clusters to record sessions at the proxy.
	recConfig, err := types.NewSessionRecordingConfigFromConfigFile(types.SessionRecordingConfigSpecV2{
		Mode: types.RecordAtProxy,
	})
	require.NoError(t, err)
	err = p.rootCluster.Process.GetAuthServer().SetSessionRecordingConfig(ctx, recConfig)
	require.NoError(t, err)
	err = p.leafCluster.Process.GetAuthServer().SetSessionRecordingConfig(ctx, recConfig)
	require.NoError(t, err)

	// Requests to root and leaf cluster are successful.
	tests := []struct {
		desc          string
		inCookies     []*http.Cookie
		outStatusCode int
		outMessage    string
	}{
		{
			desc:          "root cluster, valid application session cookie, success",
			inCookies:     p.CreateAppSession(t, p.rootAppPublicAddr, p.rootAppClusterName),
			outStatusCode: http.StatusOK,
			outMessage:    p.rootMessage,
		},
		{
			desc:          "leaf cluster, valid application session cookie, success",
			inCookies:     p.CreateAppSession(t, p.leafAppPublicAddr, p.leafAppClusterName),
			outStatusCode: http.StatusOK,
			outMessage:    p.leafMessage,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()
			status, body, err := p.MakeRequest(tt.inCookies, http.MethodGet, "/")
			require.NoError(t, err)
			require.Equal(t, tt.outStatusCode, status)
			require.Contains(t, body, tt.outMessage)
		})
	}
}

// appAccessLogout verifies the session is removed from the backend when the user logs out.
func (p *pack) appAccessLogout(t *testing.T) {
	// Create an application session.
	appCookies := p.CreateAppSession(t, p.rootAppPublicAddr, p.rootAppClusterName)

	// Log user out of session.
	status, _, err := p.MakeRequest(appCookies, http.MethodGet, "/teleport-logout")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	// Wait until requests using the session cookie have failed.
	status, err = p.waitForLogout(appCookies)
	require.NoError(t, err)
	require.Equal(t, http.StatusFound, status)
}

// appAccessJWT ensures a JWT token is attached to requests and the JWT token can
// be validated.
func (p *pack) appAccessJWT(t *testing.T) {
	// Create an application session.
	appCookies := p.CreateAppSession(t, p.jwtAppPublicAddr, p.jwtAppClusterName)

	// Get JWT.
	status, token, err := p.MakeRequest(appCookies, http.MethodGet, "/")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	// Verify JWT token.
	verifyJWT(t, p, token, p.jwtAppURI)

	// Connect to websocket application that dumps the upgrade request.
	wsCookies := p.CreateAppSession(t, p.wsHeaderAppPublicAddr, p.wsHeaderAppClusterName)
	body, err := p.makeWebsocketRequest(wsCookies, "/")
	require.NoError(t, err)

	// Parse the upgrade request the websocket application received.
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(body)))
	require.NoError(t, err)

	// Extract JWT token from header and verify it.
	wsToken := req.Header.Get(teleport.AppJWTHeader)
	require.NotEmpty(t, wsToken, "websocket upgrade request doesn't contain JWT header")
	verifyJWT(t, p, wsToken, p.wsHeaderAppURI)
}

func verifyJWT(t *testing.T, pack *pack, token, appURI string) {
	// Get and unmarshal JWKs
	status, body, err := pack.MakeRequest(nil, http.MethodGet, "/.well-known/jwks.json")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	var jwks web.JWKSResponse
	err = json.Unmarshal([]byte(body), &jwks)
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 1)
	publicKey, err := jwt.UnmarshalJWK(jwks.Keys[0])
	require.NoError(t, err)

	// Verify JWT.
	key, err := jwt.New(&jwt.Config{
		PublicKey:   publicKey,
		Algorithm:   defaults.ApplicationTokenAlgorithm,
		ClusterName: pack.jwtAppClusterName,
	})
	require.NoError(t, err)
	claims, err := key.Verify(jwt.VerifyParams{
		Username: pack.username,
		RawToken: token,
		URI:      appURI,
	})
	require.NoError(t, err)
	require.Equal(t, pack.username, claims.Username)
	require.Equal(t, pack.user.GetRoles(), claims.Roles)
}

// appAccessNoHeaderOverrides ensures that AAP-specific headers cannot be overridden
// by values passed in by the user.
func (p *pack) appAccessNoHeaderOverrides(t *testing.T) {
	// Create an application session.
	appCookies := p.CreateAppSession(t, p.headerAppPublicAddr, p.headerAppClusterName)

	// Get HTTP headers forwarded to the application.
	status, origHeaderResp, err := p.MakeRequest(appCookies, http.MethodGet, "/")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	origHeaders := strings.Split(origHeaderResp, "\n")
	require.Equal(t, len(origHeaders), len(forwardedHeaderNames)+1)

	// Construct HTTP request with custom headers.
	req, err := http.NewRequest(http.MethodGet, p.assembleRootProxyURL("/"), nil)
	require.NoError(t, err)
	for _, c := range appCookies {
		req.AddCookie(c)
	}
	for _, headerName := range forwardedHeaderNames {
		req.Header.Set(headerName, uuid.New().String())
	}

	// Issue the request.
	status, newHeaderResp, err := p.sendRequest(req, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	newHeaders := strings.Split(newHeaderResp, "\n")
	require.Equal(t, len(newHeaders), len(forwardedHeaderNames)+1)

	// Headers sent to the application should not be affected.
	for i := range forwardedHeaderNames {
		require.Equal(t, origHeaders[i], newHeaders[i])
	}
}

// appAccessRewriteHeadersRoot validates that http headers from application
// rewrite configuration are correctly passed to proxied applications in root.
func (p *pack) appAccessRewriteHeadersRoot(t *testing.T) {
	// Create an application session for dumper app in root cluster.
	appCookies := p.CreateAppSession(t, "dumper-root.example.com", "example.com")

	// Get headers response and make sure headers were passed.
	status, resp, err := p.MakeRequest(appCookies, http.MethodGet, "/", service.Header{
		Name: "X-Existing", Value: "existing",
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	// Dumper app just dumps HTTP request so we should be able to read it back.
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(resp)))
	require.NoError(t, err)
	require.Equal(t, req.Host, "example.com")
	require.Equal(t, req.Header.Get("X-Teleport-Cluster"), "root")
	require.Equal(t, req.Header.Get("X-External-Env"), "production")
	require.Equal(t, req.Header.Get("X-Existing"), "rewritten-existing-header")
	require.NotEqual(t, req.Header.Get(teleport.AppJWTHeader), "rewritten-app-jwt-header")
	require.NotEqual(t, req.Header.Get(teleport.AppCFHeader), "rewritten-app-cf-header")
	require.NotEqual(t, req.Header.Get(forward.XForwardedFor), "rewritten-x-forwarded-for-header")
	require.NotEqual(t, req.Header.Get(forward.XForwardedHost), "rewritten-x-forwarded-host-header")
	require.NotEqual(t, req.Header.Get(forward.XForwardedProto), "rewritten-x-forwarded-proto-header")
	require.NotEqual(t, req.Header.Get(forward.XForwardedServer), "rewritten-x-forwarded-server-header")

	// Verify JWT tokens.
	for _, header := range []string{teleport.AppJWTHeader, teleport.AppCFHeader, "X-JWT"} {
		verifyJWT(t, p, req.Header.Get(header), p.dumperAppURI)
	}
}

// appAccessRewriteHeadersLeaf validates that http headers from application
// rewrite configuration are correctly passed to proxied applications in leaf.
func (p *pack) appAccessRewriteHeadersLeaf(t *testing.T) {
	// Create an application session for dumper app in leaf cluster.
	appCookie := p.CreateAppSession(t, "dumper-leaf.example.com", "leaf.example.com")

	// Get headers response and make sure headers were passed.
	status, resp, err := p.MakeRequest(appCookie, http.MethodGet, "/", service.Header{
		Name: "X-Existing", Value: "existing",
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, resp, "X-Teleport-Cluster: leaf")
	require.Contains(t, resp, "X-Teleport-Login: root")
	require.Contains(t, resp, "X-Teleport-Login: ubuntu")
	require.Contains(t, resp, "X-External-Env: production")
	require.Contains(t, resp, "Host: example.com")
	require.Contains(t, resp, "X-Existing: rewritten-existing-header")
	require.NotContains(t, resp, "X-Existing: existing")
	require.NotContains(t, resp, "rewritten-app-jwt-header")
	require.NotContains(t, resp, "rewritten-app-cf-header")
	require.NotContains(t, resp, "rewritten-x-forwarded-for-header")
	require.NotContains(t, resp, "rewritten-x-forwarded-host-header")
	require.NotContains(t, resp, "rewritten-x-forwarded-proto-header")
	require.NotContains(t, resp, "rewritten-x-forwarded-server-header")
}

func (p *pack) appAuditEvents(t *testing.T) {
	inCookies := p.CreateAppSession(t, p.rootAppPublicAddr, p.rootAppClusterName)

	status, body, err := p.MakeRequest(inCookies, http.MethodGet, "/")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, body, p.rootMessage)

	// session start event
	p.ensureAuditEvent(t, events.AppSessionStartEvent, func(event apievents.AuditEvent) {
		expectedEvent := &apievents.AppSessionStart{
			Metadata: apievents.Metadata{
				Type:        events.AppSessionStartEvent,
				Code:        events.AppSessionStartCode,
				ClusterName: p.rootAppClusterName,
			},
			AppMetadata: apievents.AppMetadata{
				AppURI:        p.rootAppURI,
				AppPublicAddr: p.rootAppPublicAddr,
				AppName:       p.rootAppName,
			},
			PublicAddr: p.rootAppPublicAddr,
		}
		require.Empty(t, cmp.Diff(
			expectedEvent,
			event,
			cmpopts.IgnoreTypes(apievents.ServerMetadata{}, apievents.SessionMetadata{}, apievents.UserMetadata{}, apievents.ConnectionMetadata{}),
			cmpopts.IgnoreFields(apievents.Metadata{}, "ID", "Time"),
		))
	})

	// session chunk event
	p.ensureAuditEvent(t, events.AppSessionChunkEvent, func(event apievents.AuditEvent) {
		expectedEvent := &apievents.AppSessionChunk{
			Metadata: apievents.Metadata{
				Type:        events.AppSessionChunkEvent,
				Code:        events.AppSessionChunkCode,
				ClusterName: p.rootAppClusterName,
			},
			AppMetadata: apievents.AppMetadata{
				AppURI:        p.rootAppURI,
				AppPublicAddr: p.rootAppPublicAddr,
				AppName:       p.rootAppName,
			},
		}
		require.Empty(t, cmp.Diff(
			expectedEvent,
			event,
			cmpopts.IgnoreTypes(apievents.ServerMetadata{}, apievents.SessionMetadata{}, apievents.UserMetadata{}, apievents.ConnectionMetadata{}),
			cmpopts.IgnoreFields(apievents.Metadata{}, "ID", "Time"),
			cmpopts.IgnoreFields(apievents.AppSessionChunk{}, "SessionChunkID"),
		))
	})
}

func (p *pack) appServersHA(t *testing.T) {
	type packInfo struct {
		clusterName    string
		publicHTTPAddr string
		publicWSAddr   string
		appServers     []*service.TeleportProcess
	}

	testCases := map[string]struct {
		packInfo          func(pack *pack) packInfo
		startAppServers   func(pack *pack, count int) []*service.TeleportProcess
		waitForTunnelConn func(t *testing.T, pack *pack, count int)
	}{
		"RootServer": {
			packInfo: func(pack *pack) packInfo {
				return packInfo{
					clusterName:    pack.rootAppClusterName,
					publicHTTPAddr: pack.rootAppPublicAddr,
					publicWSAddr:   pack.rootWSPublicAddr,
					appServers:     pack.rootAppServers,
				}
			},
			startAppServers: func(pack *pack, count int) []*service.TeleportProcess {
				return pack.startRootAppServers(t, count, appTestOptions{})
			},
			waitForTunnelConn: func(t *testing.T, pack *pack, count int) {
				waitForActiveTunnelConnections(t, pack.rootCluster.Tunnel, pack.rootCluster.Secrets.SiteName, count)
			},
		},
		"LeafServer": {
			packInfo: func(pack *pack) packInfo {
				return packInfo{
					clusterName:    pack.leafAppClusterName,
					publicHTTPAddr: pack.leafAppPublicAddr,
					publicWSAddr:   pack.leafWSPublicAddr,
					appServers:     pack.leafAppServers,
				}
			},
			startAppServers: func(pack *pack, count int) []*service.TeleportProcess {
				return pack.startLeafAppServers(t, count, appTestOptions{})
			},
			waitForTunnelConn: func(t *testing.T, pack *pack, count int) {
				waitForActiveTunnelConnections(t, pack.leafCluster.Tunnel, pack.leafCluster.Secrets.SiteName, count)
			},
		},
	}

	// asserts that the response has error.
	responseWithError := func(t *testing.T, status int, err error) {
		if status > 0 {
			require.NoError(t, err)
			require.Equal(t, http.StatusInternalServerError, status)
			return
		}

		require.Error(t, err)
	}
	// asserts that the response has no errors.
	responseWithoutError := func(t *testing.T, status int, err error) {
		if status > 0 {
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, status)
			return
		}

		require.NoError(t, err)
	}

	makeRequests := func(t *testing.T, pack *pack, httpCookies, wsCookies []*http.Cookie, responseAssertion func(*testing.T, int, error)) {
		status, _, err := pack.MakeRequest(httpCookies, http.MethodGet, "/")
		responseAssertion(t, status, err)

		_, err = pack.makeWebsocketRequest(wsCookies, "/")
		responseAssertion(t, 0, err)
	}

	for name, test := range testCases {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			info := test.packInfo(p)
			httpCookies := p.CreateAppSession(t, info.publicHTTPAddr, info.clusterName)
			wsCookies := p.CreateAppSession(t, info.publicWSAddr, info.clusterName)

			makeRequests(t, p, httpCookies, wsCookies, responseWithoutError)

			// Stop all root app servers.
			for i, appServer := range info.appServers {
				require.NoError(t, appServer.Close())
				require.NoError(t, appServer.Wait())

				if i == len(info.appServers)-1 {
					// fails only when the last one is closed.
					makeRequests(t, p, httpCookies, wsCookies, responseWithError)
				} else {
					// otherwise the request should be handled by another
					// server.
					makeRequests(t, p, httpCookies, wsCookies, responseWithoutError)
				}
			}

			servers := test.startAppServers(p, 1)
			test.waitForTunnelConn(t, p, 1)
			makeRequests(t, p, httpCookies, wsCookies, responseWithoutError)

			// Start an additional app server and stop all current running
			// ones.
			test.startAppServers(p, 1)
			test.waitForTunnelConn(t, p, 2)

			for _, appServer := range servers {
				require.NoError(t, appServer.Close())
				require.NoError(t, appServer.Wait())

				// Everytime an app server stops we issue a request to
				// guarantee that the requests are going to be resolved by
				// the remaining app servers.
				makeRequests(t, p, httpCookies, wsCookies, responseWithoutError)
			}
		})
	}
}

func (p *pack) appInvalidateAppSessionsOnLogout(t *testing.T) {
	t.Cleanup(func() {
		// This test will invalidate the web session so init it again after the
		// test, otherwise tests that run after this one will be getting 403's.
		p.initWebSession(t)
	})

	// Create an application session.
	appCookies := p.CreateAppSession(t, p.rootAppPublicAddr, p.rootAppClusterName)
	sessID := helpers.ParseCookies(t, appCookies).SessionCookie.Value

	// Issue a request to the application to guarantee everything is working correctly.
	status, _, err := p.MakeRequest(appCookies, http.MethodGet, "/")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	// Generates TLS config for making app requests.
	reqTLS := p.makeTLSConfig(t, sessID, p.username, p.rootAppPublicAddr, p.rootAppClusterName)
	require.NotNil(t, reqTLS)

	// Issue a request to the application to guarantee everything is working correctly.
	status, _, err = p.makeRequestWithClientCert(reqTLS, http.MethodGet, "/")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	// Logout from Teleport.
	status, _, err = p.makeWebapiRequest(http.MethodDelete, "sessions", []byte{})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	// As deleting WebSessions might not happen immediately, run the next request
	// in an `Eventually` block.
	require.Eventually(t, func() bool {
		// Issue another request to the application. Now, it should receive a
		// redirect because the application sessions are gone.
		status, _, err = p.MakeRequest(appCookies, http.MethodGet, "/")
		require.NoError(t, err)
		return status == http.StatusFound
	}, time.Second, 250*time.Millisecond)

	// Check the same for the client certificate.
	require.Eventually(t, func() bool {
		// Issue another request to the application. Now, it should receive a
		// redirect because the application sessions are gone.
		status, _, err = p.makeRequestWithClientCert(reqTLS, http.MethodGet, "/")
		require.NoError(t, err)
		return status == http.StatusFound
	}, time.Second, 250*time.Millisecond)
}

// pack contains identity as well as initialized Teleport clusters and instances.
type pack struct {
	username string
	password string

	tc *client.TeleportClient

	user types.User

	webCookie string
	webToken  string

	rootCluster    *TeleInstance
	rootAppServers []*service.TeleportProcess
	rootCertPool   *x509.CertPool

	rootAppName        string
	rootAppPublicAddr  string
	rootAppClusterName string
	rootMessage        string
	rootAppURI         string

	rootWSAppName    string
	rootWSPublicAddr string
	rootWSMessage    string
	rootWSAppURI     string

	rootWSSAppName    string
	rootWSSPublicAddr string
	rootWSSMessage    string
	rootWSSAppURI     string

	rootTCPAppName    string
	rootTCPPublicAddr string
	rootTCPMessage    string
	rootTCPAppURI     string

	rootTCPTwoWayAppName    string
	rootTCPTwoWayPublicAddr string
	rootTCPTwoWayMessage    string
	rootTCPTwoWayAppURI     string

	jwtAppName        string
	jwtAppPublicAddr  string
	jwtAppClusterName string
	jwtAppURI         string

	leafCluster *TeleInstance

	dumperAppURI string

	leafAppServers []*service.TeleportProcess

	leafAppName        string
	leafAppPublicAddr  string
	leafAppClusterName string
	leafMessage        string
	leafAppURI         string

	leafWSAppName    string
	leafWSPublicAddr string
	leafWSMessage    string
	leafWSAppURI     string

	leafWSSAppName    string
	leafWSSPublicAddr string
	leafWSSMessage    string
	leafWSSAppURI     string

	leafTCPAppName    string
	leafTCPPublicAddr string
	leafTCPMessage    string
	leafTCPAppURI     string

	headerAppName        string
	headerAppPublicAddr  string
	headerAppClusterName string
	headerAppURI         string

	wsHeaderAppName        string
	wsHeaderAppPublicAddr  string
	wsHeaderAppClusterName string
	wsHeaderAppURI         string

	flushAppName        string
	flushAppPublicAddr  string
	flushAppClusterName string
	flushAppURI         string
}

type appTestOptions struct {
	extraRootApps       []service.App
	extraLeafApps       []service.App
	rootClusterPorts    *InstancePorts
	leafClusterPorts    *InstancePorts
	clock               clockwork.FakeClock
	monitorCloseChannel chan struct{}

	rootConfig func(config *service.Config)
	leafConfig func(config *service.Config)
}

// setup configures all clusters and servers needed for a test.
func setup(t *testing.T) *pack {
	return setupWithOptions(t, appTestOptions{})
}

// newTCPServer starts accepting TCP connections and serving them using the
// provided handler. Handlers are expected to close client connections.
// Returns the TCP listener.
func newTCPServer(t *testing.T, handleConn func(net.Conn)) net.Listener {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := listener.Accept()
			if err == nil {
				go handleConn(conn)
			}
			if err != nil && !utils.IsOKNetworkError(err) {
				t.Error(err)
				return
			}
		}
	}()

	return listener
}

// setupWithOptions configures app access test with custom options.
func setupWithOptions(t *testing.T, opts appTestOptions) *pack {
	tr := utils.NewTracer(utils.ThisFunction()).Start()
	defer tr.Stop()

	log := utils.NewLoggerForTests()

	// Insecure development mode needs to be set because the web proxy uses a
	// self-signed certificate during tests.
	lib.SetInsecureDevMode(true)

	p := &pack{
		rootAppName:        "app-01",
		rootAppPublicAddr:  "app-01.example.com",
		rootAppClusterName: "example.com",
		rootMessage:        uuid.New().String(),

		rootWSAppName:    "ws-01",
		rootWSPublicAddr: "ws-01.example.com",
		rootWSMessage:    uuid.New().String(),

		rootWSSAppName:    "wss-01",
		rootWSSPublicAddr: "wss-01.example.com",
		rootWSSMessage:    uuid.New().String(),

		rootTCPAppName:    "tcp-01",
		rootTCPPublicAddr: "tcp-01.example.com",
		rootTCPMessage:    uuid.New().String(),

		rootTCPTwoWayAppName:    "tcp-twoway",
		rootTCPTwoWayPublicAddr: "tcp-twoway.example.com",
		rootTCPTwoWayMessage:    uuid.New().String(),

		leafAppName:        "app-02",
		leafAppPublicAddr:  "app-02.example.com",
		leafAppClusterName: "leaf.example.com",
		leafMessage:        uuid.New().String(),

		leafWSAppName:    "ws-02",
		leafWSPublicAddr: "ws-02.example.com",
		leafWSMessage:    uuid.New().String(),

		leafWSSAppName:    "wss-02",
		leafWSSPublicAddr: "wss-02.example.com",
		leafWSSMessage:    uuid.New().String(),

		leafTCPAppName:    "tcp-02",
		leafTCPPublicAddr: "tcp-02.example.com",
		leafTCPMessage:    uuid.New().String(),

		jwtAppName:        "app-03",
		jwtAppPublicAddr:  "app-03.example.com",
		jwtAppClusterName: "example.com",

		headerAppName:        "app-04",
		headerAppPublicAddr:  "app-04.example.com",
		headerAppClusterName: "example.com",

		wsHeaderAppName:        "ws-header",
		wsHeaderAppPublicAddr:  "ws-header.example.com",
		wsHeaderAppClusterName: "example.com",

		flushAppName:        "app-05",
		flushAppPublicAddr:  "app-05.example.com",
		flushAppClusterName: "example.com",
	}

	createHandler := func(handler func(conn *websocket.Conn)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			upgrader := websocket.Upgrader{
				ReadBufferSize:  1024,
				WriteBufferSize: 1024,
			}
			conn, err := upgrader.Upgrade(w, r, nil)
			require.NoError(t, err)
			handler(conn)
		}
	}

	// Start a few different HTTP server that will be acting like a proxied application.
	rootServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, p.rootMessage)
	}))
	t.Cleanup(rootServer.Close)
	// Websockets server in root cluster (ws://).
	rootWSServer := httptest.NewServer(createHandler(func(conn *websocket.Conn) {
		conn.WriteMessage(websocket.BinaryMessage, []byte(p.rootWSMessage))
		conn.Close()
	}))
	t.Cleanup(rootWSServer.Close)
	// Secure websockets server in root cluster (wss://).
	rootWSSServer := httptest.NewTLSServer(createHandler(func(conn *websocket.Conn) {
		conn.WriteMessage(websocket.BinaryMessage, []byte(p.rootWSSMessage))
		conn.Close()
	}))
	t.Cleanup(rootWSSServer.Close)
	// Plain TCP application in root cluster (tcp://).
	rootTCPServer := newTCPServer(t, func(c net.Conn) {
		c.Write([]byte(p.rootTCPMessage))
		c.Close()
	})
	t.Cleanup(func() { rootTCPServer.Close() })
	// TCP application that reads after every write in the root cluster (tcp://).
	rootTCPTwoWayServer := newTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 64)
		for {
			if _, err := c.Write([]byte(p.rootTCPTwoWayMessage)); err != nil {
				break
			}
			if _, err := c.Read(buf); err != nil {
				break
			}
		}
		c.Close()
	})
	t.Cleanup(func() { rootTCPTwoWayServer.Close() })
	// HTTP server in leaf cluster.
	leafServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, p.leafMessage)
	}))
	t.Cleanup(leafServer.Close)
	// Websockets server in leaf cluster (ws://).
	leafWSServer := httptest.NewServer(createHandler(func(conn *websocket.Conn) {
		conn.WriteMessage(websocket.BinaryMessage, []byte(p.leafWSMessage))
		conn.Close()
	}))
	t.Cleanup(leafWSServer.Close)
	// Secure websockets server in leaf cluster (wss://).
	leafWSSServer := httptest.NewTLSServer(createHandler(func(conn *websocket.Conn) {
		conn.WriteMessage(websocket.BinaryMessage, []byte(p.leafWSSMessage))
		conn.Close()
	}))
	t.Cleanup(leafWSSServer.Close)
	// Plain TCP application in leaf cluster (tcp://).
	leafTCPServer := newTCPServer(t, func(c net.Conn) {
		c.Write([]byte(p.leafTCPMessage))
		c.Close()
	})
	t.Cleanup(func() { leafTCPServer.Close() })
	// JWT server writes generated JWT token in the response.
	jwtServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, r.Header.Get(teleport.AppJWTHeader))
	}))
	t.Cleanup(jwtServer.Close)
	// Websocket header server dumps initial HTTP upgrade request in the response.
	wsHeaderServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		require.NoError(t, err)
		reqDump, err := httputil.DumpRequest(r, false)
		require.NoError(t, err)
		require.NoError(t, conn.WriteMessage(websocket.BinaryMessage, reqDump))
		require.NoError(t, conn.Close())
	}))
	t.Cleanup(wsHeaderServer.Close)
	headerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, headerName := range forwardedHeaderNames {
			fmt.Fprintln(w, r.Header.Get(headerName))
		}
	}))
	t.Cleanup(headerServer.Close)
	// Start test server that will dump all request headers in the response.
	dumperServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Write(w)
	}))
	t.Cleanup(dumperServer.Close)
	flushServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.(http.Hijacker)
		conn, _, err := h.Hijack()
		require.NoError(t, err)
		defer conn.Close()
		data := "HTTP/1.1 200 OK\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"05\r\n" +
			"hello\r\n"
		fmt.Fprint(conn, data)
		time.Sleep(500 * time.Millisecond)
		data = "05\r\n" +
			"world\r\n" +
			"0\r\n" +
			"\r\n"
		fmt.Fprint(conn, data)
	}))
	t.Cleanup(flushServer.Close)

	p.rootAppURI = rootServer.URL
	p.rootWSAppURI = rootWSServer.URL
	p.rootWSSAppURI = rootWSSServer.URL
	p.rootTCPAppURI = fmt.Sprintf("tcp://%v", rootTCPServer.Addr().String())
	p.rootTCPTwoWayAppURI = fmt.Sprintf("tcp://%v", rootTCPTwoWayServer.Addr().String())
	p.leafAppURI = leafServer.URL
	p.leafWSAppURI = leafWSServer.URL
	p.leafWSSAppURI = leafWSSServer.URL
	p.leafTCPAppURI = fmt.Sprintf("tcp://%v", leafTCPServer.Addr().String())
	p.jwtAppURI = jwtServer.URL
	p.headerAppURI = headerServer.URL
	p.wsHeaderAppURI = wsHeaderServer.URL
	p.flushAppURI = flushServer.URL
	p.dumperAppURI = dumperServer.URL

	privateKey, publicKey, err := testauthority.New().GenerateKeyPair()
	require.NoError(t, err)

	// Create a new Teleport instance with passed in configuration.
	p.rootCluster = NewInstance(InstanceConfig{
		Clock:       opts.clock,
		ClusterName: "example.com",
		HostID:      uuid.New().String(),
		NodeName:    Host,
		Priv:        privateKey,
		Pub:         publicKey,
		Log:         log,
		Ports:       opts.rootClusterPorts,
	})

	// Create a new Teleport instance with passed in configuration.
	p.leafCluster = NewInstance(InstanceConfig{
		Clock:       opts.clock,
		ClusterName: "leaf.example.com",
		HostID:      uuid.New().String(),
		NodeName:    Host,
		Priv:        privateKey,
		Pub:         publicKey,
		Log:         log,
		Ports:       opts.leafClusterPorts,
	})

	rcConf := service.MakeDefaultConfig()
	rcConf.Console = nil
	rcConf.Log = log
	rcConf.DataDir = t.TempDir()
	rcConf.Auth.Enabled = true
	rcConf.Auth.Preference.SetSecondFactor("off")
	rcConf.Auth.Preference.SetDisconnectExpiredCert(true)
	rcConf.Proxy.Enabled = true
	rcConf.Proxy.DisableWebService = false
	rcConf.Proxy.DisableWebInterface = true
	rcConf.SSH.Enabled = false
	rcConf.Apps.Enabled = false
	rcConf.CircuitBreakerConfig = breaker.NoopBreakerConfig()
	if opts.rootConfig != nil {
		opts.rootConfig(rcConf)
	}
	rcConf.Clock = opts.clock

	lcConf := service.MakeDefaultConfig()
	lcConf.Console = nil
	lcConf.Log = log
	lcConf.DataDir = t.TempDir()
	lcConf.Auth.Enabled = true
	lcConf.Auth.Preference.SetSecondFactor("off")
	lcConf.Auth.Preference.SetDisconnectExpiredCert(true)
	lcConf.Proxy.Enabled = true
	lcConf.Proxy.DisableWebService = false
	lcConf.Proxy.DisableWebInterface = true
	lcConf.SSH.Enabled = false
	lcConf.Apps.Enabled = false
	lcConf.CircuitBreakerConfig = breaker.NoopBreakerConfig()
	if opts.rootConfig != nil {
		opts.rootConfig(lcConf)
	}
	lcConf.Clock = opts.clock

	err = p.leafCluster.CreateEx(t, p.rootCluster.Secrets.AsSlice(), lcConf)
	require.NoError(t, err)
	err = p.rootCluster.CreateEx(t, p.leafCluster.Secrets.AsSlice(), rcConf)
	require.NoError(t, err)

	err = p.leafCluster.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.leafCluster.StopAll()) })
	err = p.rootCluster.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.rootCluster.StopAll()) })

	// At least one rootAppServer should start during the setup
	rootAppServersCount := 1
	p.rootAppServers = p.startRootAppServers(t, rootAppServersCount, opts)

	// At least one leafAppServer should start during the setup
	leafAppServersCount := 1
	p.leafAppServers = p.startLeafAppServers(t, leafAppServersCount, opts)

	// Create user for tests.
	p.initUser(t)

	// Create Web UI session.
	p.initWebSession(t)

	// Initialize cert pool with root CA's.
	p.initCertPool(t)

	// Initialize Teleport client with the user's credentials.
	p.initTeleportClient(t, opts)

	return p
}

// initUser will create a user within the root cluster.
func (p *pack) initUser(t *testing.T) {
	p.user, p.password = p.createUser(t)
	p.username = p.user.GetName()
}

// CreateUser creates and upserts a new user into the root cluster, and returns the new user and password.
func (p *pack) createUser(t *testing.T) (types.User, string) {
	username := uuid.New().String()
	password := uuid.New().String()

	user, err := types.NewUser(username)
	require.NoError(t, err)

	role := services.RoleForUser(user)
	role.SetLogins(types.Allow, []string{username, "root", "ubuntu"})
	err = p.rootCluster.Process.GetAuthServer().UpsertRole(context.Background(), role)
	require.NoError(t, err)

	user.AddRole(role.GetName())
	user.SetTraits(map[string][]string{"env": {"production"}, "empty": {}, "nil": nil})
	err = p.rootCluster.Process.GetAuthServer().CreateUser(context.Background(), user)
	require.NoError(t, err)

	err = p.rootCluster.Process.GetAuthServer().UpsertPassword(user.GetName(), []byte(password))
	require.NoError(t, err)
	return user, password
}

// initWebSession creates a Web UI session within the root cluster.
func (p *pack) initWebSession(t *testing.T) {
	csReq, err := json.Marshal(web.CreateSessionReq{
		User: p.username,
		Pass: p.password,
	})
	require.NoError(t, err)

	// Create POST request to create session.
	u := url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(Loopback, p.rootCluster.GetPortWeb()),
		Path:   "/v1/webapi/sessions/web",
	}
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(csReq))
	require.NoError(t, err)

	// Attach CSRF token in cookie and header.
	csrfToken, err := utils.CryptoRandomHex(32)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{
		Name:  csrf.CookieName,
		Value: csrfToken,
	})
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set(csrf.HeaderName, csrfToken)

	// Issue request.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Read in response.
	var csResp *web.CreateSessionResponse
	err = json.NewDecoder(resp.Body).Decode(&csResp)
	require.NoError(t, err)

	// Extract session cookie and bearer token.
	require.Len(t, resp.Cookies(), 1)
	cookie := resp.Cookies()[0]
	require.Equal(t, cookie.Name, web.CookieName)

	p.webCookie = cookie.Value
	p.webToken = csResp.Token
}

// initTeleportClient initializes a Teleport client with this pack's user
// credentials.
func (p *pack) initTeleportClient(t *testing.T, opts appTestOptions) {
	p.tc = p.MakeTeleportClient(t, p.username)
}

func (p *pack) MakeTeleportClient(t *testing.T, user string) *client.TeleportClient {
	creds, err := GenerateUserCreds(UserCredsRequest{
		Process:  p.rootCluster.Process,
		Username: user,
	})
	require.NoError(t, err)

	tc, err := p.rootCluster.NewClientWithCreds(ClientConfig{
		Login:   user,
		Cluster: p.rootCluster.Secrets.SiteName,
		Host:    Loopback,
		Port:    p.rootCluster.GetPortSSHInt(),
	}, *creds)
	require.NoError(t, err)
	return tc
}

// CreateAppSession creates an application session with the root cluster. The
// application that the user connects to may be running in a leaf cluster.
func (p *pack) CreateAppSession(t *testing.T, publicAddr, clusterName string) []*http.Cookie {
	require.NotEmpty(t, p.webCookie)
	require.NotEmpty(t, p.webToken)

	casReq, err := json.Marshal(web.CreateAppSessionRequest{
		FQDNHint:    publicAddr,
		PublicAddr:  publicAddr,
		ClusterName: clusterName,
	})
	require.NoError(t, err)
	statusCode, body, err := p.makeWebapiRequest(http.MethodPost, "sessions/app", casReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, statusCode)

	var casResp *web.CreateAppSessionResponse
	err = json.Unmarshal(body, &casResp)
	require.NoError(t, err)

	return []*http.Cookie{
		{
			Name:  app.CookieName,
			Value: casResp.CookieValue,
		},
		{
			Name:  app.SubjectCookieName,
			Value: casResp.SubjectCookieValue,
		},
	}
}

// LockUser will lock the configured user for this pack.
func (p *pack) LockUser(t *testing.T) {
	err := p.rootCluster.Process.GetAuthServer().UpsertLock(context.Background(), &types.LockV2{
		Spec: types.LockSpecV2{
			Target: types.LockTarget{
				User: p.username,
			},
		},
		Metadata: types.Metadata{
			Name: "test-lock",
		},
	})
	require.NoError(t, err)
}

// makeWebapiRequest makes a request to the root cluster Web API.
func (p *pack) makeWebapiRequest(method, endpoint string, payload []byte) (int, []byte, error) {
	u := url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(Loopback, p.rootCluster.GetPortWeb()),
		Path:   fmt.Sprintf("/v1/webapi/%s", endpoint),
	}

	req, err := http.NewRequest(method, u.String(), bytes.NewBuffer(payload))
	if err != nil {
		return 0, nil, trace.Wrap(err)
	}

	req.AddCookie(&http.Cookie{
		Name:  web.CookieName,
		Value: p.webCookie,
	})
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %v", p.webToken))
	req.Header.Add("Content-Type", "application/json")

	statusCode, body, err := p.sendRequest(req, nil)
	return statusCode, []byte(body), trace.Wrap(err)
}

func (p *pack) ensureAuditEvent(t *testing.T, eventType string, checkEvent func(event apievents.AuditEvent)) {
	require.Eventuallyf(t, func() bool {
		events, _, err := p.rootCluster.Process.GetAuthServer().SearchEvents(
			time.Now().Add(-time.Hour),
			time.Now().Add(time.Hour),
			apidefaults.Namespace,
			[]string{eventType},
			1,
			types.EventOrderDescending,
			"",
		)
		require.NoError(t, err)
		if len(events) == 0 {
			return false
		}

		checkEvent(events[0])
		return true
	}, 500*time.Millisecond, 50*time.Millisecond, "failed to fetch audit event \"%s\"", eventType)
}

// initCertPool initializes root cluster CA pool.
func (p *pack) initCertPool(t *testing.T) {
	authClient := p.rootCluster.GetSiteAPI(p.rootCluster.Secrets.SiteName)
	ca, err := authClient.GetCertAuthority(context.Background(), types.CertAuthID{
		Type:       types.HostCA,
		DomainName: p.rootCluster.Secrets.SiteName,
	}, false)
	require.NoError(t, err)

	pool, err := services.CertPool(ca)
	require.NoError(t, err)

	p.rootCertPool = pool
}

// startLocalProxy starts a local ALPN proxy for the specified application.
func (p *pack) startLocalProxy(t *testing.T, tlsConfig *tls.Config) string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	proxy, err := alpnproxy.NewLocalProxy(alpnproxy.LocalProxyConfig{
		RemoteProxyAddr:    p.rootCluster.GetWebAddr(),
		Protocols:          []alpncommon.Protocol{alpncommon.ProtocolTCP},
		InsecureSkipVerify: true,
		Listener:           listener,
		ParentContext:      context.Background(),
		Certs:              tlsConfig.Certificates,
	})
	require.NoError(t, err)
	t.Cleanup(func() { proxy.Close() })

	go proxy.Start(context.Background())

	return proxy.GetAddr()
}

// makeTLSConfig returns TLS config suitable for making an app access request.
func (p *pack) makeTLSConfig(t *testing.T, sessionID, username, publicAddr, clusterName string) *tls.Config {
	privateKey, publicKey, err := native.GenerateKeyPair()
	require.NoError(t, err)

	// Make sure the session ID can be seen in the backend before we continue onward.
	require.Eventually(t, func() bool {
		_, err := p.rootCluster.Process.GetAuthServer().GetAppSession(context.Background(), types.GetAppSessionRequest{
			SessionID: sessionID,
		})
		return err == nil
	}, 5*time.Second, 100*time.Millisecond)
	certificate, err := p.rootCluster.Process.GetAuthServer().GenerateUserAppTestCert(
		auth.AppTestCertRequest{
			PublicKey:   publicKey,
			Username:    username,
			TTL:         time.Hour,
			PublicAddr:  publicAddr,
			ClusterName: clusterName,
			SessionID:   sessionID,
		})
	require.NoError(t, err)

	tlsCert, err := tls.X509KeyPair(certificate, privateKey)
	require.NoError(t, err)

	return &tls.Config{
		RootCAs:            p.rootCertPool,
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: true,
	}
}

// makeTLSConfigNoSession returns TLS config for application access without
// creating session to simulate nonexistent session scenario.
func (p *pack) makeTLSConfigNoSession(t *testing.T, publicAddr, clusterName string) *tls.Config {
	privateKey, publicKey, err := native.GenerateKeyPair()
	require.NoError(t, err)

	certificate, err := p.rootCluster.Process.GetAuthServer().GenerateUserAppTestCert(
		auth.AppTestCertRequest{
			PublicKey:   publicKey,
			Username:    p.user.GetName(),
			TTL:         time.Hour,
			PublicAddr:  publicAddr,
			ClusterName: clusterName,
			// Use arbitrary session ID
			SessionID: uuid.New().String(),
		})
	require.NoError(t, err)

	tlsCert, err := tls.X509KeyPair(certificate, privateKey)
	require.NoError(t, err)

	return &tls.Config{
		RootCAs:            p.rootCertPool,
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: true,
	}
}

// MakeRequest makes a request to the root cluster with the given session cookie.
func (p *pack) MakeRequest(cookies []*http.Cookie, method string, endpoint string, headers ...service.Header) (int, string, error) {
	req, err := http.NewRequest(method, p.assembleRootProxyURL(endpoint), nil)
	if err != nil {
		return 0, "", trace.Wrap(err)
	}

	// attach session cookies if passed in.
	for _, c := range cookies {
		req.AddCookie(c)
	}

	for _, h := range headers {
		req.Header.Add(h.Name, h.Value)
	}

	return p.sendRequest(req, nil)
}

// makeRequestWithClientCert makes a request to the root cluster using the
// client certificate authentication from the provided tls config.
func (p *pack) makeRequestWithClientCert(tlsConfig *tls.Config, method, endpoint string) (int, string, error) {
	req, err := http.NewRequest(method, p.assembleRootProxyURL(endpoint), nil)
	if err != nil {
		return 0, "", trace.Wrap(err)
	}
	return p.sendRequest(req, tlsConfig)
}

// makeWebsocketRequest makes a websocket request with the given session cookie.
func (p *pack) makeWebsocketRequest(cookies []*http.Cookie, endpoint string) (string, error) {
	header := http.Header{}
	dialer := websocket.Dialer{}

	for _, c := range cookies {
		header.Add("Cookie", c.String())
	}
	dialer.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, resp, err := dialer.Dial(fmt.Sprintf("wss://%s%s", net.JoinHostPort(Loopback, p.rootCluster.GetPortWeb()), endpoint), header)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	defer resp.Body.Close()
	stream := &web.WebsocketIO{Conn: conn}
	data, err := io.ReadAll(stream)
	if err != nil && websocket.IsUnexpectedCloseError(err, websocket.CloseAbnormalClosure) {
		return "", err
	}
	return string(data), nil
}

// assembleRootProxyURL returns the URL string of an endpoint at the root
// cluster's proxy web.
func (p *pack) assembleRootProxyURL(endpoint string) string {
	u := url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(Loopback, p.rootCluster.GetPortWeb()),
		Path:   endpoint,
	}
	return u.String()
}

// sendReqeust sends the request to the root cluster.
func (p *pack) sendRequest(req *http.Request, tlsConfig *tls.Config) (int, string, error) {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", trace.Wrap(err)
	}
	defer resp.Body.Close()

	// Read in response body.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", trace.Wrap(err)
	}

	return resp.StatusCode, string(body), nil
}

// waitForLogout keeps making request with the passed in session cookie until
// they return a non-200 status.
func (p *pack) waitForLogout(appCookies []*http.Cookie) (int, error) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()

	for {
		select {
		case <-ticker.C:
			status, _, err := p.MakeRequest(appCookies, http.MethodGet, "/")
			if err != nil {
				return 0, trace.Wrap(err)
			}
			if status != http.StatusOK {
				return status, nil
			}
		case <-timeout.C:
			return 0, trace.BadParameter("timed out waiting for logout")
		}
	}
}

func (p *pack) startRootAppServers(t *testing.T, count int, opts appTestOptions) []*service.TeleportProcess {
	log := utils.NewLoggerForTests()

	configs := make([]*service.Config, count)

	for i := 0; i < count; i++ {
		raConf := service.MakeDefaultConfig()
		raConf.Clock = opts.clock
		raConf.Console = nil
		raConf.Log = log
		raConf.DataDir = t.TempDir()
		raConf.SetToken("static-token-value")
		raConf.AuthServers = []utils.NetAddr{
			{
				AddrNetwork: "tcp",
				Addr:        net.JoinHostPort(Loopback, p.rootCluster.GetPortWeb()),
			},
		}
		raConf.Auth.Enabled = false
		raConf.Proxy.Enabled = false
		raConf.SSH.Enabled = false
		raConf.Apps.Enabled = true
		raConf.CircuitBreakerConfig = breaker.NoopBreakerConfig()
		raConf.Apps.MonitorCloseChannel = opts.monitorCloseChannel
		raConf.Apps.Apps = append([]service.App{
			{
				Name:       p.rootAppName,
				URI:        p.rootAppURI,
				PublicAddr: p.rootAppPublicAddr,
			},
			{
				Name:       p.rootWSAppName,
				URI:        p.rootWSAppURI,
				PublicAddr: p.rootWSPublicAddr,
			},
			{
				Name:       p.rootWSSAppName,
				URI:        p.rootWSSAppURI,
				PublicAddr: p.rootWSSPublicAddr,
			},
			{
				Name:       p.rootTCPAppName,
				URI:        p.rootTCPAppURI,
				PublicAddr: p.rootTCPPublicAddr,
			},
			{
				Name:       p.rootTCPTwoWayAppName,
				URI:        p.rootTCPTwoWayAppURI,
				PublicAddr: p.rootTCPTwoWayPublicAddr,
			},
			{
				Name:       p.jwtAppName,
				URI:        p.jwtAppURI,
				PublicAddr: p.jwtAppPublicAddr,
			},
			{
				Name:       p.headerAppName,
				URI:        p.headerAppURI,
				PublicAddr: p.headerAppPublicAddr,
			},
			{
				Name:       p.wsHeaderAppName,
				URI:        p.wsHeaderAppURI,
				PublicAddr: p.wsHeaderAppPublicAddr,
			},
			{
				Name:       p.flushAppName,
				URI:        p.flushAppURI,
				PublicAddr: p.flushAppPublicAddr,
			},
			{
				Name:       "dumper-root",
				URI:        p.dumperAppURI,
				PublicAddr: "dumper-root.example.com",
				Rewrite: &service.Rewrite{
					Headers: []service.Header{
						{
							Name:  "X-Teleport-Cluster",
							Value: "root",
						},
						{
							Name:  "X-External-Env",
							Value: "{{external.env}}",
						},
						// Make sure can rewrite Host header.
						{
							Name:  "Host",
							Value: "example.com",
						},
						// Make sure can rewrite existing header.
						{
							Name:  "X-Existing",
							Value: "rewritten-existing-header",
						},
						// Make sure can't rewrite Teleport headers.
						{
							Name:  teleport.AppJWTHeader,
							Value: "rewritten-app-jwt-header",
						},
						{
							Name:  teleport.AppCFHeader,
							Value: "rewritten-app-cf-header",
						},
						{
							Name:  forward.XForwardedFor,
							Value: "rewritten-x-forwarded-for-header",
						},
						{
							Name:  forward.XForwardedHost,
							Value: "rewritten-x-forwarded-host-header",
						},
						{
							Name:  forward.XForwardedProto,
							Value: "rewritten-x-forwarded-proto-header",
						},
						{
							Name:  forward.XForwardedServer,
							Value: "rewritten-x-forwarded-server-header",
						},
						// Make sure we can insert JWT token in custom header.
						{
							Name:  "X-JWT",
							Value: teleport.TraitInternalJWTVariable,
						},
					},
				},
			},
		}, opts.extraRootApps...)

		configs[i] = raConf
	}

	servers, err := p.rootCluster.StartApps(configs)
	require.NoError(t, err)
	require.Equal(t, len(configs), len(servers))

	for i, appServer := range servers {
		srv := appServer
		t.Cleanup(func() {
			require.NoError(t, srv.Close())
		})
		waitForAppServer(t, p.rootCluster.Tunnel, p.rootAppClusterName, srv.Config.HostUUID, configs[i].Apps.Apps)
	}

	return servers
}

func waitForAppServer(t *testing.T, tunnel reversetunnel.Server, name string, hostUUID string, apps []service.App) {
	// Make sure that the app server is ready to accept connections.
	// The remote site cache needs to be filled with new registered application services.
	waitForAppRegInRemoteSiteCache(t, tunnel, name, apps, hostUUID)
}

func (p *pack) startLeafAppServers(t *testing.T, count int, opts appTestOptions) []*service.TeleportProcess {
	log := utils.NewLoggerForTests()
	configs := make([]*service.Config, count)

	for i := 0; i < count; i++ {
		laConf := service.MakeDefaultConfig()
		laConf.Clock = opts.clock
		laConf.Console = nil
		laConf.Log = log
		laConf.DataDir = t.TempDir()
		laConf.SetToken("static-token-value")
		laConf.AuthServers = []utils.NetAddr{
			{
				AddrNetwork: "tcp",
				Addr:        net.JoinHostPort(Loopback, p.leafCluster.GetPortWeb()),
			},
		}
		laConf.Auth.Enabled = false
		laConf.Proxy.Enabled = false
		laConf.SSH.Enabled = false
		laConf.Apps.Enabled = true
		laConf.CircuitBreakerConfig = breaker.NoopBreakerConfig()
		laConf.Apps.MonitorCloseChannel = opts.monitorCloseChannel
		laConf.Apps.Apps = append([]service.App{
			{
				Name:       p.leafAppName,
				URI:        p.leafAppURI,
				PublicAddr: p.leafAppPublicAddr,
			},
			{
				Name:       p.leafWSAppName,
				URI:        p.leafWSAppURI,
				PublicAddr: p.leafWSPublicAddr,
			},
			{
				Name:       p.leafWSSAppName,
				URI:        p.leafWSSAppURI,
				PublicAddr: p.leafWSSPublicAddr,
			},
			{
				Name:       p.leafTCPAppName,
				URI:        p.leafTCPAppURI,
				PublicAddr: p.leafTCPPublicAddr,
			},
			{
				Name:       "dumper-leaf",
				URI:        p.dumperAppURI,
				PublicAddr: "dumper-leaf.example.com",
				Rewrite: &service.Rewrite{
					Headers: []service.Header{
						{
							Name:  "X-Teleport-Cluster",
							Value: "leaf",
						},
						// In leaf clusters internal.logins variable is
						// populated with the user's root role logins.
						{
							Name:  "X-Teleport-Login",
							Value: "{{internal.logins}}",
						},
						{
							Name:  "X-External-Env",
							Value: "{{external.env}}",
						},
						// Make sure can rewrite Host header.
						{
							Name:  "Host",
							Value: "example.com",
						},
						// Make sure can rewrite existing header.
						{
							Name:  "X-Existing",
							Value: "rewritten-existing-header",
						},
						// Make sure can't rewrite Teleport headers.
						{
							Name:  teleport.AppJWTHeader,
							Value: "rewritten-app-jwt-header",
						},
						{
							Name:  teleport.AppCFHeader,
							Value: "rewritten-app-cf-header",
						},
						{
							Name:  forward.XForwardedFor,
							Value: "rewritten-x-forwarded-for-header",
						},
						{
							Name:  forward.XForwardedHost,
							Value: "rewritten-x-forwarded-host-header",
						},
						{
							Name:  forward.XForwardedProto,
							Value: "rewritten-x-forwarded-proto-header",
						},
						{
							Name:  forward.XForwardedServer,
							Value: "rewritten-x-forwarded-server-header",
						},
					},
				},
			},
		}, opts.extraLeafApps...)

		configs[i] = laConf
	}

	servers, err := p.leafCluster.StartApps(configs)
	require.NoError(t, err)
	require.Equal(t, len(configs), len(servers))

	for i, appServer := range servers {
		srv := appServer
		t.Cleanup(func() {
			require.NoError(t, srv.Close())
		})
		waitForAppServer(t, p.leafCluster.Tunnel, p.leafAppClusterName, srv.Config.HostUUID, configs[i].Apps.Apps)
	}

	return servers
}

var forwardedHeaderNames = []string{
	teleport.AppJWTHeader,
	teleport.AppCFHeader,
	"X-Forwarded-Proto",
	"X-Forwarded-Host",
	"X-Forwarded-Server",
	"X-Forwarded-For",
}

func waitForAppRegInRemoteSiteCache(t *testing.T, tunnel reversetunnel.Server, clusterName string, cfgApps []service.App, hostUUID string) {
	require.Eventually(t, func() bool {
		site, err := tunnel.GetSite(clusterName)
		require.NoError(t, err)
		ap, err := site.CachingAccessPoint()
		require.NoError(t, err)
		apps, err := ap.GetApplicationServers(context.Background(), apidefaults.Namespace)
		require.NoError(t, err)

		counter := 0
		for _, v := range apps {
			if v.GetHostID() == hostUUID {
				counter++
			}
		}
		return len(cfgApps) == counter
	}, time.Minute*2, time.Millisecond*200)
}
