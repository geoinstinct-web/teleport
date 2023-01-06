/*
Copyright 2015-2020 Gravitational, Inc.

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

package web

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/user"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/gogo/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/gravitational/roundtrip"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/julienschmidt/httprouter"
	lemma_secret "github.com/mailgun/lemma/secret"
	"github.com/pquerna/otp/totp"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/text/encoding/unicode"
	kyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/gravitational/teleport"
	apiProto "github.com/gravitational/teleport/api/client/proto"
	authproto "github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/client/webclient"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/mocku2f"
	"github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/auth/u2f"
	wanlib "github.com/gravitational/teleport/lib/auth/webauthn"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/bpf"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/fixtures"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/httplib/csrf"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/observability/tracing"
	"github.com/gravitational/teleport/lib/pam"
	"github.com/gravitational/teleport/lib/proxy"
	restricted "github.com/gravitational/teleport/lib/restrictedsession"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/secret"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/srv"
	"github.com/gravitational/teleport/lib/srv/desktop"
	"github.com/gravitational/teleport/lib/srv/desktop/tdp"
	"github.com/gravitational/teleport/lib/srv/regular"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/web/ui"
)

const hostID = "00000000-0000-0000-0000-000000000000"

type WebSuite struct {
	ctx    context.Context
	cancel context.CancelFunc

	node        *regular.Server
	proxy       *regular.Server
	proxyTunnel reversetunnel.Server
	srvID       string

	user       string
	webServer  *httptest.Server
	webHandler *APIHandler

	mockU2F     *mocku2f.Key
	server      *auth.TestServer
	proxyClient *auth.Client
	clock       clockwork.FakeClock
}

// TestMain will re-execute Teleport to run a command if "exec" is passed to
// it as an argument. Otherwise it will run tests as normal.
func TestMain(m *testing.M) {
	utils.InitLoggerForTests()
	// If the test is re-executing itself, execute the command that comes over
	// the pipe.
	if srv.IsReexec() {
		srv.RunAndExit(os.Args[1])
		return
	}

	// Otherwise run tests as normal.
	code := m.Run()
	os.Exit(code)
}

func newWebSuite(t *testing.T) *WebSuite {
	mockU2F, err := mocku2f.Create()
	require.NoError(t, err)
	require.NotNil(t, mockU2F)

	u, err := user.Current()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	s := &WebSuite{
		mockU2F: mockU2F,
		clock:   clockwork.NewFakeClock(),
		user:    u.Username,
		ctx:     ctx,
		cancel:  cancel,
	}

	networkingConfig, err := types.NewClusterNetworkingConfigFromConfigFile(types.ClusterNetworkingConfigSpecV2{
		KeepAliveInterval: types.Duration(10 * time.Second),
	})
	require.NoError(t, err)

	s.server, err = auth.NewTestServer(auth.TestServerConfig{
		Auth: auth.TestAuthServerConfig{
			ClusterName:             "localhost",
			Dir:                     t.TempDir(),
			Clock:                   s.clock,
			ClusterNetworkingConfig: networkingConfig,
		},
	})
	require.NoError(t, err)

	// Register the auth server, since test auth server doesn't start its own
	// heartbeat.
	err = s.server.Auth().UpsertAuthServer(&types.ServerV2{
		Kind:    types.KindAuthServer,
		Version: types.V2,
		Metadata: types.Metadata{
			Namespace: apidefaults.Namespace,
			Name:      "auth",
		},
		Spec: types.ServerSpecV2{
			Addr:     s.server.TLS.Listener.Addr().String(),
			Hostname: "localhost",
			Version:  teleport.Version,
		},
	})
	require.NoError(t, err)

	priv, pub, err := s.server.AuthServer.AuthServer.GenerateKeyPair("")
	require.NoError(t, err)

	tlsPub, err := auth.PrivateKeyToPublicKeyTLS(priv)
	require.NoError(t, err)

	// start node
	certs, err := s.server.Auth().GenerateHostCerts(s.ctx,
		&apiProto.HostCertsRequest{
			HostID:       hostID,
			NodeName:     s.server.ClusterName(),
			Role:         types.RoleNode,
			PublicSSHKey: pub,
			PublicTLSKey: tlsPub,
		})
	require.NoError(t, err)

	signer, err := sshutils.NewSigner(priv, certs.SSH)
	require.NoError(t, err)

	nodeID := "node"
	nodeClient, err := s.server.NewClient(auth.TestIdentity{
		I: auth.BuiltinRole{
			Role:     types.RoleNode,
			Username: nodeID,
		},
	})
	require.NoError(t, err)

	nodeLockWatcher, err := services.NewLockWatcher(s.ctx, services.LockWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component: teleport.ComponentNode,
			Client:    nodeClient,
		},
	})
	require.NoError(t, err)

	nodeSessionController, err := srv.NewSessionController(srv.SessionControllerConfig{
		Semaphores:   nodeClient,
		AccessPoint:  nodeClient,
		LockEnforcer: nodeLockWatcher,
		Emitter:      nodeClient,
		Component:    teleport.ComponentNode,
		ServerID:     nodeID,
	})
	require.NoError(t, err)

	// create SSH service:
	nodeDataDir := t.TempDir()
	node, err := regular.New(
		ctx,
		utils.NetAddr{AddrNetwork: "tcp", Addr: "127.0.0.1:0"},
		s.server.ClusterName(),
		[]ssh.Signer{signer},
		nodeClient,
		nodeDataDir,
		"",
		utils.NetAddr{},
		nodeClient,
		regular.SetUUID(nodeID),
		regular.SetNamespace(apidefaults.Namespace),
		regular.SetShell("/bin/sh"),
		regular.SetSessionServer(nodeClient),
		regular.SetEmitter(nodeClient),
		regular.SetPAMConfig(&pam.Config{Enabled: false}),
		regular.SetBPF(&bpf.NOP{}),
		regular.SetRestrictedSessionManager(&restricted.NOP{}),
		regular.SetClock(s.clock),
		regular.SetLockWatcher(nodeLockWatcher),
		regular.SetSessionController(nodeSessionController),
	)
	require.NoError(t, err)
	s.node = node
	s.srvID = node.ID()
	require.NoError(t, s.node.Start())

	// create reverse tunnel service:
	proxyID := "proxy"
	s.proxyClient, err = s.server.NewClient(auth.TestIdentity{
		I: auth.BuiltinRole{
			Role:     types.RoleProxy,
			Username: proxyID,
		},
	})
	require.NoError(t, err)

	revTunListener, err := net.Listen("tcp", fmt.Sprintf("%v:0", s.server.ClusterName()))
	require.NoError(t, err)

	proxyLockWatcher, err := services.NewLockWatcher(s.ctx, services.LockWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component: teleport.ComponentProxy,
			Client:    s.proxyClient,
		},
	})
	require.NoError(t, err)

	proxyNodeWatcher, err := services.NewNodeWatcher(s.ctx, services.NodeWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component: teleport.ComponentProxy,
			Client:    s.proxyClient,
		},
	})
	require.NoError(t, err)

	caWatcher, err := services.NewCertAuthorityWatcher(s.ctx, services.CertAuthorityWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component: teleport.ComponentProxy,
			Client:    s.proxyClient,
		},
		Types: []types.CertAuthType{types.HostCA, types.UserCA},
	})
	require.NoError(t, err)
	defer caWatcher.Close()

	revTunServer, err := reversetunnel.NewServer(reversetunnel.Config{
		ID:                    node.ID(),
		Listener:              revTunListener,
		ClientTLS:             s.proxyClient.TLSConfig(),
		ClusterName:           s.server.ClusterName(),
		HostSigners:           []ssh.Signer{signer},
		LocalAuthClient:       s.proxyClient,
		LocalAccessPoint:      s.proxyClient,
		LocalAuthAddresses:    []string{s.server.TLS.Listener.Addr().String()},
		Emitter:               s.proxyClient,
		NewCachingAccessPoint: noCache,
		DataDir:               t.TempDir(),
		LockWatcher:           proxyLockWatcher,
		NodeWatcher:           proxyNodeWatcher,
		CertAuthorityWatcher:  caWatcher,
		Clock:                 s.clock,
		KeyGen:                testauthority.New(),
	})
	require.NoError(t, err)
	s.proxyTunnel = revTunServer

	router, err := proxy.NewRouter(proxy.RouterConfig{
		ClusterName:         s.server.ClusterName(),
		Log:                 utils.NewLoggerForTests().WithField(trace.Component, "test"),
		RemoteClusterGetter: s.proxyClient,
		SiteGetter:          revTunServer,
		TracerProvider:      tracing.NoopProvider(),
	})
	require.NoError(t, err)

	proxySessionController, err := srv.NewSessionController(srv.SessionControllerConfig{
		Semaphores:   s.proxyClient,
		AccessPoint:  s.proxyClient,
		LockEnforcer: proxyLockWatcher,
		Emitter:      s.proxyClient,
		Component:    teleport.ComponentProxy,
		ServerID:     proxyID,
	})
	require.NoError(t, err)

	// proxy server:
	s.proxy, err = regular.New(
		ctx,
		utils.NetAddr{AddrNetwork: "tcp", Addr: "127.0.0.1:0"},
		s.server.ClusterName(),
		[]ssh.Signer{signer},
		s.proxyClient,
		t.TempDir(),
		"",
		utils.NetAddr{},
		s.proxyClient,
		regular.SetUUID(proxyID),
		regular.SetProxyMode(revTunServer, s.proxyClient, router),
		regular.SetSessionServer(s.proxyClient),
		regular.SetEmitter(s.proxyClient),
		regular.SetNamespace(apidefaults.Namespace),
		regular.SetBPF(&bpf.NOP{}),
		regular.SetRestrictedSessionManager(&restricted.NOP{}),
		regular.SetClock(s.clock),
		regular.SetLockWatcher(proxyLockWatcher),
		regular.SetNodeWatcher(proxyNodeWatcher),
		regular.SetSessionController(proxySessionController),
	)
	require.NoError(t, err)

	// Expired sessions are purged immediately
	var sessionLingeringThreshold time.Duration
	fs, err := NewDebugFileSystem("../../webassets/teleport")
	require.NoError(t, err)
	handler, err := NewHandler(Config{
		Proxy:                           revTunServer,
		AuthServers:                     utils.FromAddr(s.server.TLS.Addr()),
		DomainName:                      s.server.ClusterName(),
		ProxyClient:                     s.proxyClient,
		CipherSuites:                    utils.DefaultCipherSuites(),
		AccessPoint:                     s.proxyClient,
		Context:                         s.ctx,
		HostUUID:                        proxyID,
		Emitter:                         s.proxyClient,
		StaticFS:                        fs,
		cachedSessionLingeringThreshold: &sessionLingeringThreshold,
		ProxySettings:                   &mockProxySettings{},
		SessionControl:                  proxySessionController,
		Router:                          router,
	}, SetSessionStreamPollPeriod(200*time.Millisecond), SetClock(s.clock))
	require.NoError(t, err)

	s.webServer = httptest.NewUnstartedServer(handler)
	s.webHandler = handler
	s.webServer.StartTLS()
	err = s.proxy.Start()
	require.NoError(t, err)

	// Wait for proxy to fully register before starting the test.
	for start := time.Now(); ; {
		proxies, err := s.proxyClient.GetProxies()
		require.NoError(t, err)
		if len(proxies) != 0 {
			break
		}
		if time.Since(start) > 5*time.Second {
			t.Fatal("proxy didn't register within 5s after startup")
		}
	}

	proxyAddr := utils.MustParseAddr(s.proxy.Addr())

	addr := utils.MustParseAddr(s.webServer.Listener.Addr().String())
	handler.handler.cfg.ProxyWebAddr = *addr
	handler.handler.cfg.ProxySSHAddr = *proxyAddr
	_, sshPort, err := net.SplitHostPort(proxyAddr.String())
	require.NoError(t, err)
	handler.handler.sshPort = sshPort

	t.Cleanup(func() {
		// In particular close the lock watchers by cancelling the context.
		s.cancel()

		s.webServer.Close()

		var errors []error
		if err := s.proxyTunnel.Close(); err != nil {
			errors = append(errors, err)
		}
		if err := s.node.Close(); err != nil {
			errors = append(errors, err)
		}
		s.webServer.Close()
		if err := s.proxy.Close(); err != nil {
			errors = append(errors, err)
		}
		if err := s.server.Shutdown(context.Background()); err != nil {
			errors = append(errors, err)
		}
		require.Empty(t, errors)
	})

	return s
}

func noCache(clt auth.ClientI, cacheName []string) (auth.RemoteProxyAccessPoint, error) {
	return clt, nil
}

func (r *authPack) renewSession(ctx context.Context, t *testing.T) *roundtrip.Response {
	resp, err := r.clt.PostJSON(ctx, r.clt.Endpoint("webapi", "sessions", "renew"), nil)
	require.NoError(t, err)
	return resp
}

func (r *authPack) validateAPI(ctx context.Context, t *testing.T) {
	_, err := r.clt.Get(ctx, r.clt.Endpoint("webapi", "sites"), url.Values{})
	require.NoError(t, err)
}

type authPack struct {
	otpSecret string
	user      string
	login     string
	password  string
	session   *CreateSessionResponse
	clt       *client.WebClient
	cookies   []*http.Cookie
}

// authPack returns new authenticated package consisting of created valid
// user, otp token, created web session and authenticated client.
func (s *WebSuite) authPack(t *testing.T, user string) *authPack {
	login := s.user
	pass := "abc123"
	rawSecret := "def456"
	otpSecret := base32.StdEncoding.EncodeToString([]byte(rawSecret))

	ap, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
		Type:         constants.Local,
		SecondFactor: constants.SecondFactorOTP,
	})
	require.NoError(t, err)
	err = s.server.Auth().SetAuthPreference(s.ctx, ap)
	require.NoError(t, err)

	s.createUser(t, user, login, pass, otpSecret)

	// create a valid otp token
	validToken, err := totp.GenerateCode(otpSecret, s.clock.Now())
	require.NoError(t, err)

	clt := s.client()
	req := CreateSessionReq{
		User:              user,
		Pass:              pass,
		SecondFactorToken: validToken,
	}

	csrfToken := "2ebcb768d0090ea4368e42880c970b61865c326172a4a2343b645cf5d7f20992"
	re, err := s.login(clt, csrfToken, csrfToken, req)
	require.NoError(t, err)

	var rawSess *CreateSessionResponse
	require.NoError(t, json.Unmarshal(re.Bytes(), &rawSess))

	sess, err := rawSess.response()
	require.NoError(t, err)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	clt = s.client(roundtrip.BearerAuth(sess.Token), roundtrip.CookieJar(jar))
	jar.SetCookies(s.url(), re.Cookies())

	return &authPack{
		otpSecret: otpSecret,
		user:      user,
		login:     login,
		session:   sess,
		clt:       clt,
		cookies:   re.Cookies(),
	}
}

func (s *WebSuite) createUser(t *testing.T, user string, login string, pass string, otpSecret string) {
	teleUser, err := types.NewUser(user)
	require.NoError(t, err)
	role := services.RoleForUser(teleUser)
	role.SetLogins(types.Allow, []string{login})
	options := role.GetOptions()
	options.ForwardAgent = types.NewBool(true)
	role.SetOptions(options)
	err = s.server.Auth().UpsertRole(s.ctx, role)
	require.NoError(t, err)
	teleUser.AddRole(role.GetName())

	teleUser.SetCreatedBy(types.CreatedBy{
		User: types.UserRef{Name: "some-auth-user"},
	})
	err = s.server.Auth().CreateUser(s.ctx, teleUser)
	require.NoError(t, err)

	err = s.server.Auth().UpsertPassword(user, []byte(pass))
	require.NoError(t, err)

	if otpSecret != "" {
		dev, err := services.NewTOTPDevice("otp", otpSecret, s.clock.Now())
		require.NoError(t, err)
		err = s.server.Auth().UpsertMFADevice(context.Background(), user, dev)
		require.NoError(t, err)
	}
}

func TestValidRedirectURL(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		desc, url string
		valid     bool
	}{
		{"valid absolute https url", "https://example.com?a=1", true},
		{"valid absolute http url", "http://example.com?a=1", true},
		{"valid relative url", "/path/to/something", true},
		{"garbage", "fjoiewjwpods302j09", false},
		{"empty string", "", false},
		{"block bad protocol", "javascript:alert('xss')", false},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			require.Equal(t, tt.valid, isValidRedirectURL(tt.url))
		})
	}
}

func TestMetaRedirect(t *testing.T) {
	t.Parallel()
	h := &Handler{}
	redirectHandler := h.WithMetaRedirect(func(w http.ResponseWriter, r *http.Request, p httprouter.Params) string {
		return "https://example.com"
	})
	req := httptest.NewRequest(http.MethodPost, "/some/route", nil)
	resp := httptest.NewRecorder()
	redirectHandler(resp, req, nil)
	targetElement := `<meta http-equiv="refresh" content="0;URL='https://example.com'" />`
	require.Equal(t, http.StatusOK, resp.Code)
	body := resp.Body.String()
	require.Contains(t, body, targetElement)
}

func TestSAMLSuccess(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)
	input := fixtures.SAMLOktaConnectorV2

	decoder := kyaml.NewYAMLOrJSONDecoder(strings.NewReader(input), defaults.LookaheadBufSize)
	var raw services.UnknownResource
	err := decoder.Decode(&raw)
	require.NoError(t, err)

	connector, err := services.UnmarshalSAMLConnector(raw.Raw)
	require.NoError(t, err)
	err = services.ValidateSAMLConnector(connector)
	require.NoError(t, err)

	role, err := types.NewRole(connector.GetAttributesToRoles()[0].Roles[0], types.RoleSpecV5{
		Options: types.RoleOptions{
			MaxSessionTTL: types.NewDuration(apidefaults.MaxCertDuration),
		},
		Allow: types.RoleConditions{
			NodeLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
			Namespaces: []string{apidefaults.Namespace},
			Rules: []types.Rule{
				types.NewRule(types.Wildcard, services.RW()),
			},
		},
	})
	require.NoError(t, err)
	role.SetLogins(types.Allow, []string{s.user})
	err = s.server.Auth().UpsertRole(s.ctx, role)
	require.NoError(t, err)

	err = s.server.Auth().CreateSAMLConnector(connector)
	require.NoError(t, err)
	s.server.Auth().SetClock(clockwork.NewFakeClockAt(time.Date(2017, 5, 10, 18, 53, 0, 0, time.UTC)))
	clt := s.clientNoRedirects()

	csrfToken := "2ebcb768d0090ea4368e42880c970b61865c326172a4a2343b645cf5d7f20992"

	baseURL, err := url.Parse(clt.Endpoint("webapi", "saml", "sso") + `?connector_id=` + connector.GetName() + `&redirect_url=http://localhost/after`)
	require.NoError(t, err)
	req, err := http.NewRequest("GET", baseURL.String(), nil)
	require.NoError(t, err)
	addCSRFCookieToReq(req, csrfToken)
	re, err := clt.Client.RoundTrip(func() (*http.Response, error) {
		return clt.Client.HTTPClient().Do(req)
	})
	require.NoError(t, err)

	// we got a redirect
	urlPattern := regexp.MustCompile(`URL='([^']*)'`)
	locationURL := urlPattern.FindStringSubmatch(string(re.Bytes()))[1]
	u, err := url.Parse(locationURL)
	require.NoError(t, err)
	require.Equal(t, fixtures.SAMLOktaSSO, u.Scheme+"://"+u.Host+u.Path)
	data, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	require.NoError(t, err)
	buf, err := io.ReadAll(flate.NewReader(bytes.NewReader(data)))
	require.NoError(t, err)
	doc := etree.NewDocument()
	err = doc.ReadFromBytes(buf)
	require.NoError(t, err)
	id := doc.Root().SelectAttr("ID")
	require.NotNil(t, id)

	authRequest, err := s.server.Auth().GetSAMLAuthRequest(id.Value)
	require.NoError(t, err)

	// now swap the request id to the hardcoded one in fixtures
	authRequest.ID = fixtures.SAMLOktaAuthRequestID
	authRequest.CSRFToken = csrfToken
	err = s.server.Auth().Identity.CreateSAMLAuthRequest(*authRequest, backend.Forever)
	require.NoError(t, err)

	// now respond with pre-recorded request to the POST url
	in := &bytes.Buffer{}
	fw, err := flate.NewWriter(in, flate.DefaultCompression)
	require.NoError(t, err)

	_, err = fw.Write([]byte(fixtures.SAMLOktaAuthnResponseXML))
	require.NoError(t, err)
	err = fw.Close()
	require.NoError(t, err)
	encodedResponse := base64.StdEncoding.EncodeToString(in.Bytes())
	require.NotNil(t, encodedResponse)

	// now send the response to the server to exchange it for auth session
	form := url.Values{}
	form.Add("SAMLResponse", encodedResponse)
	req, err = http.NewRequest("POST", clt.Endpoint("webapi", "saml", "acs"), strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	addCSRFCookieToReq(req, csrfToken)
	require.NoError(t, err)
	authRe, err := clt.Client.RoundTrip(func() (*http.Response, error) {
		return clt.Client.HTTPClient().Do(req)
	})

	require.NoError(t, err)
	// This route uses a meta redirect, so expect redirect URL in body instead of location header.
	require.Equal(t, http.StatusOK, authRe.Code(), "Response: %v", string(authRe.Bytes()))
	// we have got valid session
	require.NotEmpty(t, authRe.Headers().Get("Set-Cookie"))
	// we are being redirected to original URL
	require.Contains(t, string(authRe.Bytes()), "/after")
}

func TestWebSessionsCRUD(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)
	pack := s.authPack(t, "foo")

	// make sure we can use client to make authenticated requests
	re, err := pack.clt.Get(context.Background(), pack.clt.Endpoint("webapi", "sites"), url.Values{})
	require.NoError(t, err)

	var clusters []ui.Cluster
	require.NoError(t, json.Unmarshal(re.Bytes(), &clusters))

	// now delete session
	_, err = pack.clt.Delete(
		context.Background(),
		pack.clt.Endpoint("webapi", "sessions"))
	require.NoError(t, err)

	// subsequent requests trying to use this session will fail
	_, err = pack.clt.Get(context.Background(), pack.clt.Endpoint("webapi", "sites"), url.Values{})
	require.Error(t, err)
	require.True(t, trace.IsAccessDenied(err))
}

func TestCSRF(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)
	type input struct {
		reqToken    string
		cookieToken string
	}

	// create a valid user
	user := "csrfuser"
	pass := "abc123"
	otpSecret := base32.StdEncoding.EncodeToString([]byte("def456"))
	s.createUser(t, user, user, pass, otpSecret)

	// create a valid login form request
	validToken, err := totp.GenerateCode(otpSecret, time.Now())
	require.NoError(t, err)
	loginForm := CreateSessionReq{
		User:              user,
		Pass:              pass,
		SecondFactorToken: validToken,
	}

	encodedToken1 := "2ebcb768d0090ea4368e42880c970b61865c326172a4a2343b645cf5d7f20992"
	encodedToken2 := "bf355921bbf3ef3672a03e410d4194077dfa5fe863c652521763b3e7f81e7b11"
	invalid := []input{
		{reqToken: encodedToken2, cookieToken: encodedToken1},
		{reqToken: "", cookieToken: encodedToken1},
		{reqToken: "", cookieToken: ""},
		{reqToken: encodedToken1, cookieToken: ""},
	}

	clt := s.client()

	// valid
	_, err = s.login(clt, encodedToken1, encodedToken1, loginForm)
	require.NoError(t, err)

	// invalid
	for i := range invalid {
		_, err := s.login(clt, invalid[i].cookieToken, invalid[i].reqToken, loginForm)
		require.Error(t, err)
		require.True(t, trace.IsAccessDenied(err))
	}
}

func TestPasswordChange(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)
	pack := s.authPack(t, "foo")

	// invalidate the token
	s.clock.Advance(1 * time.Minute)
	validToken, err := totp.GenerateCode(pack.otpSecret, s.clock.Now())
	require.NoError(t, err)

	req := changePasswordReq{
		OldPassword:       []byte("abc123"),
		NewPassword:       []byte("abc1234"),
		SecondFactorToken: validToken,
	}

	_, err = pack.clt.PutJSON(context.Background(), pack.clt.Endpoint("webapi", "users", "password"), req)
	require.NoError(t, err)
}

// TestValidateBearerToken tests that the bearer token's user name
// matches the user name on the cookie.
func TestValidateBearerToken(t *testing.T) {
	t.Parallel()
	env := newWebPack(t, 1)
	proxy := env.proxies[0]
	pack1 := proxy.authPack(t, "user1", nil /* roles */)
	pack2 := proxy.authPack(t, "user2", nil /* roles */)

	// Swap pack1's session token with pack2's sessionToken
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	pack1.clt = proxy.newClient(t, roundtrip.BearerAuth(pack2.session.Token), roundtrip.CookieJar(jar))
	jar.SetCookies(&proxy.webURL, pack1.cookies)

	// Auth protected endpoint.
	req := changePasswordReq{}
	_, err = pack1.clt.PutJSON(context.Background(), pack1.clt.Endpoint("webapi", "users", "password"), req)
	require.True(t, trace.IsAccessDenied(err))
	require.True(t, strings.Contains(err.Error(), "bad bearer token"))
}

func TestWebSessionsBadInput(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)
	user := "bob"
	pass := "abc123"
	rawSecret := "def456"
	otpSecret := base32.StdEncoding.EncodeToString([]byte(rawSecret))

	err := s.server.Auth().UpsertPassword(user, []byte(pass))
	require.NoError(t, err)

	dev, err := services.NewTOTPDevice("otp", otpSecret, s.clock.Now())
	require.NoError(t, err)
	err = s.server.Auth().UpsertMFADevice(context.Background(), user, dev)
	require.NoError(t, err)

	// create valid token
	validToken, err := totp.GenerateCode(otpSecret, time.Now())
	require.NoError(t, err)

	clt := s.client()

	reqs := []CreateSessionReq{
		// empty request
		{},
		// missing user
		{
			Pass:              pass,
			SecondFactorToken: validToken,
		},
		// missing pass
		{
			User:              user,
			SecondFactorToken: validToken,
		},
		// bad pass
		{
			User:              user,
			Pass:              "bla bla",
			SecondFactorToken: validToken,
		},
		// bad hotp token
		{
			User:              user,
			Pass:              pass,
			SecondFactorToken: "bad token",
		},
		// missing hotp token
		{
			User: user,
			Pass: pass,
		},
	}
	for i, req := range reqs {
		t.Run(fmt.Sprintf("tc %v", i), func(t *testing.T) {
			_, err := clt.PostJSON(s.ctx, clt.Endpoint("webapi", "sessions"), req)
			require.Error(t, err)
			require.True(t, trace.IsAccessDenied(err))
		})
	}
}

type clusterNodesGetResponse struct {
	Items      []ui.Server `json:"items"`
	StartKey   string      `json:"startKey"`
	TotalCount int         `json:"totalCount"`
}

func TestClusterNodesGet(t *testing.T) {
	t.Parallel()
	env := newWebPack(t, 1)
	proxy := env.proxies[0]
	pack := proxy.authPack(t, "test-user@example.com", nil /* roles */)

	// Get the node already added by `newWebPack`
	servers, err := env.server.Auth().GetNodes(context.Background(), apidefaults.Namespace)
	require.NoError(t, err)
	require.Len(t, servers, 1)
	server1 := servers[0]

	// Add another node.
	server2, err := types.NewServerWithLabels("server2", types.KindNode, types.ServerSpecV2{}, map[string]string{"test-field": "test-value"})
	require.NoError(t, err)
	_, err = env.server.Auth().UpsertNode(context.Background(), server2)
	require.NoError(t, err)

	// Get nodes from endpoint.
	clusterName := env.server.ClusterName()
	endpoint := pack.clt.Endpoint("webapi", "sites", clusterName, "nodes")
	re, err := pack.clt.Get(context.Background(), endpoint, url.Values{})
	require.NoError(t, err)

	u, err := user.Current()
	require.NoError(t, err)

	// Test response.
	res := clusterNodesGetResponse{}
	require.NoError(t, json.Unmarshal(re.Bytes(), &res))
	require.Len(t, res.Items, 2)
	require.Equal(t, 2, res.TotalCount)
	require.ElementsMatch(t, res.Items, []ui.Server{
		{
			ClusterName: clusterName,
			Name:        server1.GetName(),
			Hostname:    server1.GetHostname(),
			Tunnel:      server1.GetUseTunnel(),
			Addr:        server1.GetAddr(),
			Labels:      []ui.Label{},
			SSHLogins:   []string{u.Username},
		},
		{
			ClusterName: clusterName,
			Name:        "server2",
			Labels:      []ui.Label{{Name: "test-field", Value: "test-value"}},
			Tunnel:      false,
			SSHLogins:   []string{u.Username},
		},
	})

	// Get nodes using shortcut.
	re, err = pack.clt.Get(context.Background(), pack.clt.Endpoint("webapi", "sites", currentSiteShortcut, "nodes"), url.Values{})
	require.NoError(t, err)

	res2 := clusterNodesGetResponse{}
	require.NoError(t, json.Unmarshal(re.Bytes(), &res2))
	require.Len(t, res.Items, 2)
	require.Equal(t, res, res2)
}

func TestSiteNodeConnectInvalidSessionID(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)
	_, err := s.makeTerminal(t, s.authPack(t, "foo"), withSessionID("/../../../foo"))
	require.Error(t, err)
}

func TestResolveServerHostPort(t *testing.T) {
	t.Parallel()
	sampleNode := types.ServerV2{}
	sampleNode.SetName("eca53e45-86a9-11e7-a893-0242ac0a0101")
	sampleNode.Spec.Hostname = "nodehostname"

	// valid cases
	validCases := []struct {
		server       string
		nodes        []types.Server
		expectedHost string
		expectedPort int
	}{
		{
			server:       "localhost",
			expectedHost: "localhost",
			expectedPort: 0,
		},
		{
			server:       "localhost:8080",
			expectedHost: "localhost",
			expectedPort: 8080,
		},
		{
			server:       "eca53e45-86a9-11e7-a893-0242ac0a0101",
			nodes:        []types.Server{&sampleNode},
			expectedHost: "nodehostname",
			expectedPort: 0,
		},
	}

	// invalid cases
	invalidCases := []struct {
		server      string
		expectedErr string
	}{
		{
			server:      ":22",
			expectedErr: "empty hostname",
		},
		{
			server:      ":",
			expectedErr: "empty hostname",
		},
		{
			server:      "",
			expectedErr: "empty server name",
		},
		{
			server:      "host:",
			expectedErr: "invalid port",
		},
		{
			server:      "host:port",
			expectedErr: "invalid port",
		},
	}

	for _, testCase := range validCases {
		host, port, err := resolveServerHostPort(testCase.server, testCase.nodes)
		require.NoError(t, err, testCase.server)
		require.Equal(t, testCase.expectedHost, host, testCase.server)
		require.Equal(t, testCase.expectedPort, port, testCase.server)
	}

	for _, testCase := range invalidCases {
		_, _, err := resolveServerHostPort(testCase.server, nil)
		require.Error(t, err, testCase.server)
		require.Regexp(t, ".*"+testCase.expectedErr+".*", err.Error(), testCase.server)
	}
}

func TestNewTerminalHandler(t *testing.T) {
	validNode := types.ServerV2{}
	validNode.SetName("eca53e45-86a9-11e7-a893-0242ac0a0101")
	validNode.Spec.Hostname = "nodehostname"

	validServer := "localhost"
	validLogin := "root"
	validSID := session.ID("eca53e45-86a9-11e7-a893-0242ac0a0101")
	validParams := session.TerminalParams{
		H: 1,
		W: 1,
	}

	makeProvider := func(server types.ServerV2) AuthProvider {
		return authProviderMock{
			server: server,
		}
	}

	// valid cases
	validCases := []struct {
		req          TerminalRequest
		authProvider AuthProvider
		expectedHost string
		expectedPort int
	}{
		{
			req: TerminalRequest{
				Login:     validLogin,
				Server:    validServer,
				SessionID: validSID,
				Term:      validParams,
			},
			authProvider: makeProvider(validNode),
			expectedHost: validServer,
			expectedPort: 0,
		},
		{
			req: TerminalRequest{
				Login:     validLogin,
				Server:    "eca53e45-86a9-11e7-a893-0242ac0a0101",
				SessionID: validSID,
				Term:      validParams,
			},
			authProvider: makeProvider(validNode),
			expectedHost: "nodehostname",
			expectedPort: 0,
		},
	}

	// invalid cases
	invalidCases := []struct {
		req          TerminalRequest
		authProvider AuthProvider
		expectedErr  string
	}{
		{
			authProvider: makeProvider(validNode),
			expectedErr:  "invalid session",
			req: TerminalRequest{
				SessionID: "",
				Login:     validLogin,
				Server:    validServer,
				Term:      validParams,
			},
		},
		{
			expectedErr:  "invalid dimensions",
			authProvider: makeProvider(validNode),
			req: TerminalRequest{
				SessionID: validSID,
				Login:     validLogin,
				Server:    validServer,
				Term: session.TerminalParams{
					H: -1,
					W: 0,
				},
			},
		},
		{
			authProvider: makeProvider(validNode),
			expectedErr:  "invalid server name",
			req: TerminalRequest{
				Server:    "localhost:port",
				SessionID: validSID,
				Login:     validLogin,
				Term:      validParams,
			},
		},
	}

	ctx := context.Background()
	for _, testCase := range validCases {
		term, err := NewTerminal(ctx, TerminalHandlerConfig{
			Req:          testCase.req,
			AuthProvider: testCase.authProvider,
			SessionCtx:   &SessionContext{},
			Router:       &proxy.Router{},
		})
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(testCase.req, term.params))
		require.Equal(t, testCase.expectedHost, testCase.expectedHost)
		require.Equal(t, testCase.expectedPort, testCase.expectedPort)
	}

	for _, testCase := range invalidCases {
		_, err := NewTerminal(ctx, TerminalHandlerConfig{
			Req:          testCase.req,
			AuthProvider: testCase.authProvider,
			SessionCtx:   &SessionContext{},
			Router:       &proxy.Router{},
		})
		require.Regexp(t, ".*"+testCase.expectedErr+".*", err.Error())
	}
}

func TestResizeTerminal(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)
	sid := session.NewID()

	errs := make(chan error, 2)
	readLoop := func(ctx context.Context, ws *websocket.Conn, ch chan<- *Envelope) {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			typ, b, err := ws.ReadMessage()
			if err != nil {
				errs <- err
				return
			}
			if typ != websocket.BinaryMessage {
				errs <- trace.BadParameter("expected binary message, got %v", typ)
				return
			}
			var envelope Envelope
			if err := proto.Unmarshal(b, &envelope); err != nil {
				errs <- trace.Wrap(err)
				return
			}
			ch <- &envelope
		}
	}

	// Create a new user "foo", open a terminal to a new session
	pack1 := s.authPack(t, "foo")
	ws1, err := s.makeTerminal(t, pack1, withSessionID(sid))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ws1.Close()) })

	// Create a new user "bar", open a terminal to the session created above
	pack2 := s.authPack(t, "bar")
	ws2, err := s.makeTerminal(t, pack2, withSessionID(sid))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ws2.Close()) })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ws1Messages := make(chan *Envelope)
	ws2Messages := make(chan *Envelope)
	go readLoop(ctx, ws1, ws1Messages)
	go readLoop(ctx, ws2, ws2Messages)

	// consume events from the first terminal
	// we exect to see at least one raw event with PTY data (indicating terminal ready)
	// and 2 resize events from the second user joining the session (one for the default
	// size, and one for the manual resize request)
	done := time.After(10 * time.Second)
	t1ResizeEvents, t1RawEvents := 0, 0
t1ready:
	for {
		select {
		case <-done:
			require.FailNow(t, "expected to receive 2 resize events (got %d) and at least 1 raw event (got %d)", t1ResizeEvents, t1RawEvents)
		case err := <-errs:
			require.NoError(t, err)
		case e := <-ws1Messages:
			if isResizeEventEnvelope(e) {
				t1ResizeEvents++
			}
			if e.GetType() == defaults.WebsocketRaw {
				t1RawEvents++
			}
			if t1ResizeEvents == 2 && t1RawEvents > 0 {
				break t1ready
			}
		}
	}

	// we should not expect to see a resize event on terminal 2,
	// since they are not broadcasted back to the originator
	select {
	case e := <-ws2Messages:
		if isResizeEventEnvelope(e) {
			require.FailNow(t, "terminal 2 chould not have received a resize event")
		}
	case err := <-errs:
		require.NoError(t, err)
	case <-time.After(1 * time.Second):
	}

	// Resize the second terminal. This should be reflected only on the first terminal
	// because resize events are sent to participants but not the originator..
	params, err := session.NewTerminalParamsFromInt(300, 120)
	require.NoError(t, err)
	data, err := json.Marshal(events.EventFields{
		events.EventType:      events.ResizeEvent,
		events.EventNamespace: apidefaults.Namespace,
		events.SessionEventID: sid.String(),
		events.TerminalSize:   params.Serialize(),
	})
	require.NoError(t, err)
	envelope := &Envelope{
		Version: defaults.WebsocketVersion,
		Type:    defaults.WebsocketResize,
		Payload: string(data),
	}
	envelopeBytes, err := proto.Marshal(envelope)
	require.NoError(t, err)
	err = ws2.WriteMessage(websocket.BinaryMessage, envelopeBytes)
	require.NoError(t, err)

	// the first terminal should see the resize event
	done = time.After(5 * time.Second)
	for {
		select {
		case <-done:
			require.FailNow(t, "expected to receive a final resize event")
		case err := <-errs:
			require.NoError(t, err)
		case e := <-ws1Messages:
			if isResizeEventEnvelope(e) {
				return
			}
		}
	}
}

func isResizeEventEnvelope(e *Envelope) bool {
	if e.GetType() != defaults.WebsocketAudit {
		return false
	}
	var ef events.EventFields
	if err := json.Unmarshal([]byte(e.GetPayload()), &ef); err != nil {
		return false
	}
	return ef.GetType() == events.ResizeEvent
}

// TestTerminalPing tests that the server sends continuous ping control messages.
func TestTerminalPing(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)
	ws, err := s.makeTerminal(t, s.authPack(t, "foo"), withKeepaliveInterval(500*time.Millisecond))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ws.Close()) })

	closed := false
	done := make(chan struct{})
	ws.SetPingHandler(func(message string) error {
		if closed == false {
			close(done)
			closed = true
		}

		err := ws.WriteControl(websocket.PongMessage, []byte(message), time.Now().Add(time.Second))
		if err == websocket.ErrCloseSent {
			return nil
		} else if e, ok := err.(net.Error); ok && e.Temporary() {
			return nil
		}
		return err
	})

	// We need to continuously read incoming messages in order to process ping messages.
	// We only care about receiving a ping here so dropping them is fine.
	go func() {
		for {
			_, _, err := ws.ReadMessage()
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(time.Minute):
		t.Fatal("timeout waiting for ping")
	}
}

func TestTerminal(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name            string
		recordingConfig types.SessionRecordingConfigV2
	}{
		{
			name: "node recording mode",
			recordingConfig: types.SessionRecordingConfigV2{
				Spec: types.SessionRecordingConfigSpecV2{
					Mode: types.RecordAtNodeSync,
				},
			},
		},
		{
			name: "proxy recording mode",
			recordingConfig: types.SessionRecordingConfigV2{
				Spec: types.SessionRecordingConfigSpecV2{
					Mode: types.RecordAtProxySync,
				},
			},
		},
	}

	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newWebSuite(t)

			require.NoError(t, s.server.Auth().SetSessionRecordingConfig(context.Background(), &tt.recordingConfig))

			ws, err := s.makeTerminal(t, s.authPack(t, "foo"))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, ws.Close()) })

			termHandler := newTerminalHandler()
			stream := termHandler.asTerminalStream(ws)

			// here we intentionally run a command where the output we're looking
			// for is not present in the command itself
			_, err = io.WriteString(stream, "echo txlxport | sed 's/x/e/g'\r\n")
			require.NoError(t, err)
			require.NoError(t, waitForOutput(stream, "teleport"))
		})
	}
}

func TestTerminalRequireSessionMfa(t *testing.T) {
	ctx := context.Background()
	env := newWebPack(t, 1)
	proxy := env.proxies[0]
	pack := proxy.authPack(t, "llama", nil /* roles */)

	clt, err := env.server.NewClient(auth.TestUser("llama"))
	require.NoError(t, err)

	cases := []struct {
		name                      string
		getAuthPreference         func() types.AuthPreference
		registerDevice            func() *auth.TestDevice
		getChallengeResponseBytes func(chals *auth.MFAAuthenticateChallenge, dev *auth.TestDevice) []byte
	}{
		{
			name: "with webauthn",
			getAuthPreference: func() types.AuthPreference {
				ap, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
					Type:         constants.Local,
					SecondFactor: constants.SecondFactorWebauthn,
					Webauthn: &types.Webauthn{
						RPID: "localhost",
					},
					RequireSessionMFA: true,
				})
				require.NoError(t, err)

				return ap
			},
			registerDevice: func() *auth.TestDevice {
				webauthnDev, err := auth.RegisterTestDevice(ctx, clt, "webauthn", apiProto.DeviceType_DEVICE_TYPE_WEBAUTHN, nil /* authenticator */)
				require.NoError(t, err)

				return webauthnDev
			},
			getChallengeResponseBytes: func(chals *auth.MFAAuthenticateChallenge, dev *auth.TestDevice) []byte {
				res, err := dev.SolveAuthn(&apiProto.MFAAuthenticateChallenge{
					WebauthnChallenge: wanlib.CredentialAssertionToProto(chals.WebauthnChallenge),
				})
				require.Nil(t, err)

				webauthnResBytes, err := json.Marshal(wanlib.CredentialAssertionResponseFromProto(res.GetWebauthn()))
				require.Nil(t, err)

				return webauthnResBytes
			},
		},
		{
			name: "with u2f",
			getAuthPreference: func() types.AuthPreference {
				ap, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
					Type:         constants.Local,
					SecondFactor: constants.SecondFactorU2F,
					U2F: &types.U2F{
						AppID:  "https://localhost",
						Facets: []string{"https://localhost"},
					},
					RequireSessionMFA: true,
				})
				require.NoError(t, err)

				return ap
			},
			registerDevice: func() *auth.TestDevice {
				u2fDev, err := auth.RegisterTestDevice(ctx, clt, "u2f", apiProto.DeviceType_DEVICE_TYPE_U2F, nil /* authenticator */)
				require.NoError(t, err)

				return u2fDev
			},
			getChallengeResponseBytes: func(chals *auth.MFAAuthenticateChallenge, dev *auth.TestDevice) []byte {
				res, err := dev.SolveAuthn(&apiProto.MFAAuthenticateChallenge{
					U2F: []*apiProto.U2FChallenge{{
						KeyHandle: chals.U2FChallenges[0].KeyHandle,
						Challenge: chals.U2FChallenges[0].Challenge,
						AppID:     chals.U2FChallenges[0].AppID,
						Version:   chals.U2FChallenges[0].Version,
					}},
				})
				require.NoError(t, err)

				u2fResBytes, err := json.Marshal(&u2f.AuthenticateChallengeResponse{
					KeyHandle:     res.GetU2F().KeyHandle,
					SignatureData: res.GetU2F().Signature,
					ClientData:    res.GetU2F().ClientData,
				})
				require.NoError(t, err)

				return u2fResBytes
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err = env.server.Auth().SetAuthPreference(ctx, tc.getAuthPreference())
			require.NoError(t, err)

			dev := tc.registerDevice()

			// Open a terminal to a new session.
			ws := proxy.makeTerminal(t, pack, session.NewID())

			// Wait for websocket authn challenge event.
			ty, raw, err := ws.ReadMessage()
			require.Nil(t, err)
			require.Equal(t, websocket.BinaryMessage, ty)
			var env Envelope
			require.Nil(t, proto.Unmarshal(raw, &env))

			chals := &auth.MFAAuthenticateChallenge{}
			require.Nil(t, json.Unmarshal([]byte(env.Payload), &chals))

			// Send response over ws.
			termHandler := newTerminalHandler()
			_, err = termHandler.write(tc.getChallengeResponseBytes(chals, dev), ws)
			require.Nil(t, err)

			// Test we can write.
			stream := termHandler.asTerminalStream(ws)
			_, err = io.WriteString(stream, "echo alpacas\r\n")
			require.Nil(t, err)
			require.Nil(t, waitForOutput(stream, "alpacas"))
		})
	}
}

type windowsDesktopServiceMock struct {
	listener net.Listener
}

func mustStartWindowsDesktopMock(t *testing.T, authClient *auth.Server) *windowsDesktopServiceMock {
	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, l.Close())
	})
	authID := auth.IdentityID{
		Role:     types.RoleWindowsDesktop,
		HostUUID: "windows_server",
		NodeName: "windows_server",
	}
	n, err := authClient.GetClusterName()
	require.NoError(t, err)
	dns := []string{"localhost", "127.0.0.1", desktop.WildcardServiceDNS}
	identity, err := auth.LocalRegister(authID, authClient, nil, dns, "")
	require.NoError(t, err)

	tlsConfig, err := identity.TLSConfig(nil)
	require.NoError(t, err)
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	require.NoError(t, err)

	ca, err := authClient.GetCertAuthority(context.Background(), types.CertAuthID{Type: types.UserCA, DomainName: n.GetClusterName()}, false)
	require.NoError(t, err)

	for _, kp := range services.GetTLSCerts(ca) {
		require.True(t, tlsConfig.ClientCAs.AppendCertsFromPEM(kp))
	}

	wd := &windowsDesktopServiceMock{
		listener: l,
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		tlsConn := tls.Server(conn, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("Unexpected error %v", err)
			return
		}
		wd.handleConn(t, tlsConn)
	}()

	return wd
}

func (w *windowsDesktopServiceMock) handleConn(t *testing.T, conn *tls.Conn) {
	tdpConn := tdp.NewConn(conn)

	// Ensure that incoming connection is MFAVerified.
	require.NotEmpty(t, conn.ConnectionState().PeerCertificates)
	cert := conn.ConnectionState().PeerCertificates[0]
	identity, err := tlsca.FromSubject(cert.Subject, cert.NotAfter)
	require.NoError(t, err)
	require.NotEmpty(t, identity.MFAVerified)

	msg, err := tdpConn.ReadMessage()
	require.NoError(t, err)
	require.IsType(t, tdp.ClientUsername{}, msg)

	msg, err = tdpConn.ReadMessage()
	require.NoError(t, err)
	require.IsType(t, tdp.ClientScreenSpec{}, msg)

	img := image.NewRGBA(image.Rect(0, 0, 100, 100))
	err = tdpConn.WriteMessage(tdp.NewPNG(img, tdp.PNGEncoder()))
	require.NoError(t, err)
}

func TestDesktopAccessMFARequiresMfa(t *testing.T) {
	tests := []struct {
		name           string
		authPref       types.AuthPreferenceSpecV2
		mfaHandler     func(t *testing.T, ws *websocket.Conn, dev *auth.TestDevice)
		registerDevice func(t *testing.T, ctx context.Context, clt *auth.Client) *auth.TestDevice
	}{
		{
			name: "u2f",
			authPref: types.AuthPreferenceSpecV2{
				Type:         constants.Local,
				SecondFactor: constants.SecondFactorU2F,
				U2F: &types.U2F{
					AppID:  "https://localhost",
					Facets: []string{"https://localhost"},
				},
				RequireSessionMFA: true,
			},
			mfaHandler: handleMFAU2FCChallenge,
			registerDevice: func(t *testing.T, ctx context.Context, clt *auth.Client) *auth.TestDevice {
				dev, err := auth.RegisterTestDevice(ctx, clt, "u2f", apiProto.DeviceType_DEVICE_TYPE_U2F, nil /* authenticator */)
				require.NoError(t, err)
				return dev
			},
		},
		{
			name: "webauthn",
			authPref: types.AuthPreferenceSpecV2{
				Type:         constants.Local,
				SecondFactor: constants.SecondFactorWebauthn,
				Webauthn: &types.Webauthn{
					RPID: "localhost",
				},
				RequireSessionMFA: true,
			},
			mfaHandler: handleMFAWebauthnChallenge,
			registerDevice: func(t *testing.T, ctx context.Context, clt *auth.Client) *auth.TestDevice {
				webauthnDev, err := auth.RegisterTestDevice(ctx, clt, "webauthn", apiProto.DeviceType_DEVICE_TYPE_WEBAUTHN, nil /* authenticator */)
				require.NoError(t, err)
				return webauthnDev
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			env := newWebPack(t, 1)
			proxy := env.proxies[0]
			pack := proxy.authPack(t, "llama", nil /* roles */)

			clt, err := env.server.NewClient(auth.TestUser("llama"))
			require.NoError(t, err)
			wdID := uuid.New().String()

			wdMock := mustStartWindowsDesktopMock(t, env.server.Auth())
			wd, err := types.NewWindowsDesktopV3("desktop1", nil, types.WindowsDesktopSpecV3{
				Addr:   wdMock.listener.Addr().String(),
				Domain: "CORP",
				HostID: wdID,
			})
			require.NoError(t, err)

			err = env.server.Auth().UpsertWindowsDesktop(context.Background(), wd)
			require.NoError(t, err)
			wds, err := types.NewWindowsDesktopServiceV3(wdID, types.WindowsDesktopServiceSpecV3{
				Addr:            wdMock.listener.Addr().String(),
				TeleportVersion: teleport.Version,
			})
			require.NoError(t, err)

			_, err = env.server.Auth().UpsertWindowsDesktopService(context.Background(), wds)
			require.NoError(t, err)

			ap, err := types.NewAuthPreference(tc.authPref)
			require.NoError(t, err)
			err = env.server.Auth().SetAuthPreference(ctx, ap)
			require.NoError(t, err)

			dev := tc.registerDevice(t, ctx, clt)

			ws := proxy.makeDesktopSession(t, pack, session.NewID(), env.server.TLS.Listener.Addr())
			tc.mfaHandler(t, ws, dev)

			tdpClient := tdp.NewConn(&WebsocketIO{Conn: ws})

			msg, err := tdpClient.ReadMessage()
			require.NoError(t, err)
			require.IsType(t, tdp.PNG2Frame{}, msg)
		})
	}
}
func handleMFAWebauthnChallenge(t *testing.T, ws *websocket.Conn, dev *auth.TestDevice) {
	br := bufio.NewReader(&WebsocketIO{Conn: ws})
	mt, err := br.ReadByte()
	require.NoError(t, err)
	require.Equal(t, tdp.TypeMFA, tdp.MessageType(mt))

	mfaChallange, err := tdp.DecodeMFAChallenge(br)
	require.NoError(t, err)
	res, err := dev.SolveAuthn(&apiProto.MFAAuthenticateChallenge{
		WebauthnChallenge: wanlib.CredentialAssertionToProto(mfaChallange.WebauthnChallenge),
	})
	require.NoError(t, err)
	err = tdp.NewConn(&WebsocketIO{Conn: ws}).WriteMessage(tdp.MFA{
		Type: defaults.WebsocketWebauthnChallenge[0],
		MFAAuthenticateResponse: &authproto.MFAAuthenticateResponse{
			Response: &authproto.MFAAuthenticateResponse_Webauthn{
				Webauthn: res.GetWebauthn(),
			},
		},
	})
	require.NoError(t, err)
}

func handleMFAU2FCChallenge(t *testing.T, ws *websocket.Conn, dev *auth.TestDevice) {
	br := bufio.NewReader(&WebsocketIO{Conn: ws})
	mt, err := br.ReadByte()
	require.NoError(t, err)
	require.Equal(t, tdp.TypeMFA, tdp.MessageType(mt))

	mfaChallange, err := tdp.DecodeMFAChallenge(br)
	require.NoError(t, err)
	res, err := dev.SolveAuthn(&apiProto.MFAAuthenticateChallenge{
		U2F: []*apiProto.U2FChallenge{{
			KeyHandle: mfaChallange.U2FChallenges[0].KeyHandle,
			Challenge: mfaChallange.U2FChallenges[0].Challenge,
			AppID:     mfaChallange.U2FChallenges[0].AppID,
			Version:   mfaChallange.U2FChallenges[0].Version,
		}},
	})
	require.NoError(t, err)
	err = tdp.NewConn(&WebsocketIO{Conn: ws}).WriteMessage(tdp.MFA{
		Type: defaults.WebsocketU2FChallenge[0],
		MFAAuthenticateResponse: &authproto.MFAAuthenticateResponse{
			Response: &authproto.MFAAuthenticateResponse_U2F{
				U2F: &authproto.U2FResponse{
					KeyHandle:  res.GetU2F().KeyHandle,
					ClientData: res.GetU2F().ClientData,
					Signature:  res.GetU2F().Signature,
				},
			},
		},
	})
	require.NoError(t, err)
}

func TestWebAgentForward(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)
	ws, err := s.makeTerminal(t, s.authPack(t, "foo"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ws.Close()) })

	termHandler := newTerminalHandler()
	stream := termHandler.asTerminalStream(ws)

	_, err = io.WriteString(stream, "echo $SSH_AUTH_SOCK\r\n")
	require.NoError(t, err)

	err = waitForOutput(stream, "/")
	require.NoError(t, err)
}

func TestActiveSessions(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)
	sid := session.NewID()
	pack := s.authPack(t, "foo")

	ws, err := s.makeTerminal(t, pack, withSessionID(sid))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ws.Close()) })

	termHandler := newTerminalHandler()
	stream := termHandler.asTerminalStream(ws)

	// To make sure we have a session.
	_, err = io.WriteString(stream, "echo vinsong\r\n")
	require.NoError(t, err)

	// Make sure server has replied.
	err = waitForOutput(stream, "vinsong")
	require.NoError(t, err)

	// Make sure this session appears in the list of active sessions.
	var sessResp *siteSessionsGetResponse
	for i := 0; i < 10; i++ {
		// Get site nodes and make sure the node has our active party.
		re, err := pack.clt.Get(s.ctx, pack.clt.Endpoint("webapi", "sites", s.server.ClusterName(), "sessions"), url.Values{})
		require.NoError(t, err)

		require.NoError(t, json.Unmarshal(re.Bytes(), &sessResp))
		require.Len(t, sessResp.Sessions, 1)

		// Sessions do not appear momentarily as there's async heartbeat
		// procedure.
		time.Sleep(250 * time.Millisecond)
	}

	require.Len(t, sessResp.Sessions, 1)

	sess := sessResp.Sessions[0]
	require.Equal(t, sid, sess.ID)
	require.Equal(t, s.node.GetNamespace(), sess.Namespace)
	require.NotNil(t, sess.Parties)
	require.Greater(t, sess.TerminalParams.H, 0)
	require.Greater(t, sess.TerminalParams.W, 0)
	require.Equal(t, pack.login, sess.Login)
	require.False(t, sess.Created.IsZero())
	require.False(t, sess.LastActive.IsZero())
	require.Equal(t, s.srvID, sess.ServerID)
	require.Equal(t, s.node.GetInfo().GetHostname(), sess.ServerHostname)
	require.Equal(t, s.node.GetInfo().GetAddr(), sess.ServerAddr)
	require.Equal(t, s.server.ClusterName(), sess.ClusterName)
}

// DELETE IN: 5.0.0
// Tests the code snippet from apiserver.(*Handler).siteSessionGet/siteSessionsGet
// that tests empty ClusterName and ServerHostname gets set.
func TestEmptySessionClusterHostnameIsSet(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)
	nodeClient, err := s.server.NewClient(auth.TestBuiltin(types.RoleNode))
	require.NoError(t, err)
	ctx := context.Background()

	// Create a session with empty ClusterName.
	sess1 := session.Session{
		ClusterName:    "",
		ServerID:       string(session.NewID()),
		ID:             session.NewID(),
		Namespace:      apidefaults.Namespace,
		Login:          "foo",
		Created:        time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
		LastActive:     time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
		TerminalParams: session.TerminalParams{W: 100, H: 100},
	}
	err = nodeClient.CreateSession(ctx, sess1)
	require.NoError(t, err)

	// Retrieve the session with the empty ClusterName.
	pack := s.authPack(t, "baz")
	res, err := pack.clt.Get(s.ctx, pack.clt.Endpoint("webapi", "sites", s.server.ClusterName(), "sessions", sess1.ID.String()), url.Values{})
	require.NoError(t, err)

	// Test that empty ClusterName and ServerHostname got set.
	var sessionResult *session.Session
	err = json.Unmarshal(res.Bytes(), &sessionResult)
	require.NoError(t, err)
	require.Equal(t, s.server.ClusterName(), sessionResult.ClusterName)
	require.Equal(t, sess1.ServerID, sessionResult.ServerHostname)

	// Create another session to test sessions list.
	sess2 := sess1
	sess2.ID = session.NewID()
	sess2.ServerID = string(session.NewID())
	err = nodeClient.CreateSession(ctx, sess2)
	require.NoError(t, err)

	// Retrieve sessions list.
	res, err = pack.clt.Get(s.ctx, pack.clt.Endpoint("webapi", "sites", s.server.ClusterName(), "sessions"), url.Values{})
	require.NoError(t, err)

	var sessionList *siteSessionsGetResponse
	err = json.Unmarshal(res.Bytes(), &sessionList)
	require.NoError(t, err)

	s1 := sessionList.Sessions[0]
	s2 := sessionList.Sessions[1]

	require.Equal(t, s.server.ClusterName(), s1.ClusterName)
	require.Equal(t, s.server.ClusterName(), s2.ClusterName)
	require.Equal(t, s1.ServerID, s1.ServerHostname)
	require.Equal(t, s2.ServerID, s2.ServerHostname)
}

func TestCloseConnectionsOnLogout(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)
	sid := session.NewID()
	pack := s.authPack(t, "foo")

	ws, err := s.makeTerminal(t, pack, withSessionID(sid))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ws.Close()) })

	termHandler := newTerminalHandler()
	stream := termHandler.asTerminalStream(ws)

	// to make sure we have a session
	_, err = io.WriteString(stream, "expr 137 + 39\r\n")
	require.NoError(t, err)

	// make sure server has replied
	out := make([]byte, 100)
	_, err = stream.Read(out)
	require.NoError(t, err)

	_, err = pack.clt.Delete(s.ctx, pack.clt.Endpoint("webapi", "sessions"))
	require.NoError(t, err)

	// wait until we timeout or detect that connection has been closed
	after := time.After(5 * time.Second)
	errC := make(chan error)
	go func() {
		for {
			_, err := stream.Read(out)
			if err != nil {
				errC <- err
			}
		}
	}()

	select {
	case <-after:
		t.Fatalf("timeout")
	case err := <-errC:
		require.ErrorIs(t, err, io.EOF)
	}
}

func TestCreateSession(t *testing.T) {
	t.Parallel()
	env := newWebPack(t, 1)
	proxy := env.proxies[0]
	user := "test-user@example.com"
	pack := proxy.authPack(t, user, nil /* roles */)

	// get site nodes
	re, err := pack.clt.Get(context.Background(), pack.clt.Endpoint("webapi", "sites", env.server.ClusterName(), "nodes"), url.Values{})
	require.NoError(t, err)

	nodes := clusterNodesGetResponse{}
	require.NoError(t, json.Unmarshal(re.Bytes(), &nodes))
	node := nodes.Items[0]

	sess := session.Session{
		TerminalParams: session.TerminalParams{W: 300, H: 120},
		Login:          user,
	}

	// test using node UUID
	sess.ServerID = node.Name
	re, err = pack.clt.PostJSON(
		context.Background(),
		pack.clt.Endpoint("webapi", "sites", env.server.ClusterName(), "sessions"),
		siteSessionGenerateReq{Session: sess},
	)
	require.NoError(t, err)

	var created *siteSessionGenerateResponse
	require.NoError(t, json.Unmarshal(re.Bytes(), &created))
	require.NotEmpty(t, created.Session.ID)
	require.Equal(t, node.Hostname, created.Session.ServerHostname)

	// test empty serverID (older version does not supply serverID)
	sess.ServerID = ""
	_, err = pack.clt.PostJSON(
		context.Background(),
		pack.clt.Endpoint("webapi", "sites", env.server.ClusterName(), "sessions"),
		siteSessionGenerateReq{Session: sess},
	)
	require.NoError(t, err)
}

func TestPlayback(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)
	pack := s.authPack(t, "foo")
	sid := session.NewID()
	ws, err := s.makeTerminal(t, pack, withSessionID(sid))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ws.Close()) })
}

func TestLogin(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)
	ap, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
		Type:         constants.Local,
		SecondFactor: constants.SecondFactorOff,
	})
	require.NoError(t, err)
	err = s.server.Auth().SetAuthPreference(s.ctx, ap)
	require.NoError(t, err)

	// create user
	s.createUser(t, "user1", "root", "password", "")

	loginReq, err := json.Marshal(CreateSessionReq{
		User: "user1",
		Pass: "password",
	})
	require.NoError(t, err)

	clt := s.client()
	req, err := http.NewRequest("POST", clt.Endpoint("webapi", "sessions"), bytes.NewBuffer(loginReq))
	require.NoError(t, err)

	csrfToken := "2ebcb768d0090ea4368e42880c970b61865c326172a4a2343b645cf5d7f20992"
	addCSRFCookieToReq(req, csrfToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrf.HeaderName, csrfToken)

	re, err := clt.Client.RoundTrip(func() (*http.Response, error) {
		return clt.Client.HTTPClient().Do(req)
	})
	require.NoError(t, err)

	var rawSess *CreateSessionResponse
	require.NoError(t, json.Unmarshal(re.Bytes(), &rawSess))
	cookies := re.Cookies()
	require.Len(t, cookies, 1)

	// now make sure we are logged in by calling authenticated method
	// we need to supply both session cookie and bearer token for
	// request to succeed
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	clt = s.client(roundtrip.BearerAuth(rawSess.Token), roundtrip.CookieJar(jar))
	jar.SetCookies(s.url(), re.Cookies())

	re, err = clt.Get(s.ctx, clt.Endpoint("webapi", "sites"), url.Values{})
	require.NoError(t, err)

	var clusters []ui.Cluster
	require.NoError(t, json.Unmarshal(re.Bytes(), &clusters))

	// in absence of session cookie or bearer auth the same request fill fail

	// no session cookie:
	clt = s.client(roundtrip.BearerAuth(rawSess.Token))
	_, err = clt.Get(s.ctx, clt.Endpoint("webapi", "sites"), url.Values{})
	require.Error(t, err)
	require.True(t, trace.IsAccessDenied(err))

	// no bearer token:
	clt = s.client(roundtrip.CookieJar(jar))
	_, err = clt.Get(s.ctx, clt.Endpoint("webapi", "sites"), url.Values{})
	require.Error(t, err)
	require.True(t, trace.IsAccessDenied(err))
}

func TestChangePasswordAndAddTOTPDeviceWithToken(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)

	ap, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
		Type:         constants.Local,
		SecondFactor: constants.SecondFactorOTP,
	})
	require.NoError(t, err)
	err = s.server.Auth().SetAuthPreference(s.ctx, ap)
	require.NoError(t, err)

	// create user
	s.createUser(t, "user1", "root", "password", "")

	// create password change token
	token, err := s.server.Auth().CreateResetPasswordToken(context.TODO(), auth.CreateUserTokenRequest{
		Name: "user1",
	})
	require.NoError(t, err)

	clt := s.client()
	re, err := clt.Get(context.Background(), clt.Endpoint("webapi", "users", "password", "token", token.GetName()), url.Values{})
	require.NoError(t, err)

	var uiToken *ui.ResetPasswordToken
	require.NoError(t, json.Unmarshal(re.Bytes(), &uiToken))
	require.Equal(t, token.GetUser(), uiToken.User)
	require.Equal(t, token.GetName(), uiToken.TokenID)
	require.NotNil(t, uiToken.QRCode)

	res, err := s.server.Auth().CreateRegisterChallenge(context.Background(), &apiProto.CreateRegisterChallengeRequest{
		TokenID:    token.GetName(),
		DeviceType: apiProto.DeviceType_DEVICE_TYPE_TOTP,
	})
	require.NoError(t, err)

	// Advance the clock to invalidate the TOTP token
	s.clock.Advance(1 * time.Minute)
	secondFactorToken, err := totp.GenerateCode(res.GetTOTP().GetSecret(), s.clock.Now())
	require.NoError(t, err)

	data, err := json.Marshal(auth.ChangePasswordWithTokenRequest{
		TokenID:           token.GetName(),
		Password:          []byte("abc123"),
		SecondFactorToken: secondFactorToken,
	})
	require.NoError(t, err)

	req, err := http.NewRequest("PUT", clt.Endpoint("webapi", "users", "password", "token"), bytes.NewBuffer(data))
	require.NoError(t, err)

	csrfToken := "2ebcb768d0090ea4368e42880c970b61865c326172a4a2343b645cf5d7f20992"
	addCSRFCookieToReq(req, csrfToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrf.HeaderName, csrfToken)

	re, err = clt.Client.RoundTrip(func() (*http.Response, error) {
		return clt.Client.HTTPClient().Do(req)
	})
	require.NoError(t, err)

	// Test that no recovery codes are returned b/c cloud feature isn't enabled.
	var response ui.RecoveryCodes
	require.NoError(t, json.Unmarshal(re.Bytes(), &response))
	require.Nil(t, response.Codes)
	require.Nil(t, response.Created)
}

func TestChangePasswordAndAddU2FDeviceWithToken(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)

	ap, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
		Type:         constants.Local,
		SecondFactor: constants.SecondFactorU2F,
		U2F: &types.U2F{
			AppID:  "https://" + s.server.ClusterName(),
			Facets: []string{"https://" + s.server.ClusterName()},
		},
	})
	require.NoError(t, err)
	err = s.server.Auth().SetAuthPreference(s.ctx, ap)
	require.NoError(t, err)

	s.createUser(t, "user2", "root", "password", "")

	// create reset password token
	token, err := s.server.Auth().CreateResetPasswordToken(context.TODO(), auth.CreateUserTokenRequest{
		Name: "user2",
	})
	require.NoError(t, err)

	clt := s.client()
	re, err := clt.Get(context.Background(), clt.Endpoint("webapi", "u2f", "signuptokens", token.GetName()), url.Values{})
	require.NoError(t, err)

	var u2fRegReq u2f.RegisterChallenge
	require.NoError(t, json.Unmarshal(re.Bytes(), &u2fRegReq))

	u2fRegResp, err := s.mockU2F.RegisterResponse(&u2fRegReq)
	require.NoError(t, err)

	data, err := json.Marshal(auth.ChangePasswordWithTokenRequest{
		TokenID:             token.GetName(),
		Password:            []byte("qweQWE"),
		U2FRegisterResponse: u2fRegResp,
	})
	require.NoError(t, err)

	req, err := http.NewRequest("PUT", clt.Endpoint("webapi", "users", "password", "token"), bytes.NewBuffer(data))
	require.NoError(t, err)

	csrfToken := "2ebcb768d0090ea4368e42880c970b61865c326172a4a2343b645cf5d7f20992"
	addCSRFCookieToReq(req, csrfToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrf.HeaderName, csrfToken)

	re, err = clt.Client.RoundTrip(func() (*http.Response, error) {
		return clt.Client.HTTPClient().Do(req)
	})
	require.NoError(t, err)

	// Test that no recovery codes are returned b/c cloud is not turned on.
	var response ui.RecoveryCodes
	require.NoError(t, json.Unmarshal(re.Bytes(), &response))
	require.Nil(t, response.Codes)
	require.Nil(t, response.Created)
}

// TestEmptyMotD ensures that responses returned by both /webapi/ping and
// /webapi/motd work when no MotD is set
func TestEmptyMotD(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)
	wc := s.client()

	// Given an auth server configured *not* to expose a Message Of The
	// Day...

	// When I issue a ping request...
	re, err := wc.Get(s.ctx, wc.Endpoint("webapi", "ping"), url.Values{})
	require.NoError(t, err)

	// Expect that the MotD flag in the ping response is *not* set
	var pingResponse *webclient.PingResponse
	require.NoError(t, json.Unmarshal(re.Bytes(), &pingResponse))
	require.False(t, pingResponse.Auth.HasMessageOfTheDay)

	// When I fetch the MotD...
	re, err = wc.Get(s.ctx, wc.Endpoint("webapi", "motd"), url.Values{})
	require.NoError(t, err)

	// Expect that an empty response returned
	var motdResponse *webclient.MotD
	require.NoError(t, json.Unmarshal(re.Bytes(), &motdResponse))
	require.Empty(t, motdResponse.Text)
}

// TestMotD ensures that a response is returned by both /webapi/ping and /webapi/motd
// and that that the response bodies contain their MOTD components
func TestMotD(t *testing.T) {
	t.Parallel()
	const motd = "Hello. I'm a Teleport cluster!"

	s := newWebSuite(t)
	wc := s.client()

	// Given an auth server configured to expose a Message Of The Day...
	prefs := types.DefaultAuthPreference()
	prefs.SetMessageOfTheDay(motd)
	require.NoError(t, s.server.AuthServer.AuthServer.SetAuthPreference(s.ctx, prefs))

	// When I issue a ping request...
	re, err := wc.Get(s.ctx, wc.Endpoint("webapi", "ping"), url.Values{})
	require.NoError(t, err)

	// Expect that the MotD flag in the ping response is set to indicate
	// a MotD
	var pingResponse *webclient.PingResponse
	require.NoError(t, json.Unmarshal(re.Bytes(), &pingResponse))
	require.True(t, pingResponse.Auth.HasMessageOfTheDay)

	// When I fetch the MotD...
	re, err = wc.Get(s.ctx, wc.Endpoint("webapi", "motd"), url.Values{})
	require.NoError(t, err)

	// Expect that the text returned is the configured value
	var motdResponse *webclient.MotD
	require.NoError(t, json.Unmarshal(re.Bytes(), &motdResponse))
	require.Equal(t, motd, motdResponse.Text)
}

func TestMultipleConnectors(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)
	wc := s.client()

	// create two oidc connectors, one named "foo" and another named "bar"
	oidcConnectorSpec := types.OIDCConnectorSpecV3{
		RedirectURLs: []string{"https://localhost:3080/v1/webapi/oidc/callback"},
		ClientID:     "000000000000-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
		ClientSecret: "AAAAAAAAAAAAAAAAAAAAAAAA",
		IssuerURL:    "https://oidc.example.com",
		Display:      "Login with Example",
		Scope:        []string{"group"},
		ClaimsToRoles: []types.ClaimMapping{
			{
				Claim: "group",
				Value: "admin",
				Roles: []string{"admin"},
			},
		},
	}
	o, err := types.NewOIDCConnector("foo", oidcConnectorSpec)
	require.NoError(t, err)
	err = s.server.Auth().UpsertOIDCConnector(s.ctx, o)
	require.NoError(t, err)
	o2, err := types.NewOIDCConnector("bar", oidcConnectorSpec)
	require.NoError(t, err)
	err = s.server.Auth().UpsertOIDCConnector(s.ctx, o2)
	require.NoError(t, err)

	// set the auth preferences to oidc with no connector name
	authPreference, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
		Type: "oidc",
	})
	require.NoError(t, err)
	err = s.server.Auth().SetAuthPreference(s.ctx, authPreference)
	require.NoError(t, err)

	// hit the ping endpoint to get the auth type and connector name
	re, err := wc.Get(s.ctx, wc.Endpoint("webapi", "ping"), url.Values{})
	require.NoError(t, err)
	var out *webclient.PingResponse
	require.NoError(t, json.Unmarshal(re.Bytes(), &out))

	// make sure the connector name we got back was the first connector
	// in the backend, in this case it's "bar"
	oidcConnectors, err := s.server.Auth().GetOIDCConnectors(s.ctx, false)
	require.NoError(t, err)
	require.Equal(t, oidcConnectors[0].GetName(), out.Auth.OIDC.Name)

	// update the auth preferences and this time specify the connector name
	authPreference, err = types.NewAuthPreference(types.AuthPreferenceSpecV2{
		Type:          "oidc",
		ConnectorName: "foo",
	})
	require.NoError(t, err)
	err = s.server.Auth().SetAuthPreference(s.ctx, authPreference)
	require.NoError(t, err)

	// hit the ping endpoing to get the auth type and connector name
	re, err = wc.Get(s.ctx, wc.Endpoint("webapi", "ping"), url.Values{})
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(re.Bytes(), &out))

	// make sure the connector we get back is "foo"
	require.Equal(t, "foo", out.Auth.OIDC.Name)
}

// TestConstructSSHResponse checks if the secret package uses AES-GCM to
// encrypt and decrypt data that passes through the ConstructSSHResponse
// function.
func TestConstructSSHResponse(t *testing.T) {
	key, err := secret.NewKey()
	require.NoError(t, err)

	u, err := url.Parse("http://www.example.com/callback")
	require.NoError(t, err)
	query := u.Query()
	query.Set("secret_key", key.String())
	u.RawQuery = query.Encode()

	rawresp, err := ConstructSSHResponse(AuthParams{
		Username:          "foo",
		Cert:              []byte{0x00},
		TLSCert:           []byte{0x01},
		ClientRedirectURL: u.String(),
	})
	require.NoError(t, err)

	require.Empty(t, rawresp.Query().Get("secret"))
	require.Empty(t, rawresp.Query().Get("secret_key"))
	require.NotEmpty(t, rawresp.Query().Get("response"))

	plaintext, err := key.Open([]byte(rawresp.Query().Get("response")))
	require.NoError(t, err)

	var resp *auth.SSHLoginResponse
	err = json.Unmarshal(plaintext, &resp)
	require.NoError(t, err)
	require.Equal(t, "foo", resp.Username)
	require.EqualValues(t, []byte{0x00}, resp.Cert)
	require.EqualValues(t, []byte{0x01}, resp.TLSCert)
}

// TestConstructSSHResponseLegacy checks if the secret package uses NaCl to
// encrypt and decrypt data that passes through the ConstructSSHResponse
// function.
func TestConstructSSHResponseLegacy(t *testing.T) {
	key, err := lemma_secret.NewKey()
	require.NoError(t, err)

	lemma, err := lemma_secret.New(&lemma_secret.Config{KeyBytes: key})
	require.NoError(t, err)

	u, err := url.Parse("http://www.example.com/callback")
	require.NoError(t, err)
	query := u.Query()
	query.Set("secret", lemma_secret.KeyToEncodedString(key))
	u.RawQuery = query.Encode()

	rawresp, err := ConstructSSHResponse(AuthParams{
		Username:          "foo",
		Cert:              []byte{0x00},
		TLSCert:           []byte{0x01},
		ClientRedirectURL: u.String(),
	})
	require.NoError(t, err)

	require.Empty(t, rawresp.Query().Get("secret"))
	require.Empty(t, rawresp.Query().Get("secret_key"))
	require.NotEmpty(t, rawresp.Query().Get("response"))

	var sealedData *lemma_secret.SealedBytes
	err = json.Unmarshal([]byte(rawresp.Query().Get("response")), &sealedData)
	require.NoError(t, err)

	plaintext, err := lemma.Open(sealedData)
	require.NoError(t, err)

	var resp *auth.SSHLoginResponse
	err = json.Unmarshal(plaintext, &resp)
	require.NoError(t, err)
	require.Equal(t, "foo", resp.Username)
	require.EqualValues(t, []byte{0x00}, resp.Cert)
	require.EqualValues(t, []byte{0x01}, resp.TLSCert)
}

type byTimeAndIndex []apievents.AuditEvent

func (f byTimeAndIndex) Len() int {
	return len(f)
}

func (f byTimeAndIndex) Less(i, j int) bool {
	itime := f[i].GetTime()
	jtime := f[j].GetTime()
	if itime.Equal(jtime) && events.GetSessionID(f[i]) == events.GetSessionID(f[j]) {
		return f[i].GetIndex() < f[j].GetIndex()
	}
	return itime.Before(jtime)
}

func (f byTimeAndIndex) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
}

// TestSearchClusterEvents makes sure web API allows querying events by type.
func TestSearchClusterEvents(t *testing.T) {
	t.Parallel()
	// We need a clock that uses the current time here to work around
	// the fact that filelog doesn't support emitting past events.
	clock := clockwork.NewRealClock()

	s := newWebSuite(t)
	sessionEvents := events.GenerateTestSession(events.SessionParams{
		PrintEvents: 3,
		Clock:       clock,
		ServerID:    s.proxy.ID(),
	})

	for _, e := range sessionEvents {
		require.NoError(t, s.proxyClient.EmitAuditEvent(s.ctx, e))
	}

	sort.Sort(sort.Reverse(byTimeAndIndex(sessionEvents)))
	sessionStart := sessionEvents[0]
	sessionPrint := sessionEvents[1]
	sessionEnd := sessionEvents[4]

	fromTime := []string{clock.Now().AddDate(0, -1, 0).UTC().Format(time.RFC3339)}
	toTime := []string{clock.Now().AddDate(0, 1, 0).UTC().Format(time.RFC3339)}

	testCases := []struct {
		// Comment is the test case description.
		Comment string
		// Query is the search query sent to the API.
		Query url.Values
		// Result is the expected returned list of events.
		Result []apievents.AuditEvent
		// TestStartKey is a flag to test start key value.
		TestStartKey bool
		// StartKeyValue is the value of start key to expect.
		StartKeyValue string
	}{
		{
			Comment: "Empty query",
			Query: url.Values{
				"from": fromTime,
				"to":   toTime,
			},
			Result: sessionEvents,
		},
		{
			Comment: "Query by session start event",
			Query: url.Values{
				"include": []string{sessionStart.GetType()},
				"from":    fromTime,
				"to":      toTime,
			},
			Result: sessionEvents[:1],
		},
		{
			Comment: "Query session start and session end events",
			Query: url.Values{
				"include": []string{sessionEnd.GetType() + "," + sessionStart.GetType()},
				"from":    fromTime,
				"to":      toTime,
			},
			Result: []apievents.AuditEvent{sessionStart, sessionEnd},
		},
		{
			Comment: "Query events with filter by type and limit",
			Query: url.Values{
				"include": []string{sessionPrint.GetType() + "," + sessionEnd.GetType()},
				"limit":   []string{"1"},
				"from":    fromTime,
				"to":      toTime,
			},
			Result: []apievents.AuditEvent{sessionPrint},
		},
		{
			Comment: "Query session start and session end events with limit and test returned start key",
			Query: url.Values{
				"include": []string{sessionEnd.GetType() + "," + sessionStart.GetType()},
				"limit":   []string{"1"},
				"from":    fromTime,
				"to":      toTime,
			},
			Result:        []apievents.AuditEvent{sessionStart},
			TestStartKey:  true,
			StartKeyValue: sessionStart.GetID(),
		},
		{
			Comment: "Query session start and session end events with limit and given start key",
			Query: url.Values{
				"include":  []string{sessionEnd.GetType() + "," + sessionStart.GetType()},
				"startKey": []string{sessionStart.GetID()},
				"from":     fromTime,
				"to":       toTime,
			},
			Result:        []apievents.AuditEvent{sessionEnd},
			TestStartKey:  true,
			StartKeyValue: "",
		},
	}

	pack := s.authPack(t, "foo")
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.Comment, func(t *testing.T) {
			t.Parallel()
			response, err := pack.clt.Get(s.ctx, pack.clt.Endpoint("webapi", "sites", s.server.ClusterName(), "events", "search"), tc.Query)
			require.NoError(t, err)
			var result eventsListGetResponse
			require.NoError(t, json.Unmarshal(response.Bytes(), &result))

			require.Len(t, result.Events, len(tc.Result))
			for i, resultEvent := range result.Events {
				require.Equal(t, tc.Result[i].GetType(), resultEvent.GetType())
				require.Equal(t, tc.Result[i].GetID(), resultEvent.GetID())
			}

			// Session prints do not have ID's, only sessionStart and sessionEnd.
			// When retrieving events for sessionStart and sessionEnd, sessionStart is returned first.
			if tc.TestStartKey {
				require.Equal(t, tc.StartKeyValue, result.StartKey)
			}
		})
	}
}

func TestGetClusterDetails(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)
	site, err := s.proxyTunnel.GetSite(s.server.ClusterName())
	require.NoError(t, err)
	require.NotNil(t, site)

	cluster, err := ui.GetClusterDetails(s.ctx, site)
	require.NoError(t, err)
	require.Equal(t, s.server.ClusterName(), cluster.Name)
	require.Equal(t, teleport.Version, cluster.ProxyVersion)
	require.Equal(t, fmt.Sprintf("%v:%v", s.server.ClusterName(), defaults.HTTPListenPort), cluster.PublicURL)
	require.Equal(t, teleport.RemoteClusterStatusOnline, cluster.Status)
	require.NotNil(t, cluster.LastConnected)
	require.Equal(t, teleport.Version, cluster.AuthVersion)

	nodes, err := s.proxyClient.GetNodes(s.ctx, apidefaults.Namespace)
	require.NoError(t, err)
	require.Len(t, nodes, cluster.NodeCount)
}

func TestTokenGeneration(t *testing.T) {
	tt := []struct {
		name       string
		roles      types.SystemRoles
		shouldErr  bool
		joinMethod types.JoinMethod
		allow      []*types.TokenRule
	}{
		{
			name:      "single node role",
			roles:     types.SystemRoles{types.RoleNode},
			shouldErr: false,
		},
		{
			name:      "single app role",
			roles:     types.SystemRoles{types.RoleApp},
			shouldErr: false,
		},
		{
			name:      "single db role",
			roles:     types.SystemRoles{types.RoleDatabase},
			shouldErr: false,
		},
		{
			name:      "multiple roles",
			roles:     types.SystemRoles{types.RoleNode, types.RoleApp, types.RoleDatabase},
			shouldErr: false,
		},
		{
			name:      "return error if no role is requested",
			roles:     types.SystemRoles{},
			shouldErr: true,
		},
		{
			name:       "cannot request token with IAM join method without allow field",
			roles:      types.SystemRoles{types.RoleNode},
			joinMethod: types.JoinMethodIAM,
			shouldErr:  true,
		},
		{
			name:       "can request token with IAM join method",
			roles:      types.SystemRoles{types.RoleNode},
			joinMethod: types.JoinMethodIAM,
			allow:      []*types.TokenRule{{AWSAccount: "1234"}},
			shouldErr:  false,
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := newWebPack(t, 1)

			proxy := env.proxies[0]
			pack := proxy.authPack(t, "test-user@example.com", nil /* roles */)

			endpoint := pack.clt.Endpoint("webapi", "token")
			re, err := pack.clt.PostJSON(context.Background(), endpoint, types.ProvisionTokenSpecV2{
				Roles:      tc.roles,
				JoinMethod: tc.joinMethod,
				Allow:      tc.allow,
			})

			if tc.shouldErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			var responseToken nodeJoinToken
			err = json.Unmarshal(re.Bytes(), &responseToken)
			require.NoError(t, err)

			// generated token roles should match the requested ones
			generatedToken, err := proxy.auth.Auth().GetToken(context.Background(), responseToken.ID)
			require.NoError(t, err)
			require.Equal(t, tc.roles, generatedToken.GetRoles())

			expectedJoinMethod := tc.joinMethod
			if tc.joinMethod == "" {
				expectedJoinMethod = types.JoinMethodToken
			}
			// if no joinMethod is provided, expect token method
			require.Equal(t, expectedJoinMethod, generatedToken.GetJoinMethod())
		})
	}
}

func TestClusterDatabasesGet(t *testing.T) {
	env := newWebPack(t, 1)

	proxy := env.proxies[0]
	pack := proxy.authPack(t, "test-user@example.com", nil /* roles */)

	endpoint := pack.clt.Endpoint("webapi", "sites", env.server.ClusterName(), "databases")
	re, err := pack.clt.Get(context.Background(), endpoint, url.Values{})
	require.NoError(t, err)

	type testResponse struct {
		Items      []ui.Database `json:"items"`
		TotalCount int           `json:"totalCount"`
	}

	// No db registered.
	resp := testResponse{}
	require.NoError(t, json.Unmarshal(re.Bytes(), &resp))
	require.Len(t, resp.Items, 0)

	// Register databases.
	db, err := types.NewDatabaseServerV3(types.Metadata{
		Name:   "test-db-name",
		Labels: map[string]string{"test-field": "test-value"},
	}, types.DatabaseServerSpecV3{
		Description: "test-description",
		Protocol:    "test-protocol",
		URI:         "test-uri",
		Hostname:    "test-hostname",
		HostID:      "test-hostID",
	})
	require.NoError(t, err)
	db2, err := types.NewDatabaseServerV3(types.Metadata{
		Name: "db2",
	}, types.DatabaseServerSpecV3{
		Hostname: "test-hostname",
		HostID:   "test-hostID",
	})
	require.NoError(t, err)

	_, err = env.server.Auth().UpsertDatabaseServer(context.Background(), db)
	require.NoError(t, err)
	_, err = env.server.Auth().UpsertDatabaseServer(context.Background(), db2)
	require.NoError(t, err)

	re, err = pack.clt.Get(context.Background(), endpoint, url.Values{})
	require.NoError(t, err)

	resp = testResponse{}
	require.NoError(t, json.Unmarshal(re.Bytes(), &resp))
	require.Len(t, resp.Items, 2)
	require.Equal(t, 2, resp.TotalCount)
	require.ElementsMatch(t, resp.Items, []ui.Database{{
		Name:     "test-db-name",
		Desc:     "test-description",
		Protocol: "test-protocol",
		Type:     types.DatabaseTypeSelfHosted,
		Labels:   []ui.Label{{Name: "test-field", Value: "test-value"}},
	}, {
		Name:   "db2",
		Type:   types.DatabaseTypeSelfHosted,
		Labels: []ui.Label{},
	}})
}

func TestClusterKubesGet(t *testing.T) {
	env := newWebPack(t, 1)

	proxy := env.proxies[0]
	pack := proxy.authPack(t, "test-user@example.com", nil /* roles */)

	endpoint := pack.clt.Endpoint("webapi", "sites", env.server.ClusterName(), "kubernetes")
	re, err := pack.clt.Get(context.Background(), endpoint, url.Values{})
	require.NoError(t, err)

	type testResponse struct {
		Items      []ui.KubeCluster `json:"items"`
		TotalCount int              `json:"totalCount"`
	}

	// No kube registered.
	resp := testResponse{}
	require.NoError(t, json.Unmarshal(re.Bytes(), &resp))
	require.Len(t, resp.Items, 0)

	// Register kube services.
	_, err = env.server.Auth().UpsertKubeServiceV2(context.Background(), &types.ServerV2{
		Metadata: types.Metadata{Name: "test-kube"},
		Kind:     types.KindKubeService,
		Version:  types.V2,
		Spec: types.ServerSpecV2{
			KubernetesClusters: []*types.KubernetesCluster{
				{
					Name:         "test-kube-name",
					StaticLabels: map[string]string{"test-field": "test-value"},
				},
				// tests for de-duplication
				{
					Name:         "test-kube-name",
					StaticLabels: map[string]string{"test-field": "test-value"},
				},
			},
		},
	})
	require.NoError(t, err)
	_, err = env.server.Auth().UpsertKubeServiceV2(context.Background(), &types.ServerV2{
		Metadata: types.Metadata{Name: "test-kube2"},
		Kind:     types.KindKubeService,
		Version:  types.V2,
		Spec: types.ServerSpecV2{
			KubernetesClusters: []*types.KubernetesCluster{
				{
					Name: "test-kube-name", // test dedupping
				},
				{
					Name: "test-kube-name2",
				},
			},
		},
	})
	require.NoError(t, err)

	re, err = pack.clt.Get(context.Background(), endpoint, url.Values{})
	require.NoError(t, err)

	resp = testResponse{}
	require.NoError(t, json.Unmarshal(re.Bytes(), &resp))
	require.Len(t, resp.Items, 2)
	require.Equal(t, 2, resp.TotalCount)
	require.ElementsMatch(t, resp.Items, []ui.KubeCluster{{
		Name:   "test-kube-name",
		Labels: []ui.Label{{Name: "test-field", Value: "test-value"}},
	}, {
		Name:   "test-kube-name2",
		Labels: []ui.Label{},
	}})
}

func TestClusterDesktopsGet(t *testing.T) {
	env := newWebPack(t, 1)

	proxy := env.proxies[0]
	pack := proxy.authPack(t, "test-user@example.com", nil /* roles */)

	type testResponse struct {
		Items      []ui.Desktop `json:"items"`
		TotalCount int          `json:"totalCount"`
	}

	// Add a few desktops.
	resource, err := types.NewWindowsDesktopV3("desktop1", map[string]string{"test-field": "test-value"}, types.WindowsDesktopSpecV3{
		Addr:   "addr:3389", // test stripping off rdp port
		HostID: "host",
	})
	require.NoError(t, err)
	resource2, err := types.NewWindowsDesktopV3("desktop2", map[string]string{"test-field": "test-value2"}, types.WindowsDesktopSpecV3{
		Addr:   "addr",
		HostID: "host",
	})
	require.NoError(t, err)

	err = env.server.Auth().UpsertWindowsDesktop(context.Background(), resource)
	require.NoError(t, err)
	err = env.server.Auth().UpsertWindowsDesktop(context.Background(), resource2)
	require.NoError(t, err)

	// Make the call.
	endpoint := pack.clt.Endpoint("webapi", "sites", env.server.ClusterName(), "desktops")
	re, err := pack.clt.Get(context.Background(), endpoint, url.Values{})
	require.NoError(t, err)

	// Test correct response.
	resp := testResponse{}
	require.NoError(t, json.Unmarshal(re.Bytes(), &resp))
	require.Len(t, resp.Items, 2)
	require.Equal(t, 2, resp.TotalCount)
	require.ElementsMatch(t, resp.Items, []ui.Desktop{{
		OS:     constants.WindowsOS,
		Name:   "desktop1",
		Addr:   "addr",
		Labels: []ui.Label{{Name: "test-field", Value: "test-value"}},
	}, {
		OS:     constants.WindowsOS,
		Name:   "desktop2",
		Addr:   "addr",
		Labels: []ui.Label{{Name: "test-field", Value: "test-value2"}},
	}})
}

func TestClusterAppsGet(t *testing.T) {
	env := newWebPack(t, 1)

	proxy := env.proxies[0]
	pack := proxy.authPack(t, "test-user@example.com", nil /* roles */)

	type testResponse struct {
		Items      []ui.App `json:"items"`
		TotalCount int      `json:"totalCount"`
	}

	resource := &types.AppServerV3{
		Metadata: types.Metadata{Name: "test-app"},
		Kind:     types.KindAppServer,
		Version:  types.V2,
		Spec: types.AppServerSpecV3{
			HostID: "hostid",
			App: &types.AppV3{
				Metadata: types.Metadata{
					Name:        "name",
					Description: "description",
					Labels:      map[string]string{"test-field": "test-value"},
				},
				Spec: types.AppSpecV3{
					URI:        "https://console.aws.amazon.com", // sets field awsConsole to true
					PublicAddr: "publicaddrs",
				},
			},
		},
	}

	resource2, err := types.NewAppServerV3(types.Metadata{Name: "server2"}, types.AppServerSpecV3{
		HostID: "hostid",
		App: &types.AppV3{
			Metadata: types.Metadata{Name: "app2"},
			Spec:     types.AppSpecV3{URI: "uri", PublicAddr: "publicaddrs"},
		}})
	require.NoError(t, err)

	// Register apps.
	_, err = env.server.Auth().UpsertApplicationServer(context.Background(), resource)
	require.NoError(t, err)
	_, err = env.server.Auth().UpsertApplicationServer(context.Background(), resource2)
	require.NoError(t, err)

	// Make the call.
	endpoint := pack.clt.Endpoint("webapi", "sites", env.server.ClusterName(), "apps")
	re, err := pack.clt.Get(context.Background(), endpoint, url.Values{})
	require.NoError(t, err)

	// Test correct response.
	resp := testResponse{}
	require.NoError(t, json.Unmarshal(re.Bytes(), &resp))
	require.Len(t, resp.Items, 2)
	require.Equal(t, 2, resp.TotalCount)
	require.ElementsMatch(t, resp.Items, []ui.App{{
		Name:        resource.Spec.App.GetName(),
		Description: resource.Spec.App.GetDescription(),
		URI:         resource.Spec.App.GetURI(),
		PublicAddr:  resource.Spec.App.GetPublicAddr(),
		Labels:      []ui.Label{{Name: "test-field", Value: "test-value"}},
		FQDN:        resource.Spec.App.GetPublicAddr(),
		ClusterID:   env.server.ClusterName(),
		AWSConsole:  true,
	}, {
		Name:       "app2",
		URI:        "uri",
		Labels:     []ui.Label{},
		ClusterID:  env.server.ClusterName(),
		FQDN:       "publicaddrs",
		PublicAddr: "publicaddrs",
		AWSConsole: false,
	}})

}

// TestApplicationAccessDisabled makes sure application access can be disabled
// via modules.
func TestApplicationAccessDisabled(t *testing.T) {
	modules.SetTestModules(t, &modules.TestModules{
		TestFeatures: modules.Features{
			App: false,
		},
	})

	env := newWebPack(t, 1)

	proxy := env.proxies[0]
	pack := proxy.authPack(t, "foo@example.com", nil /* roles */)

	// Register an application.
	app, err := types.NewAppV3(types.Metadata{
		Name: "panel",
	}, types.AppSpecV3{
		URI:        "localhost",
		PublicAddr: "panel.example.com",
	})
	require.NoError(t, err)
	server, err := types.NewAppServerV3FromApp(app, "host", uuid.New().String())
	require.NoError(t, err)
	_, err = env.server.Auth().UpsertApplicationServer(context.Background(), server)
	require.NoError(t, err)

	endpoint := pack.clt.Endpoint("webapi", "sessions", "app")
	_, err = pack.clt.PostJSON(context.Background(), endpoint, &CreateAppSessionRequest{
		FQDNHint:    "panel.example.com",
		PublicAddr:  "panel.example.com",
		ClusterName: "localhost",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "this Teleport cluster is not licensed for application access")
}

// TestApplicationWebSessionsDeletedAfterLogout makes sure user's application
// sessions are deleted after user logout.
func TestApplicationWebSessionsDeletedAfterLogout(t *testing.T) {
	env := newWebPack(t, 1)

	proxy := env.proxies[0]
	pack := proxy.authPack(t, "foo@example.com", nil /* roles */)

	// Register multiple applications.
	applications := []struct {
		name       string
		publicAddr string
	}{
		{name: "panel", publicAddr: "panel.example.com"},
		{name: "admin", publicAddr: "admin.example.com"},
		{name: "metrics", publicAddr: "metrics.example.com"},
	}

	// Register and create a session for each application.
	for _, application := range applications {
		// Register an application.
		app, err := types.NewAppV3(types.Metadata{
			Name: application.name,
		}, types.AppSpecV3{
			URI:        "localhost",
			PublicAddr: application.publicAddr,
		})
		require.NoError(t, err)
		server, err := types.NewAppServerV3FromApp(app, "host", uuid.New().String())
		require.NoError(t, err)
		_, err = env.server.Auth().UpsertApplicationServer(context.Background(), server)
		require.NoError(t, err)

		// Create application session
		endpoint := pack.clt.Endpoint("webapi", "sessions", "app")
		_, err = pack.clt.PostJSON(context.Background(), endpoint, &CreateAppSessionRequest{
			FQDNHint:    application.publicAddr,
			PublicAddr:  application.publicAddr,
			ClusterName: "localhost",
		})
		require.NoError(t, err)
	}

	// List sessions, should have one for each application.
	sessions, err := proxy.client.GetAppSessions(context.Background())
	require.NoError(t, err)
	require.Len(t, sessions, len(applications))

	// Logout from Telport.
	_, err = pack.clt.Delete(context.Background(), pack.clt.Endpoint("webapi", "sessions"))
	require.NoError(t, err)

	// Check sessions after logout, should be empty.
	sessions, err = proxy.client.GetAppSessions(context.Background())
	require.NoError(t, err)
	require.Len(t, sessions, 0)
}

func TestCreatePrivilegeToken(t *testing.T) {
	t.Parallel()
	env := newWebPack(t, 1)
	proxy := env.proxies[0]

	// Create a user with second factor totp.
	pack := proxy.authPack(t, "foo@example.com", nil /* roles */)

	// Get a totp code.
	totpCode, err := totp.GenerateCode(pack.otpSecret, env.clock.Now().Add(30*time.Second))
	require.NoError(t, err)

	endpoint := pack.clt.Endpoint("webapi", "users", "privilege", "token")
	re, err := pack.clt.PostJSON(context.Background(), endpoint, &privilegeTokenRequest{
		SecondFactorToken: totpCode,
	})
	require.NoError(t, err)

	var privilegeToken string
	err = json.Unmarshal(re.Bytes(), &privilegeToken)
	require.NoError(t, err)
	require.NotEmpty(t, privilegeToken)
}

func TestAddMFADevice(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newWebPack(t, 1)
	proxy := env.proxies[0]
	pack := proxy.authPack(t, "foo@example.com", nil /* roles */)

	// Enable second factor.
	ap, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
		Type:         constants.Local,
		SecondFactor: constants.SecondFactorOptional,
		U2F: &types.U2F{
			AppID:  "https://localhost",
			Facets: []string{"https://localhost"},
		},
	})
	require.NoError(t, err)
	err = env.server.Auth().SetAuthPreference(ctx, ap)
	require.NoError(t, err)

	// Get a totp code to re-auth.
	totpCode, err := totp.GenerateCode(pack.otpSecret, env.clock.Now().Add(30*time.Second))
	require.NoError(t, err)

	// Obtain a privilege token.
	endpoint := pack.clt.Endpoint("webapi", "users", "privilege", "token")
	re, err := pack.clt.PostJSON(ctx, endpoint, &privilegeTokenRequest{
		SecondFactorToken: totpCode,
	})
	require.NoError(t, err)
	var privilegeToken string
	require.NoError(t, json.Unmarshal(re.Bytes(), &privilegeToken))

	tests := []struct {
		name            string
		deviceName      string
		getTOTPCode     func() string
		getU2FResp      func() *u2f.RegisterChallengeResponse
		getWebauthnResp func() *wanlib.CredentialCreationResponse
	}{
		{
			name:       "new TOTP device",
			deviceName: "new-totp",
			getTOTPCode: func() string {
				// Create totp secrets.
				res, err := env.server.Auth().CreateRegisterChallenge(ctx, &apiProto.CreateRegisterChallengeRequest{
					TokenID:    privilegeToken,
					DeviceType: apiProto.DeviceType_DEVICE_TYPE_TOTP,
				})
				require.NoError(t, err)

				_, regRes, err := auth.NewTestDeviceFromChallenge(res, auth.WithTestDeviceClock(env.clock))
				require.NoError(t, err)

				return regRes.GetTOTP().Code
			},
		},
		{
			name:       "new U2F device",
			deviceName: "new-u2f",
			getU2FResp: func() *u2f.RegisterChallengeResponse {
				// Get u2f register challenge.
				res, err := env.server.Auth().CreateRegisterChallenge(ctx, &apiProto.CreateRegisterChallengeRequest{
					TokenID:    privilegeToken,
					DeviceType: apiProto.DeviceType_DEVICE_TYPE_U2F,
				})
				require.NoError(t, err)

				_, regRes, err := auth.NewTestDeviceFromChallenge(res)
				require.NoError(t, err)

				return &u2f.RegisterChallengeResponse{
					RegistrationData: regRes.GetU2F().RegistrationData,
					ClientData:       regRes.GetU2F().ClientData,
				}
			},
		},
		{
			name:       "new Webauthn device",
			deviceName: "new-webauthn",
			getWebauthnResp: func() *wanlib.CredentialCreationResponse {
				// Get webauthn register challenge.
				res, err := env.server.Auth().CreateRegisterChallenge(ctx, &apiProto.CreateRegisterChallengeRequest{
					TokenID:    privilegeToken,
					DeviceType: apiProto.DeviceType_DEVICE_TYPE_WEBAUTHN,
				})
				require.NoError(t, err)

				_, regRes, err := auth.NewTestDeviceFromChallenge(res)
				require.NoError(t, err)

				return wanlib.CredentialCreationResponseFromProto(regRes.GetWebauthn())
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var totpCode string
			var u2fRegResp *u2f.RegisterChallengeResponse
			var webauthnRegResp *wanlib.CredentialCreationResponse

			switch {
			case tc.getU2FResp != nil:
				u2fRegResp = tc.getU2FResp()
			case tc.getWebauthnResp != nil:
				webauthnRegResp = tc.getWebauthnResp()
			default:
				totpCode = tc.getTOTPCode()
			}

			// Add device.
			endpoint := pack.clt.Endpoint("webapi", "mfa", "devices")
			_, err := pack.clt.PostJSON(ctx, endpoint, addMFADeviceRequest{
				PrivilegeTokenID:         privilegeToken,
				DeviceName:               tc.deviceName,
				SecondFactorToken:        totpCode,
				U2FRegisterResponse:      u2fRegResp,
				WebauthnRegisterResponse: webauthnRegResp,
			})
			require.NoError(t, err)
		})
	}
}

func TestDeleteMFA(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newWebPack(t, 1)
	proxy := env.proxies[0]
	pack := proxy.authPack(t, "foo@example.com", nil /* roles */)

	//setting up client manually because we need sanitizer off
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	opts := []roundtrip.ClientParam{roundtrip.BearerAuth(pack.session.Token), roundtrip.CookieJar(jar), roundtrip.HTTPClient(client.NewInsecureWebClient())}
	rclt, err := roundtrip.NewClient(proxy.webURL.String(), teleport.WebAPIVersion, opts...)
	require.NoError(t, err)
	clt := client.WebClient{Client: rclt}
	jar.SetCookies(&proxy.webURL, pack.cookies)

	totpCode, err := totp.GenerateCode(pack.otpSecret, env.clock.Now().Add(30*time.Second))
	require.NoError(t, err)

	// Obtain a privilege token.
	endpoint := pack.clt.Endpoint("webapi", "users", "privilege", "token")
	re, err := pack.clt.PostJSON(ctx, endpoint, &privilegeTokenRequest{
		SecondFactorToken: totpCode,
	})
	require.NoError(t, err)

	var privilegeToken string
	require.NoError(t, json.Unmarshal(re.Bytes(), &privilegeToken))

	names := []string{"x", "??", "%123/", "///", "my/device", "?/%&*1"}
	for _, devName := range names {
		devName := devName
		t.Run(devName, func(t *testing.T) {
			t.Parallel()
			otpSecret := base32.StdEncoding.EncodeToString([]byte(devName))
			dev, err := services.NewTOTPDevice(devName, otpSecret, env.clock.Now())
			require.NoError(t, err)
			err = env.server.Auth().UpsertMFADevice(ctx, pack.user, dev)
			require.NoError(t, err)

			enc := url.PathEscape(devName)
			_, err = clt.Delete(ctx, pack.clt.Endpoint("webapi", "mfa", "token", privilegeToken, "devices", enc))
			require.NoError(t, err)
		})
	}
}

func TestGetMFADevicesWithAuth(t *testing.T) {
	t.Parallel()
	env := newWebPack(t, 1)
	proxy := env.proxies[0]
	pack := proxy.authPack(t, "foo@example.com", nil /* roles */)

	endpoint := pack.clt.Endpoint("webapi", "mfa", "devices")
	re, err := pack.clt.Get(context.Background(), endpoint, url.Values{})
	require.NoError(t, err)

	var devices []ui.MFADevice
	err = json.Unmarshal(re.Bytes(), &devices)
	require.NoError(t, err)
	require.Len(t, devices, 1)
}

func TestGetAndDeleteMFADevices_WithRecoveryApprovedToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newWebPack(t, 1)
	proxy := env.proxies[0]

	// Create a user with a TOTP device.
	username := "llama"
	proxy.createUser(ctx, t, username, "root", "password", "some-otp-secret", nil /* roles */)

	// Enable second factor.
	ap, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
		Type:         constants.Local,
		SecondFactor: constants.SecondFactorOptional,
		U2F: &types.U2F{
			AppID:  "https://" + env.server.ClusterName(),
			Facets: []string{"https://" + env.server.ClusterName()},
		},
	})
	require.NoError(t, err)
	err = env.server.Auth().SetAuthPreference(ctx, ap)
	require.NoError(t, err)

	// Acquire an approved token.
	approvedToken, err := types.NewUserToken("some-token-id")
	require.NoError(t, err)
	approvedToken.SetUser(username)
	approvedToken.SetSubKind(auth.UserTokenTypeRecoveryApproved)
	approvedToken.SetExpiry(env.clock.Now().Add(5 * time.Minute))
	_, err = env.server.Auth().Identity.CreateUserToken(ctx, approvedToken)
	require.NoError(t, err)

	// Call the getter endpoint.
	clt := proxy.newClient(t)
	getDevicesEndpoint := clt.Endpoint("webapi", "mfa", "token", approvedToken.GetName(), "devices")
	res, err := clt.Get(ctx, getDevicesEndpoint, url.Values{})
	require.NoError(t, err)

	var devices []ui.MFADevice
	err = json.Unmarshal(res.Bytes(), &devices)
	require.NoError(t, err)
	require.Len(t, devices, 1)

	// Call the delete endpoint.
	_, err = clt.Delete(ctx, clt.Endpoint("webapi", "mfa", "token", approvedToken.GetName(), "devices", devices[0].Name))
	require.NoError(t, err)

	// Check device has been deleted.
	res, err = clt.Get(ctx, getDevicesEndpoint, url.Values{})
	require.NoError(t, err)

	err = json.Unmarshal(res.Bytes(), &devices)
	require.NoError(t, err)
	require.Len(t, devices, 0)
}

func TestCreateAuthenticateChallenge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newWebPack(t, 1)
	proxy := env.proxies[0]

	// Create a user with a TOTP device, with second factor preference to OTP only.
	authPack := proxy.authPack(t, "llama@example.com", nil /* roles */)

	// Authenticated client for private endpoints.
	authnClt := authPack.clt

	// Unauthenticated client for public endpoints.
	publicClt := proxy.newClient(t)

	// Acquire a start token, for the request the requires it.
	startToken, err := types.NewUserToken("some-token-id")
	require.NoError(t, err)
	startToken.SetUser(authPack.user)
	startToken.SetSubKind(auth.UserTokenTypeRecoveryStart)
	startToken.SetExpiry(env.clock.Now().Add(5 * time.Minute))
	_, err = env.server.Auth().Identity.CreateUserToken(ctx, startToken)
	require.NoError(t, err)

	tests := []struct {
		name    string
		clt     *client.WebClient
		ep      []string
		reqBody client.MFAChallengeRequest
	}{
		{
			name: "/webapi/mfa/authenticatechallenge/password",
			clt:  authnClt,
			ep:   []string{"webapi", "mfa", "authenticatechallenge", "password"},
			reqBody: client.MFAChallengeRequest{
				Pass: authPack.password,
			},
		},
		{
			name: "/webapi/mfa/login/begin",
			clt:  publicClt,
			ep:   []string{"webapi", "mfa", "login", "begin"},
			reqBody: client.MFAChallengeRequest{
				User: authPack.user,
				Pass: authPack.password,
			},
		},
		{
			name: "/webapi/mfa/authenticatechallenge",
			clt:  authnClt,
			ep:   []string{"webapi", "mfa", "authenticatechallenge"},
		},
		{
			name: "/webapi/mfa/token/:token/authenticatechallenge",
			clt:  publicClt,
			ep:   []string{"webapi", "mfa", "token", startToken.GetName(), "authenticatechallenge"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			endpoint := tc.clt.Endpoint(tc.ep...)
			res, err := tc.clt.PostJSON(ctx, endpoint, tc.reqBody)
			require.NoError(t, err)

			var chal auth.MFAAuthenticateChallenge
			err = json.Unmarshal(res.Bytes(), &chal)
			require.NoError(t, err)
			require.True(t, chal.TOTPChallenge)
			require.Empty(t, chal.U2FChallenges)
			require.Empty(t, chal.WebauthnChallenge)
		})
	}
}

func TestCreateRegisterChallenge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newWebPack(t, 1)
	proxy := env.proxies[0]
	clt := proxy.newClient(t)

	// Enable second factor.
	ap, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
		Type:         constants.Local,
		SecondFactor: constants.SecondFactorOn,
		U2F: &types.U2F{
			AppID:  "https://" + env.server.ClusterName(),
			Facets: []string{"https://" + env.server.ClusterName()},
		},
	})
	require.NoError(t, err)
	require.NoError(t, env.server.Auth().SetAuthPreference(ctx, ap))

	// Acquire an accepted token.
	token, err := types.NewUserToken("some-token-id")
	require.NoError(t, err)
	token.SetUser("llama")
	token.SetSubKind(auth.UserTokenTypePrivilege)
	token.SetExpiry(env.clock.Now().Add(5 * time.Minute))
	_, err = env.server.Auth().Identity.CreateUserToken(ctx, token)
	require.NoError(t, err)

	tests := []struct {
		name       string
		deviceType string
	}{
		{
			name:       "u2f challenge",
			deviceType: "u2f",
		},
		{
			name:       "totp challenge",
			deviceType: "totp",
		},
		{
			name:       "webauthn challenge",
			deviceType: "webauthn",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			endpoint := clt.Endpoint("webapi", "mfa", "token", token.GetName(), "registerchallenge")
			res, err := clt.PostJSON(ctx, endpoint, &createRegisterChallengeRequest{
				DeviceType: tc.deviceType,
			})
			require.NoError(t, err)

			var chal client.MFARegisterChallenge
			require.NoError(t, json.Unmarshal(res.Bytes(), &chal))

			switch tc.deviceType {
			case "u2f":
				require.NotNil(t, chal.U2F)
			case "totp":
				require.NotNil(t, chal.TOTP.QRCode)
			case "webauthn":
				require.NotNil(t, chal.Webauthn)
			}
		})
	}
}

// TestCreateAppSession verifies that an existing session to the Web UI can
// be exchanged for an application specific session.
func TestCreateAppSession(t *testing.T) {
	t.Parallel()
	s := newWebSuite(t)
	pack := s.authPack(t, "foo@example.com")

	// Register an application called "panel".
	app, err := types.NewAppV3(types.Metadata{
		Name: "panel",
	}, types.AppSpecV3{
		URI:        "http://127.0.0.1:8080",
		PublicAddr: "panel.example.com",
	})
	require.NoError(t, err)
	server, err := types.NewAppServerV3FromApp(app, "host", uuid.New().String())
	require.NoError(t, err)
	_, err = s.server.Auth().UpsertApplicationServer(s.ctx, server)
	require.NoError(t, err)

	// Extract the session ID and bearer token for the current session.
	rawCookie := *pack.cookies[0]
	cookieBytes, err := hex.DecodeString(rawCookie.Value)
	require.NoError(t, err)
	var sessionCookie SessionCookie
	err = json.Unmarshal(cookieBytes, &sessionCookie)
	require.NoError(t, err)

	tests := []struct {
		name            string
		inCreateRequest *CreateAppSessionRequest
		outError        require.ErrorAssertionFunc
		outFQDN         string
		outUsername     string
	}{
		{
			name: "Valid request: all fields",
			inCreateRequest: &CreateAppSessionRequest{
				FQDNHint:    "panel.example.com",
				PublicAddr:  "panel.example.com",
				ClusterName: "localhost",
			},
			outError:    require.NoError,
			outFQDN:     "panel.example.com",
			outUsername: "foo@example.com",
		},
		{
			name: "Valid request: without FQDN",
			inCreateRequest: &CreateAppSessionRequest{
				PublicAddr:  "panel.example.com",
				ClusterName: "localhost",
			},
			outError:    require.NoError,
			outFQDN:     "panel.example.com",
			outUsername: "foo@example.com",
		},
		{
			name: "Valid request: only FQDN",
			inCreateRequest: &CreateAppSessionRequest{
				FQDNHint: "panel.example.com",
			},
			outError:    require.NoError,
			outFQDN:     "panel.example.com",
			outUsername: "foo@example.com",
		},
		{
			name: "Invalid request: only public address",
			inCreateRequest: &CreateAppSessionRequest{
				PublicAddr: "panel.example.com",
			},
			outError: require.Error,
		},
		{
			name: "Invalid request: only cluster name",
			inCreateRequest: &CreateAppSessionRequest{
				ClusterName: "localhost",
			},
			outError: require.Error,
		},
		{
			name: "Invalid application",
			inCreateRequest: &CreateAppSessionRequest{
				FQDNHint:    "panel.example.com",
				PublicAddr:  "invalid.example.com",
				ClusterName: "localhost",
			},
			outError: require.Error,
		},
		{
			name: "Invalid cluster name",
			inCreateRequest: &CreateAppSessionRequest{
				FQDNHint:    "panel.example.com",
				PublicAddr:  "panel.example.com",
				ClusterName: "example.com",
			},
			outError: require.Error,
		},
		{
			name: "Malicious request: all fields",
			inCreateRequest: &CreateAppSessionRequest{
				FQDNHint:    "panel.example.com@malicious.com",
				PublicAddr:  "panel.example.com",
				ClusterName: "localhost",
			},
			outError:    require.NoError,
			outFQDN:     "panel.example.com",
			outUsername: "foo@example.com",
		},
		{
			name: "Malicious request: only FQDN",
			inCreateRequest: &CreateAppSessionRequest{
				FQDNHint: "panel.example.com@malicious.com",
			},
			outError: require.Error,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Make a request to create an application session for "panel".
			endpoint := pack.clt.Endpoint("webapi", "sessions", "app")
			resp, err := pack.clt.PostJSON(s.ctx, endpoint, tt.inCreateRequest)
			tt.outError(t, err)
			if err != nil {
				return
			}

			// Unmarshal the response.
			var response *CreateAppSessionResponse
			require.NoError(t, json.Unmarshal(resp.Bytes(), &response))
			require.Equal(t, tt.outFQDN, response.FQDN)

			// Verify that the application session was created.
			sess, err := s.server.Auth().GetAppSession(s.ctx, types.GetAppSessionRequest{
				SessionID: response.CookieValue,
			})
			require.NoError(t, err)
			require.Equal(t, tt.outUsername, sess.GetUser())
			require.NotEmpty(t, response.CookieValue)
			require.Equal(t, response.CookieValue, sess.GetName())
			require.NotEmpty(t, response.SubjectCookieValue, "every session should create a secret token")
			require.Equal(t, response.SubjectCookieValue, sess.GetBearerToken())
		})
	}
}

func TestNewSessionResponseWithRenewSession(t *testing.T) {
	t.Parallel()
	env := newWebPack(t, 1)

	// Set a web idle timeout.
	duration := time.Duration(5) * time.Minute
	cfg := types.DefaultClusterNetworkingConfig()
	cfg.SetWebIdleTimeout(duration)
	require.NoError(t, env.server.Auth().SetClusterNetworkingConfig(context.Background(), cfg))

	proxy := env.proxies[0]
	pack := proxy.authPack(t, "foo", nil /* roles */)

	var ns *CreateSessionResponse
	resp := pack.renewSession(context.Background(), t)
	require.NoError(t, json.Unmarshal(resp.Bytes(), &ns))

	require.Equal(t, int(duration.Milliseconds()), ns.SessionInactiveTimeoutMS)
	require.Equal(t, roundtrip.AuthBearer, ns.TokenType)
	require.NotEmpty(t, ns.SessionExpires)
	require.NotEmpty(t, ns.Token)
	require.NotEmpty(t, ns.TokenExpiresIn)
}

// TestWebSessionsRenewDoesNotBreakExistingTerminalSession validates that the
// session renewed via one proxy does not force the terminals created by another
// proxy to disconnect
//
// See https://github.com/gravitational/teleport/issues/5265
func TestWebSessionsRenewDoesNotBreakExistingTerminalSession(t *testing.T) {
	env := newWebPack(t, 2)

	proxy1, proxy2 := env.proxies[0], env.proxies[1]
	// Connect to both proxies
	pack1 := proxy1.authPack(t, "foo", nil /* roles */)
	pack2 := proxy2.authPackFromPack(t, pack1)

	ws := proxy2.makeTerminal(t, pack2, session.NewID())

	// Advance the time before renewing the session.
	// This will allow the new session to have a more plausible
	// expiration
	const delta = 30 * time.Second
	env.clock.Advance(auth.BearerTokenTTL - delta)

	// Renew the session using the 1st proxy
	resp := pack1.renewSession(context.Background(), t)

	// Expire the old session and make sure it has been removed.
	// The bearer token is also removed after this point, so we have to
	// use the new session data for future connects
	env.clock.Advance(delta + 1*time.Second)
	pack2 = proxy2.authPackFromResponse(t, resp)

	// Verify that access via the 2nd proxy also works for the same session
	pack2.validateAPI(context.Background(), t)

	// Check whether the terminal session is still active
	validateTerminalStream(t, ws)
}

// TestWebSessionsRenewAllowsOldBearerTokenToLinger validates that the
// bearer token bound to the previous session is still active after the
// session renewal, if the renewal happens with a time margin.
//
// See https://github.com/gravitational/teleport/issues/5265
func TestWebSessionsRenewAllowsOldBearerTokenToLinger(t *testing.T) {
	// Login to implicitly create a new web session
	env := newWebPack(t, 1)

	proxy := env.proxies[0]
	pack := proxy.authPack(t, "foo", nil /* roles */)

	delta := 30 * time.Second
	// Advance the time before renewing the session.
	// This will allow the new session to have a more plausible
	// expiration
	env.clock.Advance(auth.BearerTokenTTL - delta)

	// make sure we can use client to make authenticated requests
	// before we issue this request, we will recover session id and bearer token
	//
	prevSessionCookie := *pack.cookies[0]
	prevBearerToken := pack.session.Token
	resp := pack.renewSession(context.Background(), t)

	newPack := proxy.authPackFromResponse(t, resp)

	// new session is functioning
	newPack.validateAPI(context.Background(), t)

	sessionCookie := *newPack.cookies[0]
	bearerToken := newPack.session.Token
	require.NotEmpty(t, bearerToken)
	require.NotEmpty(t, cmp.Diff(bearerToken, prevBearerToken))

	prevSessionID := decodeSessionCookie(t, prevSessionCookie.Value)
	activeSessionID := decodeSessionCookie(t, sessionCookie.Value)
	require.NotEmpty(t, cmp.Diff(prevSessionID, activeSessionID))

	// old session is still valid
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	oldClt := proxy.newClient(t, roundtrip.BearerAuth(prevBearerToken), roundtrip.CookieJar(jar))
	jar.SetCookies(&proxy.webURL, []*http.Cookie{&prevSessionCookie})
	_, err = oldClt.Get(context.Background(), pack.clt.Endpoint("webapi", "sites"), url.Values{})
	require.NoError(t, err)

	// now expire the old session and make sure it has been removed
	env.clock.Advance(delta)

	_, err = proxy.client.GetWebSession(context.Background(), types.GetWebSessionRequest{
		User:      "foo",
		SessionID: prevSessionID,
	})
	require.Regexp(t, "^key.*not found$", err.Error())

	// now delete session
	_, err = newPack.clt.Delete(
		context.Background(),
		pack.clt.Endpoint("webapi", "sessions"))
	require.NoError(t, err)

	// subsequent requests to use this session will fail
	_, err = newPack.clt.Get(context.Background(), pack.clt.Endpoint("webapi", "sites"), url.Values{})
	require.True(t, trace.IsAccessDenied(err))
}

// TestChangeUserAuthentication_recoveryCodesReturnedForCloud tests for following:
// - Recovery codes are not returned for usernames that are not emails
// - Recovery codes are returned for usernames that are valid emails
func TestChangeUserAuthentication_recoveryCodesReturnedForCloud(t *testing.T) {
	env := newWebPack(t, 1)
	ctx := context.Background()

	// Enable second factor.
	ap, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
		Type:         constants.Local,
		SecondFactor: constants.SecondFactorOTP,
	})
	require.NoError(t, err)
	err = env.server.Auth().SetAuthPreference(ctx, ap)
	require.NoError(t, err)

	// Enable cloud feature.
	modules.SetTestModules(t, &modules.TestModules{
		TestFeatures: modules.Features{
			Cloud: true,
		},
	})

	// Creaet a username that is not a valid email format for recovery.
	teleUser, err := types.NewUser("invalid-name-for-recovery")
	require.NoError(t, err)
	require.NoError(t, env.server.Auth().CreateUser(ctx, teleUser))

	// Create a reset password token and secrets.
	resetToken, err := env.server.Auth().CreateResetPasswordToken(ctx, auth.CreateUserTokenRequest{
		Name: "invalid-name-for-recovery",
	})
	require.NoError(t, err)
	res, err := env.server.Auth().CreateRegisterChallenge(ctx, &apiProto.CreateRegisterChallengeRequest{
		TokenID:    resetToken.GetName(),
		DeviceType: apiProto.DeviceType_DEVICE_TYPE_TOTP,
	})
	require.NoError(t, err)
	totpCode, err := totp.GenerateCode(res.GetTOTP().GetSecret(), env.clock.Now())
	require.NoError(t, err)

	// Test invalid username does not receive codes.
	clt := env.proxies[0].client
	re, err := clt.ChangeUserAuthentication(ctx, &apiProto.ChangeUserAuthenticationRequest{
		TokenID:     resetToken.GetName(),
		NewPassword: []byte("abc123"),
		NewMFARegisterResponse: &apiProto.MFARegisterResponse{Response: &apiProto.MFARegisterResponse_TOTP{
			TOTP: &apiProto.TOTPRegisterResponse{Code: totpCode},
		}},
	})
	require.NoError(t, err)
	require.Nil(t, re.Recovery)

	// Create a user that is valid for recovery.
	teleUser, err = types.NewUser("valid-username@example.com")
	require.NoError(t, err)
	require.NoError(t, env.server.Auth().CreateUser(ctx, teleUser))

	// Create a reset password token and secrets.
	resetToken, err = env.server.Auth().CreateResetPasswordToken(ctx, auth.CreateUserTokenRequest{
		Name: "valid-username@example.com",
	})
	require.NoError(t, err)
	res, err = env.server.Auth().CreateRegisterChallenge(ctx, &apiProto.CreateRegisterChallengeRequest{
		TokenID:    resetToken.GetName(),
		DeviceType: apiProto.DeviceType_DEVICE_TYPE_TOTP,
	})
	require.NoError(t, err)
	totpCode, err = totp.GenerateCode(res.GetTOTP().GetSecret(), env.clock.Now())
	require.NoError(t, err)

	// Test valid username (email) returns codes.
	re, err = clt.ChangeUserAuthentication(ctx, &apiProto.ChangeUserAuthenticationRequest{
		TokenID:     resetToken.GetName(),
		NewPassword: []byte("abc123"),
		NewMFARegisterResponse: &apiProto.MFARegisterResponse{Response: &apiProto.MFARegisterResponse_TOTP{
			TOTP: &apiProto.TOTPRegisterResponse{Code: totpCode},
		}},
	})
	require.NoError(t, err)
	require.Len(t, re.Recovery.Codes, 3)
	require.NotEmpty(t, re.Recovery.Created)
}

func TestDesktopActive(t *testing.T) {
	desktopName := "rickey-rock"
	env := newWebPack(t, 1)
	ctx := context.Background()

	role, err := types.NewRole("admin", types.RoleSpecV5{
		Allow: types.RoleConditions{
			WindowsDesktopLabels: types.Labels{"environment": []string{"dev"}},
		},
	})
	require.NoError(t, err)

	pack := env.proxies[0].authPack(t, "foo", []types.Role{role})

	check := func(match string) {
		resp, err := pack.clt.Get(ctx, pack.clt.Endpoint("webapi", "sites", env.server.ClusterName(), "desktops", desktopName, "active"), url.Values{})
		require.NoError(t, err)
		require.Contains(t, string(resp.Bytes()), match)
	}

	check("\"active\":false")
	desktop, err := types.NewWindowsDesktopV3(desktopName, map[string]string{"environment": "dev"}, types.WindowsDesktopSpecV3{
		Domain: "ad",
		Addr:   "foo",
		HostID: "bar",
	})
	require.NoError(t, err)
	err = env.server.Auth().CreateWindowsDesktop(ctx, desktop)
	require.NoError(t, err)
	tracker, err := types.NewSessionTracker(types.SessionTrackerSpecV1{
		SessionID:   "foo",
		Kind:        string(types.WindowsDesktopSessionKind),
		State:       types.SessionState_SessionStateRunning,
		DesktopName: desktopName,
	})
	require.NoError(t, err)
	_, err = env.server.Auth().CreateSessionTracker(ctx, tracker)
	require.NoError(t, err)
	check("\"active\":true")
}

func TestParseSSORequestParams(t *testing.T) {
	t.Parallel()

	token := "someMeaninglessTokenString"

	tests := []struct {
		name, url string
		wantErr   bool
		expected  *ssoRequestParams
	}{
		{
			name: "preserve redirect's query params (escaped)",
			url:  "https://localhost/login?connector_id=oidc&redirect_url=https:%2F%2Flocalhost:8080%2Fweb%2Fcluster%2Fim-a-cluster-name%2Fnodes%3Fsearch=tunnel&sort=hostname:asc",
			expected: &ssoRequestParams{
				clientRedirectURL: "https://localhost:8080/web/cluster/im-a-cluster-name/nodes?search=tunnel&sort=hostname:asc",
				connectorID:       "oidc",
				csrfToken:         token,
			},
		},
		{
			name: "preserve redirect's query params (unescaped)",
			url:  "https://localhost/login?connector_id=github&redirect_url=https://localhost:8080/web/cluster/im-a-cluster-name/nodes?search=tunnel&sort=hostname:asc",
			expected: &ssoRequestParams{
				clientRedirectURL: "https://localhost:8080/web/cluster/im-a-cluster-name/nodes?search=tunnel&sort=hostname:asc",
				connectorID:       "github",
				csrfToken:         token,
			},
		},
		{
			name: "preserve various encoded chars",
			url:  "https://localhost/login?connector_id=saml&redirect_url=https:%2F%2Flocalhost:8080%2Fweb%2Fcluster%2Fim-a-cluster-name%2Fapps%3Fquery=search(%2522watermelon%2522%252C%2520%2522this%2522)%2520%2526%2526%2520labels%255B%2522unique-id%2522%255D%2520%253D%253D%2520%2522hi%2522&sort=name:asc",
			expected: &ssoRequestParams{
				clientRedirectURL: "https://localhost:8080/web/cluster/im-a-cluster-name/apps?query=search(%22watermelon%22%2C%20%22this%22)%20%26%26%20labels%5B%22unique-id%22%5D%20%3D%3D%20%22hi%22&sort=name:asc",
				connectorID:       "saml",
				csrfToken:         token,
			},
		},
		{
			name:    "invalid redirect_url query param",
			url:     "https://localhost/login?redirect=https://localhost/nodes&connector_id=oidc",
			wantErr: true,
		},
		{
			name:    "invalid connector_id query param",
			url:     "https://localhost/login?redirect_url=https://localhost/nodes&connector=oidc",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("", tc.url, nil)
			require.NoError(t, err)
			addCSRFCookieToReq(req, token)

			params, err := parseSSORequestParams(req)

			switch {
			case tc.wantErr:
				require.Error(t, err)
			default:
				require.NoError(t, err)
				require.Equal(t, tc.expected, params)
			}
		})
	}
}

type authProviderMock struct {
	server types.ServerV2
}

func (mock authProviderMock) GetNodes(ctx context.Context, n string, opts ...services.MarshalOption) ([]types.Server, error) {
	return []types.Server{&mock.server}, nil
}

func (mock authProviderMock) GetSessionEvents(n string, s session.ID, c int, p bool) ([]events.EventFields, error) {
	return []events.EventFields{}, nil
}

func (mock authProviderMock) GetSessionTracker(ctx context.Context, sessionID string) (types.SessionTracker, error) {
	return nil, trace.NotFound("foo")
}

func (mock authProviderMock) IsMFARequired(ctx context.Context, req *authproto.IsMFARequiredRequest) (*authproto.IsMFARequiredResponse, error) {
	return nil, nil
}

func (mock authProviderMock) GenerateUserSingleUseCerts(ctx context.Context) (authproto.AuthService_GenerateUserSingleUseCertsClient, error) {
	return nil, nil
}

type terminalOpt func(t *TerminalRequest)

func withSessionID(sid session.ID) terminalOpt {
	return func(t *TerminalRequest) { t.SessionID = sid }
}

func withKeepaliveInterval(d time.Duration) terminalOpt {
	return func(t *TerminalRequest) { t.KeepAliveInterval = d }
}

func (s *WebSuite) makeTerminal(t *testing.T, pack *authPack, opts ...terminalOpt) (*websocket.Conn, error) {
	req := TerminalRequest{
		Server: s.srvID,
		Login:  pack.login,
		Term: session.TerminalParams{
			W: 100,
			H: 100,
		},
		SessionID: session.NewID(),
	}
	for _, opt := range opts {
		opt(&req)
	}

	u := url.URL{
		Host:   s.url().Host,
		Scheme: client.WSS,
		Path:   fmt.Sprintf("/v1/webapi/sites/%v/connect", currentSiteShortcut),
	}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("params", string(data))
	q.Set(roundtrip.AccessTokenQueryParam, pack.session.Token)
	u.RawQuery = q.Encode()

	dialer := websocket.Dialer{}
	dialer.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	header := http.Header{}
	header.Add("Origin", "http://localhost")
	for _, cookie := range pack.cookies {
		header.Add("Cookie", cookie.String())
	}

	ws, resp, err := dialer.Dial(u.String(), header)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	require.NoError(t, resp.Body.Close())
	return ws, nil
}

func waitForOutput(stream *terminalStream, substr string) error {
	timeoutCh := time.After(10 * time.Second)

	for {
		select {
		case <-timeoutCh:
			return trace.BadParameter("timeout waiting on terminal for output: %v", substr)
		default:
		}

		out := make([]byte, 100)
		_, err := stream.Read(out)
		if err != nil {
			return trace.Wrap(err)
		}
		if strings.Contains(removeSpace(string(out)), substr) {
			return nil
		}
	}
}

func (s *WebSuite) clientNoRedirects(opts ...roundtrip.ClientParam) *client.WebClient {
	hclient := client.NewInsecureWebClient()
	hclient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	opts = append(opts, roundtrip.HTTPClient(hclient))
	wc, err := client.NewWebClient(s.url().String(), opts...)
	if err != nil {
		panic(err)
	}
	return wc
}

func (s *WebSuite) client(opts ...roundtrip.ClientParam) *client.WebClient {
	opts = append(opts, roundtrip.HTTPClient(client.NewInsecureWebClient()))
	wc, err := client.NewWebClient(s.url().String(), opts...)
	if err != nil {
		panic(err)
	}
	return wc
}

func (s *WebSuite) login(clt *client.WebClient, cookieToken string, reqToken string, reqData interface{}) (*roundtrip.Response, error) {
	return httplib.ConvertResponse(clt.RoundTrip(func() (*http.Response, error) {
		data, err := json.Marshal(reqData)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequest("POST", clt.Endpoint("webapi", "sessions"), bytes.NewBuffer(data))
		if err != nil {
			return nil, err
		}
		addCSRFCookieToReq(req, cookieToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(csrf.HeaderName, reqToken)
		return clt.HTTPClient().Do(req)
	}))
}

func (s *WebSuite) url() *url.URL {
	u, err := url.Parse("https://" + s.webServer.Listener.Addr().String())
	if err != nil {
		panic(err)
	}
	return u
}

func addCSRFCookieToReq(req *http.Request, token string) {
	cookie := &http.Cookie{
		Name:  csrf.CookieName,
		Value: token,
	}

	req.AddCookie(cookie)
}

func removeSpace(in string) string {
	for _, c := range []string{"\n", "\r", "\t"} {
		in = strings.Replace(in, c, " ", -1)
	}
	return strings.TrimSpace(in)
}

func newTerminalHandler() TerminalHandler {
	return TerminalHandler{
		log:     logrus.WithFields(logrus.Fields{}),
		encoder: unicode.UTF8.NewEncoder(),
		decoder: unicode.UTF8.NewDecoder(),
		wsLock:  &sync.Mutex{},
	}
}

func decodeSessionCookie(t *testing.T, value string) (sessionID string) {
	sessionBytes, err := hex.DecodeString(value)
	require.NoError(t, err)
	var cookie struct {
		User      string `json:"user"`
		SessionID string `json:"sid"`
	}
	require.NoError(t, json.Unmarshal(sessionBytes, &cookie))
	return cookie.SessionID
}

func (r CreateSessionResponse) response() (*CreateSessionResponse, error) {
	return &CreateSessionResponse{TokenType: r.TokenType, Token: r.Token, TokenExpiresIn: r.TokenExpiresIn, SessionInactiveTimeoutMS: r.SessionInactiveTimeoutMS}, nil
}

func newWebPack(t *testing.T, numProxies int) *webPack {
	ctx := context.Background()
	clock := clockwork.NewFakeClockAt(time.Now())

	server, err := auth.NewTestServer(auth.TestServerConfig{
		Auth: auth.TestAuthServerConfig{
			ClusterName: "localhost",
			Dir:         t.TempDir(),
			Clock:       clock,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, server.Shutdown(ctx)) })

	// Register the auth server, since test auth server doesn't start its own
	// heartbeat.
	err = server.Auth().UpsertAuthServer(&types.ServerV2{
		Kind:    types.KindAuthServer,
		Version: types.V2,
		Metadata: types.Metadata{
			Namespace: apidefaults.Namespace,
			Name:      "auth",
		},
		Spec: types.ServerSpecV2{
			Addr:     server.TLS.Listener.Addr().String(),
			Hostname: "localhost",
			Version:  teleport.Version,
		},
	})
	require.NoError(t, err)

	priv, pub, err := server.Auth().GenerateKeyPair("")
	require.NoError(t, err)

	tlsPub, err := auth.PrivateKeyToPublicKeyTLS(priv)
	require.NoError(t, err)

	// start auth server
	certs, err := server.Auth().GenerateHostCerts(ctx,
		&apiProto.HostCertsRequest{
			HostID:       hostID,
			NodeName:     server.TLS.ClusterName(),
			Role:         types.RoleNode,
			PublicSSHKey: pub,
			PublicTLSKey: tlsPub,
		})
	require.NoError(t, err)

	signer, err := sshutils.NewSigner(priv, certs.SSH)
	require.NoError(t, err)
	hostSigners := []ssh.Signer{signer}

	const nodeID = "node"
	nodeClient, err := server.TLS.NewClient(auth.TestIdentity{
		I: auth.BuiltinRole{
			Role:     types.RoleNode,
			Username: nodeID,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, nodeClient.Close()) })

	nodeLockWatcher, err := services.NewLockWatcher(ctx, services.LockWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component: teleport.ComponentNode,
			Client:    nodeClient,
		},
	})
	require.NoError(t, err)
	t.Cleanup(nodeLockWatcher.Close)

	nodeSessionController, err := srv.NewSessionController(srv.SessionControllerConfig{
		Semaphores:   nodeClient,
		AccessPoint:  nodeClient,
		LockEnforcer: nodeLockWatcher,
		Emitter:      nodeClient,
		Component:    teleport.ComponentNode,
		ServerID:     nodeID,
	})
	require.NoError(t, err)

	// create SSH service:
	nodeDataDir := t.TempDir()
	node, err := regular.New(
		ctx,
		utils.NetAddr{AddrNetwork: "tcp", Addr: "127.0.0.1:0"},
		server.TLS.ClusterName(),
		hostSigners,
		nodeClient,
		nodeDataDir,
		"",
		utils.NetAddr{},
		nodeClient,
		regular.SetUUID(nodeID),
		regular.SetNamespace(apidefaults.Namespace),
		regular.SetShell("/bin/sh"),
		regular.SetSessionServer(nodeClient),
		regular.SetEmitter(nodeClient),
		regular.SetPAMConfig(&pam.Config{Enabled: false}),
		regular.SetBPF(&bpf.NOP{}),
		regular.SetRestrictedSessionManager(&restricted.NOP{}),
		regular.SetClock(clock),
		regular.SetLockWatcher(nodeLockWatcher),
		regular.SetSessionController(nodeSessionController),
	)
	require.NoError(t, err)

	require.NoError(t, node.Start())
	t.Cleanup(func() { require.NoError(t, node.Close()) })

	var proxies []*testProxy
	for p := 0; p < numProxies; p++ {
		proxyID := fmt.Sprintf("proxy%v", p)
		proxies = append(proxies, createProxy(ctx, t, proxyID, node, server.TLS, hostSigners, clock))
	}

	// Wait for proxies to fully register before starting the test.
	for start := time.Now(); ; {
		proxies, err := proxies[0].client.GetProxies()
		require.NoError(t, err)
		if len(proxies) == numProxies {
			break
		}
		if time.Since(start) > 5*time.Second {
			t.Fatalf("Proxies didn't register within 5s after startup; registered: %d, want: %d", len(proxies), numProxies)
		}
	}

	return &webPack{
		proxies: proxies,
		server:  server,
		node:    node,
		clock:   clock,
	}
}

func createProxy(ctx context.Context, t *testing.T, proxyID string, node *regular.Server, authServer *auth.TestTLSServer,
	hostSigners []ssh.Signer, clock clockwork.FakeClock,
) *testProxy {
	// create reverse tunnel service:
	client, err := authServer.NewClient(auth.TestIdentity{
		I: auth.BuiltinRole{
			Role:     types.RoleProxy,
			Username: proxyID,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	revTunListener, err := net.Listen("tcp", fmt.Sprintf("%v:0", authServer.ClusterName()))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, revTunListener.Close()) })

	proxyLockWatcher, err := services.NewLockWatcher(ctx, services.LockWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component: teleport.ComponentProxy,
			Client:    client,
		},
	})
	require.NoError(t, err)
	t.Cleanup(proxyLockWatcher.Close)

	proxyCAWatcher, err := services.NewCertAuthorityWatcher(ctx, services.CertAuthorityWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component: teleport.ComponentProxy,
			Client:    client,
		},
		Types: []types.CertAuthType{types.HostCA, types.UserCA},
	})
	require.NoError(t, err)
	t.Cleanup(proxyLockWatcher.Close)

	proxyNodeWatcher, err := services.NewNodeWatcher(ctx, services.NodeWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component: teleport.ComponentProxy,
			Client:    client,
		},
	})
	require.NoError(t, err)
	t.Cleanup(proxyNodeWatcher.Close)

	revTunServer, err := reversetunnel.NewServer(reversetunnel.Config{
		ID:                    node.ID(),
		Listener:              revTunListener,
		ClientTLS:             client.TLSConfig(),
		ClusterName:           authServer.ClusterName(),
		HostSigners:           hostSigners,
		LocalAuthClient:       client,
		LocalAccessPoint:      client,
		LocalAuthAddresses:    []string{authServer.Listener.Addr().String()},
		Emitter:               client,
		NewCachingAccessPoint: noCache,
		DataDir:               t.TempDir(),
		LockWatcher:           proxyLockWatcher,
		NodeWatcher:           proxyNodeWatcher,
		CertAuthorityWatcher:  proxyCAWatcher,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, revTunServer.Close()) })

	router, err := proxy.NewRouter(proxy.RouterConfig{
		ClusterName:         authServer.ClusterName(),
		Log:                 utils.NewLoggerForTests().WithField(trace.Component, "test"),
		RemoteClusterGetter: client,
		SiteGetter:          revTunServer,
		TracerProvider:      tracing.NoopProvider(),
	})
	require.NoError(t, err)

	sessionController, err := srv.NewSessionController(srv.SessionControllerConfig{
		Semaphores:   client,
		AccessPoint:  client,
		LockEnforcer: proxyLockWatcher,
		Emitter:      client,
		Component:    teleport.ComponentProxy,
		ServerID:     proxyID,
	})
	require.NoError(t, err)

	proxyServer, err := regular.New(
		ctx,
		utils.NetAddr{AddrNetwork: "tcp", Addr: "127.0.0.1:0"},
		authServer.ClusterName(),
		hostSigners,
		client,
		t.TempDir(),
		"",
		utils.NetAddr{},
		client,
		regular.SetUUID(proxyID),
		regular.SetProxyMode(revTunServer, client, router),
		regular.SetSessionServer(client),
		regular.SetEmitter(client),
		regular.SetNamespace(apidefaults.Namespace),
		regular.SetBPF(&bpf.NOP{}),
		regular.SetRestrictedSessionManager(&restricted.NOP{}),
		regular.SetClock(clock),
		regular.SetLockWatcher(proxyLockWatcher),
		regular.SetNodeWatcher(proxyNodeWatcher),
		regular.SetSessionController(sessionController),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, proxyServer.Close()) })

	fs, err := NewDebugFileSystem("../../webassets/teleport")
	require.NoError(t, err)
	handler, err := NewHandler(Config{
		Proxy:            revTunServer,
		AuthServers:      utils.FromAddr(authServer.Addr()),
		DomainName:       authServer.ClusterName(),
		ProxyClient:      client,
		ProxyPublicAddrs: utils.MustParseAddrList("proxy-1.example.com", "proxy-2.example.com"),
		CipherSuites:     utils.DefaultCipherSuites(),
		AccessPoint:      client,
		Context:          ctx,
		HostUUID:         proxyID,
		Emitter:          client,
		StaticFS:         fs,
		ProxySettings:    &mockProxySettings{},
		SessionControl:   sessionController,
		Router:           router,
	}, SetSessionStreamPollPeriod(200*time.Millisecond), SetClock(clock))
	require.NoError(t, err)

	webServer := httptest.NewTLSServer(handler)
	t.Cleanup(webServer.Close)
	require.NoError(t, proxyServer.Start())

	proxyAddr := utils.MustParseAddr(proxyServer.Addr())
	addr := utils.MustParseAddr(webServer.Listener.Addr().String())
	handler.handler.cfg.ProxyWebAddr = *addr
	handler.handler.cfg.ProxySSHAddr = *proxyAddr
	_, sshPort, err := net.SplitHostPort(proxyAddr.String())
	require.NoError(t, err)
	handler.handler.sshPort = sshPort

	url, err := url.Parse("https://" + webServer.Listener.Addr().String())
	require.NoError(t, err)

	return &testProxy{
		clock:   clock,
		auth:    authServer,
		client:  client,
		revTun:  revTunServer,
		node:    node,
		proxy:   proxyServer,
		web:     webServer,
		handler: handler,
		webURL:  *url,
	}
}

// webPack represents the state of a single web test.
// It replicates most of the WebSuite and serves to gradually
// transition the test suite to use the testing package
// directly.
type webPack struct {
	proxies []*testProxy
	server  *auth.TestServer
	node    *regular.Server
	clock   clockwork.FakeClock
}

type testProxy struct {
	clock   clockwork.FakeClock
	client  *auth.Client
	auth    *auth.TestTLSServer
	revTun  reversetunnel.Server
	node    *regular.Server
	proxy   *regular.Server
	handler *APIHandler
	web     *httptest.Server
	webURL  url.URL
}

// authPack returns new authenticated package consisting of created valid
// user, otp token, created web session and authenticated client.
func (r *testProxy) authPack(t *testing.T, teleportUser string, roles []types.Role) *authPack {
	ctx := context.Background()
	const (
		pass      = "abc123"
		rawSecret = "def456"
	)

	u, err := user.Current()
	require.NoError(t, err)
	loginUser := u.Username

	otpSecret := base32.StdEncoding.EncodeToString([]byte(rawSecret))

	ap, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
		Type:         constants.Local,
		SecondFactor: constants.SecondFactorOTP,
	})
	require.NoError(t, err)

	err = r.auth.Auth().SetAuthPreference(ctx, ap)
	require.NoError(t, err)

	r.createUser(context.Background(), t, teleportUser, loginUser, pass, otpSecret, roles)

	// create a valid otp token
	validToken, err := totp.GenerateCode(otpSecret, r.clock.Now())
	require.NoError(t, err)

	clt := r.newClient(t)
	req := CreateSessionReq{
		User:              teleportUser,
		Pass:              pass,
		SecondFactorToken: validToken,
	}

	csrfToken := "2ebcb768d0090ea4368e42880c970b61865c326172a4a2343b645cf5d7f20992"
	resp := login(t, clt, csrfToken, csrfToken, req)

	var rawSession *CreateSessionResponse
	require.NoError(t, json.Unmarshal(resp.Bytes(), &rawSession))

	session, err := rawSession.response()
	require.NoError(t, err)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	clt = r.newClient(t, roundtrip.BearerAuth(session.Token), roundtrip.CookieJar(jar))
	jar.SetCookies(&r.webURL, resp.Cookies())

	return &authPack{
		otpSecret: otpSecret,
		user:      teleportUser,
		login:     loginUser,
		session:   session,
		clt:       clt,
		cookies:   resp.Cookies(),
		password:  pass,
	}
}

func (r *testProxy) authPackFromPack(t *testing.T, pack *authPack) *authPack {
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	clt := r.newClient(t, roundtrip.BearerAuth(pack.session.Token), roundtrip.CookieJar(jar))
	jar.SetCookies(&r.webURL, pack.cookies)

	result := *pack
	result.clt = clt
	return &result
}

func (r *testProxy) authPackFromResponse(t *testing.T, httpResp *roundtrip.Response) *authPack {
	var resp *CreateSessionResponse
	require.NoError(t, json.Unmarshal(httpResp.Bytes(), &resp))

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	clt := r.newClient(t, roundtrip.BearerAuth(resp.Token), roundtrip.CookieJar(jar))
	jar.SetCookies(&r.webURL, httpResp.Cookies())

	session, err := resp.response()
	require.NoError(t, err)
	if session.TokenExpiresIn < 0 {
		t.Errorf("Expected expiry time to be in the future but got %v", session.TokenExpiresIn)
	}
	return &authPack{
		session: session,
		clt:     clt,
		cookies: httpResp.Cookies(),
	}
}

func defaultRoleForNewUser(teleUser types.User, login string) types.Role {
	role := services.RoleForUser(teleUser)
	role.SetLogins(types.Allow, []string{login})
	role.SetWindowsDesktopLabels(types.Allow, types.Labels{types.Wildcard: {types.Wildcard}})
	options := role.GetOptions()
	options.ForwardAgent = types.NewBool(true)
	role.SetOptions(options)
	return role
}

func (r *testProxy) createUser(ctx context.Context, t *testing.T, user, login, pass, otpSecret string, roles []types.Role) {
	teleUser, err := types.NewUser(user)
	require.NoError(t, err)

	if len(roles) == 0 {
		roles = []types.Role{defaultRoleForNewUser(teleUser, login)}
	}

	for _, role := range roles {
		err = r.auth.Auth().UpsertRole(ctx, role)
		require.NoError(t, err)

		teleUser.AddRole(role.GetName())
	}

	teleUser.SetCreatedBy(types.CreatedBy{
		User: types.UserRef{Name: "some-auth-user"},
	})

	err = r.auth.Auth().CreateUser(ctx, teleUser)
	require.NoError(t, err)

	err = r.auth.Auth().UpsertPassword(user, []byte(pass))
	require.NoError(t, err)

	if otpSecret != "" {
		dev, err := services.NewTOTPDevice("otp", otpSecret, r.clock.Now())
		require.NoError(t, err)
		err = r.auth.Auth().UpsertMFADevice(ctx, user, dev)
		require.NoError(t, err)
	}
}

func (r *testProxy) newClient(t *testing.T, opts ...roundtrip.ClientParam) *client.WebClient {
	opts = append(opts, roundtrip.HTTPClient(client.NewInsecureWebClient()))
	clt, err := client.NewWebClient(r.webURL.String(), opts...)
	require.NoError(t, err)
	return clt
}

func (r *testProxy) makeTerminal(t *testing.T, pack *authPack, sessionID session.ID) *websocket.Conn {
	u := url.URL{
		Host:   r.webURL.Host,
		Scheme: client.WSS,
		Path:   fmt.Sprintf("/v1/webapi/sites/%v/connect", currentSiteShortcut),
	}
	data, err := json.Marshal(TerminalRequest{
		Server: r.node.ID(),
		Login:  pack.login,
		Term: session.TerminalParams{
			W: 100,
			H: 100,
		},
		SessionID: sessionID,
	})
	require.NoError(t, err)

	q := u.Query()
	q.Set("params", string(data))
	q.Set(roundtrip.AccessTokenQueryParam, pack.session.Token)
	u.RawQuery = q.Encode()

	dialer := websocket.Dialer{}
	dialer.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	header := http.Header{}
	header.Add("Origin", "http://localhost")
	for _, cookie := range pack.cookies {
		header.Add("Cookie", cookie.String())
	}

	ws, resp, err := dialer.Dial(u.String(), header)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, ws.Close())
		require.NoError(t, resp.Body.Close())
	})
	return ws
}

func (r *testProxy) makeDesktopSession(t *testing.T, pack *authPack, sessionID session.ID, addr net.Addr) *websocket.Conn {
	u := url.URL{
		Host:   r.webURL.Host,
		Scheme: client.WSS,
		Path:   fmt.Sprintf("/webapi/sites/%s/desktops/%s/connect", currentSiteShortcut, "desktop1"),
	}

	q := u.Query()
	q.Set("username", "marek")
	q.Set("width", "100")
	q.Set("height", "100")
	q.Set(roundtrip.AccessTokenQueryParam, pack.session.Token)
	u.RawQuery = q.Encode()

	dialer := websocket.Dialer{}
	dialer.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	header := http.Header{}
	for _, cookie := range pack.cookies {
		header.Add("Cookie", cookie.String())
	}

	ws, resp, err := dialer.Dial(u.String(), header)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, ws.Close())
		require.NoError(t, resp.Body.Close())
	})
	return ws
}

func login(t *testing.T, clt *client.WebClient, cookieToken, reqToken string, reqData interface{}) *roundtrip.Response {
	resp, err := httplib.ConvertResponse(clt.RoundTrip(func() (*http.Response, error) {
		data, err := json.Marshal(reqData)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequest("POST", clt.Endpoint("webapi", "sessions"), bytes.NewBuffer(data))
		if err != nil {
			return nil, err
		}
		addCSRFCookieToReq(req, cookieToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(csrf.HeaderName, reqToken)
		return clt.HTTPClient().Do(req)
	}))
	require.NoError(t, err)
	return resp
}

func validateTerminalStream(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	termHandler := newTerminalHandler()
	stream := termHandler.asTerminalStream(conn)

	// here we intentionally run a command where the output we're looking
	// for is not present in the command itself
	_, err := io.WriteString(stream, "echo txlxport | sed 's/x/e/g'\r\n")
	require.NoError(t, err)
	require.NoError(t, waitForOutput(stream, "teleport"))
}

type mockProxySettings struct {
}

func (mock *mockProxySettings) GetProxySettings(ctx context.Context) (*webclient.ProxySettings, error) {
	return &webclient.ProxySettings{}, nil
}

// TestUserContextWithAccessRequest checks that the userContext includes the ID of the
// access request after it has been consumed and the web session has been renewed.
func TestUserContextWithAccessRequest(t *testing.T) {
	t.Parallel()
	env := newWebPack(t, 1)
	proxy := env.proxies[0]
	ctx := context.Background()

	// Set user and role names.
	username := "user"
	baseRoleName := "role"
	requestableRolename := "requestable-role"

	// Create user's base role with the ability to request the requestable role.
	baseRole, err := types.NewRole(baseRoleName, types.RoleSpecV5{
		Allow: types.RoleConditions{
			Request: &types.AccessRequestConditions{
				Roles: []string{requestableRolename},
			},
		},
	})
	require.NoError(t, err)

	// Create user with the base role.
	pack := proxy.authPack(t, username, []types.Role{baseRole})

	// Create the requestable role.
	requestableRole, err := types.NewRole(requestableRolename, types.RoleSpecV5{})
	require.NoError(t, err)
	err = env.server.Auth().UpsertRole(ctx, requestableRole)
	require.NoError(t, err)

	// Create and approve an access request for the requestable role.
	accessReq, err := services.NewAccessRequest(username, requestableRolename)
	require.NoError(t, err)
	accessReq.SetState(types.RequestState_APPROVED)
	err = env.server.Auth().CreateAccessRequest(ctx, accessReq)
	require.NoError(t, err)

	// Get the ID of the created and approved access request.
	accessRequestID := accessReq.GetMetadata().Name

	// Make a request to renew the session with the ID of the access request.
	_, err = pack.clt.PostJSON(ctx, pack.clt.Endpoint("webapi", "sessions", "renew"), renewSessionRequest{
		AccessRequestID: accessRequestID,
	})
	require.NoError(t, err)

	// Make a request to fetch the userContext.
	endpoint := pack.clt.Endpoint("webapi", "sites", env.server.ClusterName(), "context")
	response, err := pack.clt.Get(context.Background(), endpoint, url.Values{})
	require.NoError(t, err)

	// Process the JSON response of the request.
	var userContext ui.UserContext
	err = json.Unmarshal(response.Bytes(), &userContext)
	require.NoError(t, err)

	// Verify that the userContext returned contains the correct Access Request ID.
	require.Equal(t, accessRequestID, userContext.ConsumedAccessRequestID)
}

func TestLogout(t *testing.T) {
	ctx := context.Background()
	t.Parallel()
	env := newWebPack(t, 2)

	// create a logged in user for proxy 1
	pack := env.proxies[0].authPack(t, "llama", nil /* roles */)

	// ensure the client is authenticated
	re, err := pack.clt.Get(ctx, pack.clt.Endpoint("webapi", "sites"), url.Values{})
	require.NoError(t, err)
	var clusters []ui.Cluster
	require.NoError(t, json.Unmarshal(re.Bytes(), &clusters))
	require.Len(t, clusters, 1)

	// create a client for proxy 2 with the token and cookies from proxy 1
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	jar.SetCookies(&env.proxies[1].webURL, pack.cookies)
	clt2 := env.proxies[1].newClient(t, roundtrip.BearerAuth(pack.session.Token), roundtrip.CookieJar(jar))

	// ensure the second client is authenticated
	re, err = clt2.Get(ctx, clt2.Endpoint("webapi", "sites"), url.Values{})
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(re.Bytes(), &clusters))
	require.Len(t, clusters, 1)

	// logout from proxy 1
	_, err = pack.clt.Delete(ctx, pack.clt.Endpoint("webapi", "sessions"))
	require.NoError(t, err)

	// ensure proxy 1 invalidated the session
	_, err = pack.clt.Get(ctx, pack.clt.Endpoint("webapi", "sites"), url.Values{})
	require.Error(t, err)
	require.ErrorIs(t, err, trace.AccessDenied("missing session cookie"))

	// should still be authenticated to proxy 2 until the expiration loop kicks in
	re, err = clt2.Get(ctx, clt2.Endpoint("webapi", "sites"), url.Values{})
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(re.Bytes(), &clusters))
	require.Len(t, clusters, 1)

	// advance the clock to fire the expiration ticker
	env.clock.Advance(time.Second)

	// wait for the expiration loop to purge the session
	require.Eventually(t, func() bool {
		return env.proxies[1].handler.handler.auth.ActiveSessions() == 0
	}, 5*time.Second, 100*time.Millisecond)

	// ensure proxy 2 invalidated the session
	_, err = clt2.Get(ctx, clt2.Endpoint("webapi", "sites"), url.Values{})
	require.True(t, trace.IsAccessDenied(err))
	require.ErrorIs(t, err, trace.AccessDenied("need auth"))
}
