/*
Copyright 2020-2021 Gravitational, Inc.

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

// Package client holds the implementation of the Teleport gRPC api client
package client

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/events"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/gravitational/trace"
	"github.com/gravitational/trace/trail"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	ggzip "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"
)

func init() {
	// gzip is used for gRPC auditStream compression. SetLevel changes the
	// compression level, must be called in initialization, and is not thread safe.
	if err := ggzip.SetLevel(gzip.BestSpeed); err != nil {
		panic(err)
	}
}

// Client is a gRPC Client that connects to a teleport server through TLS.
type Client struct {
	// c contains configuration values for the client.
	c Config
	// tlsConfig is the *tls.Config for a successfully connected client.
	tlsConfig *tls.Config
	// sshConfig is the *ssh.ClientConfig for a successfully connected proxy client.
	sshConfig *ssh.ClientConfig
	// dialer is the ContextDialer for a successfully connected client.
	dialer ContextDialer
	// conn is a grpc connection to the auth server.
	conn *grpc.ClientConn
	// grpc is the gRPC client specification for the auth server.
	grpc proto.AuthServiceClient
	// closedFlag is set to indicate that the connnection is closed.
	closedFlag int32
}

// New creates a new API client with a connection to a Teleport server.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	c := &Client{c: cfg}
	if err := c.connect(ctx); err != nil {
		return nil, trace.Wrap(err)
	}

	return c, nil
}

// connect connects the client to the server, using the Credentials and
// Dialer/Addresses provided in the client's config. Multiple goroutines are started
// to attempt dialing the server with different combinations of dialers + creds, and
// the first client to successfully connect is used to populate the client's connection
// attributes. If none successfully connect, an aggregated error is returned.
func (c *Client) connect(ctx context.Context) error {
	var wg sync.WaitGroup
	cltChan := make(chan Client)
	errChan := make(chan error)

	// syncConnect is used to concurrently test several connections, and apply
	// the first successful connection to the client's connection attributes.
	syncConnect := func(ctx context.Context, clt Client, addr string) {
		wg.Add(1)
		go func() {
			defer wg.Done()

			if err := clt.setClientConn(ctx, addr); err != nil {
				errChan <- trace.Wrap(err)
				return
			}

			// If cltChan is empty, send clt. If full, close clt.
			select {
			case cltChan <- clt:
			default:
				clt.Close()
			}
		}()
	}

	wg.Add(1)
	go func(clt Client) {
		defer wg.Done()

		// Connect with provided credentials.
		for _, creds := range clt.c.Credentials {
			var err error
			if clt.tlsConfig, err = creds.TLSConfig(); err != nil {
				errChan <- trace.Wrap(err)
				continue
			}

			if clt.sshConfig, err = creds.SSHClientConfig(); err != nil && !trace.IsNotImplemented(err) {
				errChan <- trace.Wrap(err)
				continue
			}

			// Connect with dialer provided in config.
			if clt.dialer = clt.c.Dialer; clt.dialer != nil {
				syncConnect(ctx, clt, constants.APIDomain)
				continue
			}

			// Connect with dialer provided in creds.
			if clt.dialer, err = creds.Dialer(); err == nil {
				syncConnect(ctx, clt, constants.APIDomain)
				continue
			}

			for _, addr := range clt.c.Addrs {
				// Connect to auth.
				clt.dialer = NewDialer(clt.c.KeepAlivePeriod, clt.c.DialTimeout)
				syncConnect(ctx, clt, addr)

				// Connect to proxy.
				if clt.sshConfig != nil {
					clt.dialer = NewTunnelDialer(*clt.sshConfig, clt.c.KeepAlivePeriod, clt.c.DialTimeout)
					wg.Add(1)
					go func(clt Client, addr string) {
						defer wg.Done()
						// Try connecting to web proxy to retrieve tunnel address.
						if tunAddr, err := findTunnelAddr(addr); err == nil {
							addr = tunAddr
						}
						syncConnect(ctx, clt, addr)
					}(clt, addr)
				}
			}
		}
	}(*c)

	// Start goroutine to wait for wait group.
	go func() {
		wg.Wait()
		close(errChan)
	}()

	var errs error
	for {
		select {
		case *c = <-cltChan:
			// clt successfullly connected and copied to c.
			return nil
		case err, ok := <-errChan:
			if !ok {
				// errChan is closed, return errors.
				if errs == nil {
					return trace.Errorf("all auth methods failed")
				}
				return trace.Wrap(errs, "all auth methods failed")
			}
			errs = trace.Errorf("%v,\n\t%v", errs, err)
		}
	}
}

// findTunnelAddr retrieves the server's public tunnel address from the web proxy.
func findTunnelAddr(webAddr string) (string, error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://" + webAddr + "/webapi/find")
	if err != nil {
		return "", trace.Wrap(err)
	}

	defer resp.Body.Close()
	findResponse := &struct {
		Proxy struct {
			SSH struct {
				TunnelPublicAddr string `json:"ssh_tunnel_public_addr,omitempty"`
			} `json:"ssh"`
		} `json:"proxy"`
	}{}
	if err := json.NewDecoder(resp.Body).Decode(findResponse); err != nil {
		return "", trace.Wrap(err)
	}

	return findResponse.Proxy.SSH.TunnelPublicAddr, nil
}

// setClientConn sets the client's AuthServiceClient with an open connection to the server.
func (c *Client) setClientConn(ctx context.Context, addr string) error {
	conn, err := c.getClientConn(ctx, addr)
	if err != nil {
		return trace.Wrap(err)
	}

	// TODO (Joerger): Add version compatibility check.

	c.conn = conn
	c.grpc = proto.NewAuthServiceClient(conn)
	return nil
}

// getClientConn opens up a connection between server and client using the client's dialer and tlsConfig.
// To dial the connection in the background, c.WithoutDialBlock can be set to true.
func (c *Client) getClientConn(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	dialOptions := []grpc.DialOption{
		grpc.WithContextDialer(c.grpcDialer(c.dialer)),
		grpc.WithTransportCredentials(credentials.NewTLS(c.tlsConfig)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                c.c.KeepAlivePeriod,
			Timeout:             c.c.KeepAlivePeriod * time.Duration(c.c.KeepAliveCount),
			PermitWithoutStream: true,
		}),
	}

	if !c.c.WithoutDialBlock {
		dialOptions = append(dialOptions, grpc.WithBlock())
	}

	dialContext, cancel := context.WithTimeout(context.Background(), c.c.DialTimeout)
	defer cancel()

	var err error
	conn, err := grpc.DialContext(dialContext, addr, dialOptions...)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return conn, nil
}

// grpcDialer wraps the given ContextDialer with a grpcDialer, which
// can be used to create a DialOption with grpc.WithContextDialer.
func (c *Client) grpcDialer(dialer ContextDialer) func(ctx context.Context, addr string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		if c.isClosed() {
			return nil, trace.ConnectionProblem(nil, "client is closed")
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, trace.ConnectionProblem(err, err.Error())
		}
		return conn, nil
	}
}

// Config contains configuration of the client
type Config struct {
	// Addrs is a list of teleport auth/proxy server addresses to dial.
	Addrs []string
	// Dialer is a custom dialer used to dial a server. If set, Dialer
	// takes precedence over all other connection options.
	Dialer ContextDialer
	// DialTimeout defines how long to attempt dialing before timing out.
	DialTimeout time.Duration
	// KeepAlivePeriod defines period between keep alives.
	KeepAlivePeriod time.Duration
	// KeepAliveCount specifies the amount of missed keep alives
	// to wait for before declaring the connection as broken.
	KeepAliveCount int
	// Credentials are a list of credentials to use when attempting
	// to form a connection from client to server.
	Credentials []Credentials
	// WithoutDialBlock makes the client establish a connection in the
	// background rather than blocking. Not recommended for external api
	// usage, set DialTimeout to reduce dial wait time instead.
	WithoutDialBlock bool
}

// CheckAndSetDefaults checks and sets default config values.
func (c *Config) CheckAndSetDefaults() error {
	if len(c.Credentials) == 0 {
		return trace.BadParameter("missing connection credentials")
	}
	if c.KeepAlivePeriod == 0 {
		c.KeepAlivePeriod = defaults.ServerKeepAliveTTL
	}
	if c.KeepAliveCount == 0 {
		c.KeepAliveCount = defaults.KeepAliveCountMax
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = defaults.DefaultDialTimeout
	}
	return nil
}

// GetHTTPDialer returns the configured dialer,
// or builds a dialer from configured addresses.
func (c *Config) GetHTTPDialer() (ContextDialer, error) {
	var err error
	if c.Dialer != nil {
		return c.Dialer, nil
	}
	c.Dialer, err = NewAddrsDialer(c.Addrs, c.KeepAlivePeriod, c.DialTimeout)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return c.Dialer, nil
}

// Config returns the tls.Config the client connected with.
func (c *Client) Config() *tls.Config {
	return c.tlsConfig
}

// Dialer returns the ContextDialer the client connected with.
func (c *Client) Dialer() ContextDialer {
	return c.dialer
}

// GetConnection returns GRPC connection.
func (c *Client) GetConnection() *grpc.ClientConn {
	return c.conn
}

// Close closes the Client connection to the auth server.
func (c *Client) Close() error {
	if c.setClosed() && c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return trace.Wrap(err)
	}
	return nil
}

// isClosed returns whether the client is marked as closed.
func (c *Client) isClosed() bool {
	return atomic.LoadInt32(&c.closedFlag) == 1
}

// setClosed marks the client as closed and returns true if it wasn't already closed.
func (c *Client) setClosed() bool {
	return atomic.CompareAndSwapInt32(&c.closedFlag, 0, 1)
}

// Ping gets basic info about the auth server.
func (c *Client) Ping(ctx context.Context) (proto.PingResponse, error) {
	rsp, err := c.grpc.Ping(ctx, &proto.PingRequest{})
	if err != nil {
		return proto.PingResponse{}, trail.FromGRPC(err)
	}
	return *rsp, nil
}

// UpsertNode is used by SSH servers to report their presence
// to the auth servers in form of heartbeat expiring after ttl period.
func (c *Client) UpsertNode(s types.Server) (*types.KeepAlive, error) {
	if s.GetNamespace() == "" {
		return nil, trace.BadParameter("missing node namespace")
	}
	protoServer, ok := s.(*types.ServerV2)
	if !ok {
		return nil, trace.BadParameter("unsupported client")
	}
	keepAlive, err := c.grpc.UpsertNode(context.TODO(), protoServer)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return keepAlive, nil
}

// UpdateRemoteCluster updates remote cluster from the specified value.
func (c *Client) UpdateRemoteCluster(ctx context.Context, rc types.RemoteCluster) error {
	rcV3, ok := rc.(*types.RemoteClusterV3)
	if !ok {
		return trace.BadParameter("unsupported remote cluster type %T", rcV3)
	}

	_, err := c.grpc.UpdateRemoteCluster(ctx, rcV3)
	return trail.FromGRPC(err)
}

// CreateUser creates a new user from the specified descriptor.
func (c *Client) CreateUser(ctx context.Context, user types.User) error {
	userV2, ok := user.(*types.UserV2)
	if !ok {
		return trace.BadParameter("unsupported user type %T", user)
	}

	_, err := c.grpc.CreateUser(ctx, userV2)
	return trail.FromGRPC(err)
}

// UpdateUser updates an existing user in a backend.
func (c *Client) UpdateUser(ctx context.Context, user types.User) error {
	userV2, ok := user.(*types.UserV2)
	if !ok {
		return trace.BadParameter("unsupported user type %T", user)
	}

	_, err := c.grpc.UpdateUser(ctx, userV2)
	return trail.FromGRPC(err)
}

// GetUser returns a list of usernames registered in the system.
// withSecrets controls whether authentication details are returned.
func (c *Client) GetUser(name string, withSecrets bool) (types.User, error) {
	if name == "" {
		return nil, trace.BadParameter("missing username")
	}
	user, err := c.grpc.GetUser(context.TODO(), &proto.GetUserRequest{
		Name:        name,
		WithSecrets: withSecrets,
	})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return user, nil
}

// GetUsers returns a list of users.
// withSecrets controls whether authentication details are returned.
func (c *Client) GetUsers(withSecrets bool) ([]types.User, error) {
	stream, err := c.grpc.GetUsers(context.TODO(), &proto.GetUsersRequest{
		WithSecrets: withSecrets,
	})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	var users []types.User
	for {
		user, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, trail.FromGRPC(err)
		}
		users = append(users, user)
	}
	return users, nil
}

// DeleteUser deletes a user by name.
func (c *Client) DeleteUser(ctx context.Context, user string) error {
	req := &proto.DeleteUserRequest{Name: user}
	_, err := c.grpc.DeleteUser(ctx, req)
	return trail.FromGRPC(err)
}

// GenerateUserCerts takes the public key in the OpenSSH `authorized_keys` plain
// text format, signs it using User Certificate Authority signing key and
// returns the resulting certificates.
func (c *Client) GenerateUserCerts(ctx context.Context, req proto.UserCertsRequest) (*proto.Certs, error) {
	certs, err := c.grpc.GenerateUserCerts(ctx, &req)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return certs, nil
}

// EmitAuditEvent sends an auditable event to the auth server.
func (c *Client) EmitAuditEvent(ctx context.Context, event events.AuditEvent) error {
	grpcEvent, err := events.ToOneOf(event)
	if err != nil {
		return trace.Wrap(err)
	}
	_, err = c.grpc.EmitAuditEvent(ctx, grpcEvent)
	if err != nil {
		return trail.FromGRPC(err)
	}
	return nil
}

// GetAccessRequests retrieves a list of all access requests matching the provided filter.
func (c *Client) GetAccessRequests(ctx context.Context, filter types.AccessRequestFilter) ([]types.AccessRequest, error) {
	rsp, err := c.grpc.GetAccessRequests(ctx, &filter)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	reqs := make([]types.AccessRequest, 0, len(rsp.AccessRequests))
	for _, req := range rsp.AccessRequests {
		reqs = append(reqs, req)
	}
	return reqs, nil
}

// CreateAccessRequest registers a new access request with the auth server.
func (c *Client) CreateAccessRequest(ctx context.Context, req types.AccessRequest) error {
	r, ok := req.(*types.AccessRequestV3)
	if !ok {
		return trace.BadParameter("unexpected access request type %T", req)
	}
	_, err := c.grpc.CreateAccessRequest(ctx, r)
	return trail.FromGRPC(err)
}

// RotateResetPasswordTokenSecrets rotates secrets for a given tokenID.
// It gets called every time a user fetches 2nd-factor secrets during registration attempt.
// This ensures that an attacker that gains the ResetPasswordToken link can not view it,
// extract the OTP key from the QR code, then allow the user to signup with
// the same OTP token.
func (c *Client) RotateResetPasswordTokenSecrets(ctx context.Context, tokenID string) (types.ResetPasswordTokenSecrets, error) {
	secrets, err := c.grpc.RotateResetPasswordTokenSecrets(ctx, &proto.RotateResetPasswordTokenSecretsRequest{
		TokenID: tokenID,
	})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return secrets, nil
}

// GetResetPasswordToken returns a ResetPasswordToken for the specified tokenID.
func (c *Client) GetResetPasswordToken(ctx context.Context, tokenID string) (types.ResetPasswordToken, error) {
	token, err := c.grpc.GetResetPasswordToken(ctx, &proto.GetResetPasswordTokenRequest{
		TokenID: tokenID,
	})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}

	return token, nil
}

// CreateResetPasswordToken creates reset password token.
func (c *Client) CreateResetPasswordToken(ctx context.Context, req *proto.CreateResetPasswordTokenRequest) (types.ResetPasswordToken, error) {
	token, err := c.grpc.CreateResetPasswordToken(ctx, req)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}

	return token, nil
}

// DeleteAccessRequest deletes an access request.
func (c *Client) DeleteAccessRequest(ctx context.Context, reqID string) error {
	_, err := c.grpc.DeleteAccessRequest(ctx, &proto.RequestID{ID: reqID})
	return trail.FromGRPC(err)
}

// SetAccessRequestState updates the state of an existing access request.
func (c *Client) SetAccessRequestState(ctx context.Context, params types.AccessRequestUpdate) error {
	setter := proto.RequestStateSetter{
		ID:          params.RequestID,
		State:       params.State,
		Reason:      params.Reason,
		Annotations: params.Annotations,
		Roles:       params.Roles,
	}
	if d := GetDelegator(ctx); d != "" {
		setter.Delegator = d
	}
	_, err := c.grpc.SetAccessRequestState(ctx, &setter)
	return trail.FromGRPC(err)
}

// GetAccessCapabilities requests the access capabilities of a user.
func (c *Client) GetAccessCapabilities(ctx context.Context, req types.AccessCapabilitiesRequest) (*types.AccessCapabilities, error) {
	caps, err := c.grpc.GetAccessCapabilities(ctx, &req)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return caps, nil
}

// GetPluginData loads all plugin data matching the supplied filter.
func (c *Client) GetPluginData(ctx context.Context, filter types.PluginDataFilter) ([]types.PluginData, error) {
	seq, err := c.grpc.GetPluginData(ctx, &filter)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	data := make([]types.PluginData, 0, len(seq.PluginData))
	for _, d := range seq.PluginData {
		data = append(data, d)
	}
	return data, nil
}

// UpdatePluginData updates a per-resource PluginData entry.
func (c *Client) UpdatePluginData(ctx context.Context, params types.PluginDataUpdateParams) error {
	_, err := c.grpc.UpdatePluginData(ctx, &params)
	return trail.FromGRPC(err)
}

// AcquireSemaphore acquires lease with requested resources from semaphore.
func (c *Client) AcquireSemaphore(ctx context.Context, params types.AcquireSemaphoreRequest) (*types.SemaphoreLease, error) {
	lease, err := c.grpc.AcquireSemaphore(ctx, &params)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return lease, nil
}

// KeepAliveSemaphoreLease updates semaphore lease.
func (c *Client) KeepAliveSemaphoreLease(ctx context.Context, lease types.SemaphoreLease) error {
	_, err := c.grpc.KeepAliveSemaphoreLease(ctx, &lease)
	return trail.FromGRPC(err)
}

// CancelSemaphoreLease cancels semaphore lease early.
func (c *Client) CancelSemaphoreLease(ctx context.Context, lease types.SemaphoreLease) error {
	_, err := c.grpc.CancelSemaphoreLease(ctx, &lease)
	return trail.FromGRPC(err)
}

// GetSemaphores returns a list of all semaphores matching the supplied filter.
func (c *Client) GetSemaphores(ctx context.Context, filter types.SemaphoreFilter) ([]types.Semaphore, error) {
	rsp, err := c.grpc.GetSemaphores(ctx, &filter)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	sems := make([]types.Semaphore, 0, len(rsp.Semaphores))
	for _, s := range rsp.Semaphores {
		sems = append(sems, s)
	}
	return sems, nil
}

// DeleteSemaphore deletes a semaphore matching the supplied filter.
func (c *Client) DeleteSemaphore(ctx context.Context, filter types.SemaphoreFilter) error {
	_, err := c.grpc.DeleteSemaphore(ctx, &filter)
	return trail.FromGRPC(err)
}

// UpsertKubeService is used by kubernetes services to report their presence
// to other auth servers in form of hearbeat expiring after ttl period.
func (c *Client) UpsertKubeService(ctx context.Context, s types.Server) error {
	server, ok := s.(*types.ServerV2)
	if !ok {
		return trace.BadParameter("invalid type %T, expected *types.ServerV2", server)
	}
	_, err := c.grpc.UpsertKubeService(ctx, &proto.UpsertKubeServiceRequest{
		Server: server,
	})
	return trace.Wrap(err)
}

// GetKubeServices returns the list of kubernetes services registered in the
// cluster.
func (c *Client) GetKubeServices(ctx context.Context) ([]types.Server, error) {
	resp, err := c.grpc.GetKubeServices(ctx, &proto.GetKubeServicesRequest{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var servers []types.Server
	for _, server := range resp.GetServers() {
		servers = append(servers, server)
	}
	return servers, nil
}

// GetAppServers gets all application servers.
func (c *Client) GetAppServers(ctx context.Context, namespace string, skipValidation bool) ([]types.Server, error) {
	resp, err := c.grpc.GetAppServers(ctx, &proto.GetAppServersRequest{
		Namespace:      namespace,
		SkipValidation: skipValidation,
	})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}

	var servers []types.Server
	for _, server := range resp.GetServers() {
		servers = append(servers, server)
	}

	return servers, nil
}

// UpsertAppServer adds an application server.
func (c *Client) UpsertAppServer(ctx context.Context, server types.Server) (*types.KeepAlive, error) {
	s, ok := server.(*types.ServerV2)
	if !ok {
		return nil, trace.BadParameter("invalid type %T", server)
	}

	keepAlive, err := c.grpc.UpsertAppServer(ctx, &proto.UpsertAppServerRequest{
		Server: s,
	})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return keepAlive, nil
}

// DeleteAppServer removes an application server.
func (c *Client) DeleteAppServer(ctx context.Context, namespace string, name string) error {
	_, err := c.grpc.DeleteAppServer(ctx, &proto.DeleteAppServerRequest{
		Namespace: namespace,
		Name:      name,
	})
	return trail.FromGRPC(err)
}

// DeleteAllAppServers removes all application servers.
func (c *Client) DeleteAllAppServers(ctx context.Context, namespace string) error {
	_, err := c.grpc.DeleteAllAppServers(ctx, &proto.DeleteAllAppServersRequest{
		Namespace: namespace,
	})
	return trail.FromGRPC(err)
}

// GetAppSession gets an application web session.
func (c *Client) GetAppSession(ctx context.Context, req types.GetAppSessionRequest) (types.WebSession, error) {
	resp, err := c.grpc.GetAppSession(ctx, &proto.GetAppSessionRequest{
		SessionID: req.SessionID,
	})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}

	return resp.GetSession(), nil
}

// GetAppSessions gets all application web sessions.
func (c *Client) GetAppSessions(ctx context.Context) ([]types.WebSession, error) {
	resp, err := c.grpc.GetAppSessions(ctx, &empty.Empty{})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}

	out := make([]types.WebSession, 0, len(resp.GetSessions()))
	for _, v := range resp.GetSessions() {
		out = append(out, v)
	}
	return out, nil
}

// CreateAppSession creates an application web session. Application web
// sessions represent a browser session the client holds.
func (c *Client) CreateAppSession(ctx context.Context, req types.CreateAppSessionRequest) (types.WebSession, error) {
	resp, err := c.grpc.CreateAppSession(ctx, &proto.CreateAppSessionRequest{
		Username:      req.Username,
		ParentSession: req.ParentSession,
		PublicAddr:    req.PublicAddr,
		ClusterName:   req.ClusterName,
	})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}

	return resp.GetSession(), nil
}

// DeleteAppSession removes an application web session.
func (c *Client) DeleteAppSession(ctx context.Context, req types.DeleteAppSessionRequest) error {
	_, err := c.grpc.DeleteAppSession(ctx, &proto.DeleteAppSessionRequest{
		SessionID: req.SessionID,
	})
	return trail.FromGRPC(err)
}

// DeleteAllAppSessions removes all application web sessions.
func (c *Client) DeleteAllAppSessions(ctx context.Context) error {
	_, err := c.grpc.DeleteAllAppSessions(ctx, &empty.Empty{})
	return trail.FromGRPC(err)
}

// GenerateAppToken creates a JWT token with application access.
func (c *Client) GenerateAppToken(ctx context.Context, req types.GenerateAppTokenRequest) (string, error) {
	resp, err := c.grpc.GenerateAppToken(ctx, &proto.GenerateAppTokenRequest{
		Username: req.Username,
		Roles:    req.Roles,
		URI:      req.URI,
		Expires:  req.Expires,
	})
	if err != nil {
		return "", trail.FromGRPC(err)
	}

	return resp.GetToken(), nil
}

// DeleteKubeService deletes a named kubernetes service.
func (c *Client) DeleteKubeService(ctx context.Context, name string) error {
	_, err := c.grpc.DeleteKubeService(ctx, &proto.DeleteKubeServiceRequest{
		Name: name,
	})
	return trace.Wrap(err)
}

// DeleteAllKubeServices deletes all registered kubernetes services.
func (c *Client) DeleteAllKubeServices(ctx context.Context) error {
	_, err := c.grpc.DeleteAllKubeServices(ctx, &proto.DeleteAllKubeServicesRequest{})
	return trace.Wrap(err)
}

// GetDatabaseServers returns all registered database proxy servers.
func (c *Client) GetDatabaseServers(ctx context.Context, namespace string, skipValidation bool) ([]types.DatabaseServer, error) {
	resp, err := c.grpc.GetDatabaseServers(ctx, &proto.GetDatabaseServersRequest{
		Namespace:      namespace,
		SkipValidation: skipValidation,
	})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	servers := make([]types.DatabaseServer, 0, len(resp.GetServers()))
	for _, server := range resp.GetServers() {
		servers = append(servers, server)
	}
	return servers, nil
}

// UpsertDatabaseServer registers a new database proxy server.
func (c *Client) UpsertDatabaseServer(ctx context.Context, server types.DatabaseServer) (*types.KeepAlive, error) {
	s, ok := server.(*types.DatabaseServerV3)
	if !ok {
		return nil, trace.BadParameter("invalid type %T", server)
	}
	keepAlive, err := c.grpc.UpsertDatabaseServer(ctx, &proto.UpsertDatabaseServerRequest{
		Server: s,
	})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return keepAlive, nil
}

// DeleteDatabaseServer removes the specified database proxy server.
func (c *Client) DeleteDatabaseServer(ctx context.Context, namespace, hostID, name string) error {
	_, err := c.grpc.DeleteDatabaseServer(ctx, &proto.DeleteDatabaseServerRequest{
		Namespace: namespace,
		HostID:    hostID,
		Name:      name,
	})
	if err != nil {
		return trail.FromGRPC(err)
	}
	return nil
}

// DeleteAllDatabaseServers removes all registered database proxy servers.
func (c *Client) DeleteAllDatabaseServers(ctx context.Context, namespace string) error {
	_, err := c.grpc.DeleteAllDatabaseServers(ctx, &proto.DeleteAllDatabaseServersRequest{
		Namespace: namespace,
	})
	if err != nil {
		return trail.FromGRPC(err)
	}
	return nil
}

// SignDatabaseCSR generates a client certificate used by proxy when talking
// to a remote database service.
func (c *Client) SignDatabaseCSR(ctx context.Context, req *proto.DatabaseCSRRequest) (*proto.DatabaseCSRResponse, error) {
	resp, err := c.grpc.SignDatabaseCSR(ctx, req)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return resp, nil
}

// GenerateDatabaseCert generates client certificate used by a database
// service to authenticate with the database instance.
func (c *Client) GenerateDatabaseCert(ctx context.Context, req *proto.DatabaseCertRequest) (*proto.DatabaseCertResponse, error) {
	resp, err := c.grpc.GenerateDatabaseCert(ctx, req)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return resp, nil
}

func (c *Client) AddMFADevice(ctx context.Context) (proto.AuthService_AddMFADeviceClient, error) {
	stream, err := c.grpc.AddMFADevice(ctx)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return stream, nil
}

func (c *Client) DeleteMFADevice(ctx context.Context) (proto.AuthService_DeleteMFADeviceClient, error) {
	stream, err := c.grpc.DeleteMFADevice(ctx)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return stream, nil
}

func (c *Client) GetMFADevices(ctx context.Context, in *proto.GetMFADevicesRequest) (*proto.GetMFADevicesResponse, error) {
	resp, err := c.grpc.GetMFADevices(ctx, in)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return resp, nil
}

func (c *Client) GenerateUserSingleUseCerts(ctx context.Context) (proto.AuthService_GenerateUserSingleUseCertsClient, error) {
	stream, err := c.grpc.GenerateUserSingleUseCerts(ctx)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return stream, nil
}
