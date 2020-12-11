/*
Copyright 2020 Gravitational, Inc.

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

// Package auth implements teleport's grpc auth client
package auth

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/jwt"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/trace"
	"github.com/gravitational/trace/trail"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	ggzip "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"
)

func init() {
	if err := ggzip.SetLevel(gzip.BestSpeed); err != nil {
		panic(err)
	}
}

// Client is a gRPC Client that connects to a teleport auth server through TLS.
type Client struct {
	c    Config
	grpc AuthServiceClient
	conn *grpc.ClientConn
	// closedFlag is set to indicate that the services are closed
	closedFlag int32
}

// TLSConfig returns TLS config used by the client, could return nil
// if the client is not using TLS
func (c *Client) TLSConfig() *tls.Config {
	return c.c.TLS
}

// NewClient returns a new auth client that uses mutual TLS authentication and
// connects to the remote server using the Dialer or Addrs in Config.
func NewClient(cfg Config) (*Client, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	c := &Client{c: cfg}
	dialer := grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		if c.isClosed() {
			return nil, trace.ConnectionProblem(nil, "client is closed")
		}
		conn, err := c.c.Dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, trace.ConnectionProblem(err, "failed to dial")
		}
		return conn, nil
	})

	tlsConfig := c.c.TLS.Clone()
	tlsConfig.NextProtos = []string{http2.NextProtoTLS}
	conn, err := grpc.Dial(teleport.APIDomain,
		dialer,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                c.c.KeepAlivePeriod,
			Timeout:             c.c.KeepAlivePeriod * time.Duration(c.c.KeepAliveCount),
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}

	c.conn = conn
	c.grpc = NewAuthServiceClient(c.conn)
	return c, nil
}

// NewFromAuthServiceClient is used to make mock clients for testing
func NewFromAuthServiceClient(asc AuthServiceClient) *Client {
	return &Client{
		grpc: asc,
	}
}

// Close closes the Client connection to the auth server
func (c *Client) Close() error {
	if !c.setClosed() {
		return nil
	}
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return trace.Wrap(err)
	}
	return nil
}

func (c *Client) isClosed() bool {
	return atomic.LoadInt32(&c.closedFlag) == 1
}

func (c *Client) setClosed() bool {
	return atomic.CompareAndSwapInt32(&c.closedFlag, 0, 1)
}

// Ping gets basic info about the auth server.
func (c *Client) Ping(ctx context.Context) (PingResponse, error) {
	rsp, err := c.grpc.Ping(ctx, &PingRequest{})
	if err != nil {
		return PingResponse{}, trail.FromGRPC(err)
	}
	return *rsp, nil
}

// UpsertNode is used by SSH servers to report their presence
// to the auth servers in form of hearbeat expiring after ttl period.
func (c *Client) UpsertNode(s services.Server) (*services.KeepAlive, error) {
	if s.GetNamespace() == "" {
		return nil, trace.BadParameter("missing node namespace")
	}
	protoServer, ok := s.(*services.ServerV2)
	if !ok {
		return nil, trace.BadParameter("unsupported client")
	}
	keepAlive, err := c.grpc.UpsertNode(context.TODO(), protoServer)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return keepAlive, nil
}

// NewKeepAliver returns a new instance of keep aliver
func (c *Client) NewKeepAliver(ctx context.Context) (services.KeepAliver, error) {
	cancelCtx, cancel := context.WithCancel(ctx)
	stream, err := c.grpc.SendKeepAlives(cancelCtx)
	if err != nil {
		cancel()
		return nil, trail.FromGRPC(err)
	}
	k := &streamKeepAliver{
		stream:      stream,
		ctx:         cancelCtx,
		cancel:      cancel,
		keepAlivesC: make(chan services.KeepAlive),
	}
	go k.forwardKeepAlives()
	go k.recv()
	return k, nil
}

type streamKeepAliver struct {
	sync.RWMutex
	stream      AuthService_SendKeepAlivesClient
	ctx         context.Context
	cancel      context.CancelFunc
	keepAlivesC chan services.KeepAlive
	err         error
}

func (k *streamKeepAliver) KeepAlives() chan<- services.KeepAlive {
	return k.keepAlivesC
}

func (k *streamKeepAliver) forwardKeepAlives() {
	for {
		select {
		case <-k.ctx.Done():
			return
		case keepAlive := <-k.keepAlivesC:
			err := k.stream.Send(&keepAlive)
			if err != nil {
				k.closeWithError(trail.FromGRPC(err))
				return
			}
		}
	}
}

func (k *streamKeepAliver) Error() error {
	k.RLock()
	defer k.RUnlock()
	return k.err
}

func (k *streamKeepAliver) Done() <-chan struct{} {
	return k.ctx.Done()
}

// recv is necessary to receive errors from the
// server, otherwise no errors will be propagated
func (k *streamKeepAliver) recv() {
	err := k.stream.RecvMsg(&empty.Empty{})
	k.closeWithError(trail.FromGRPC(err))
}

func (k *streamKeepAliver) closeWithError(err error) {
	k.Close()
	k.Lock()
	defer k.Unlock()
	k.err = err
}

func (k *streamKeepAliver) Close() error {
	k.cancel()
	return nil
}

// NewWatcher returns a new event watcher
func (c *Client) NewWatcher(ctx context.Context, watch services.Watch) (services.Watcher, error) {
	cancelCtx, cancel := context.WithCancel(ctx)
	var protoWatch Watch
	for _, k := range watch.Kinds {
		protoWatch.Kinds = append(protoWatch.Kinds, WatchKind{
			Name:        k.Name,
			Kind:        k.Kind,
			LoadSecrets: k.LoadSecrets,
			Filter:      k.Filter,
		})
	}
	stream, err := c.grpc.WatchEvents(cancelCtx, &protoWatch)
	if err != nil {
		cancel()
		return nil, trail.FromGRPC(err)
	}
	w := &streamWatcher{
		stream:  stream,
		ctx:     cancelCtx,
		cancel:  cancel,
		eventsC: make(chan services.Event),
	}
	go w.receiveEvents()
	return w, nil
}

type streamWatcher struct {
	mu      sync.RWMutex
	stream  AuthService_WatchEventsClient
	ctx     context.Context
	cancel  context.CancelFunc
	eventsC chan services.Event
	err     error
}

func (w *streamWatcher) Error() error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.err == nil {
		return trace.Wrap(w.ctx.Err())
	}
	return w.err
}

func (w *streamWatcher) closeWithError(err error) {
	w.Close()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.err = err
}

func (w *streamWatcher) Events() <-chan services.Event {
	return w.eventsC
}

func (w *streamWatcher) receiveEvents() {
	for {
		event, err := w.stream.Recv()
		if err != nil {
			w.closeWithError(trail.FromGRPC(err))
			return
		}
		out, err := eventFromGRPC(*event)
		if err != nil {
			w.closeWithError(trail.FromGRPC(err))
			return
		}
		select {
		case w.eventsC <- *out:
		case <-w.Done():
			return
		}
	}
}

func (w *streamWatcher) Done() <-chan struct{} {
	return w.ctx.Done()
}

func (w *streamWatcher) Close() error {
	w.cancel()
	return nil
}

// UpdateRemoteCluster updates remote cluster from the specified value.
func (c *Client) UpdateRemoteCluster(ctx context.Context, rc services.RemoteCluster) error {

	rcV3, ok := rc.(*services.RemoteClusterV3)
	if !ok {
		return trace.BadParameter("unsupported remote cluster type %T", rcV3)
	}

	_, err := c.grpc.UpdateRemoteCluster(ctx, rcV3)
	return trail.FromGRPC(err)
}

// CreateUser creates a new user from the specified descriptor.
func (c *Client) CreateUser(ctx context.Context, user services.User) error {

	userV2, ok := user.(*services.UserV2)
	if !ok {
		return trace.BadParameter("unsupported user type %T", user)
	}

	_, err := c.grpc.CreateUser(ctx, userV2)
	return trail.FromGRPC(err)
}

// UpdateUser updates an existing user in a backend.
func (c *Client) UpdateUser(ctx context.Context, user services.User) error {

	userV2, ok := user.(*services.UserV2)
	if !ok {
		return trace.BadParameter("unsupported user type %T", user)
	}

	_, err := c.grpc.UpdateUser(ctx, userV2)
	return trail.FromGRPC(err)
}

// GetUser returns a list of usernames registered in the system.
// withSecrets controls whether authentication details are returned.
func (c *Client) GetUser(name string, withSecrets bool) (services.User, error) {
	if name == "" {
		return nil, trace.BadParameter("missing username")
	}
	user, err := c.grpc.GetUser(context.TODO(), &GetUserRequest{
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
func (c *Client) GetUsers(withSecrets bool) ([]services.User, error) {
	stream, err := c.grpc.GetUsers(context.TODO(), &GetUsersRequest{
		WithSecrets: withSecrets,
	})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	var users []services.User
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
	req := &DeleteUserRequest{Name: user}
	_, err := c.grpc.DeleteUser(ctx, req)
	return trail.FromGRPC(err)
}

// GenerateUserCerts takes the public key in the OpenSSH `authorized_keys` plain
// text format, signs it using User Certificate Authority signing key and
// returns the resulting certificates.
func (c *Client) GenerateUserCerts(ctx context.Context, req UserCertsRequest) (*Certs, error) {
	certs, err := c.grpc.GenerateUserCerts(ctx, &req)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return certs, nil
}

// createOrResumeAuditStream creates or resumes audit stream described in the request
func (c *Client) createOrResumeAuditStream(ctx context.Context, request AuditStreamRequest) (events.Stream, error) {
	closeCtx, cancel := context.WithCancel(ctx)
	stream, err := c.grpc.CreateAuditStream(closeCtx, grpc.UseCompressor(ggzip.Name))
	if err != nil {
		cancel()
		return nil, trail.FromGRPC(err)
	}
	s := &auditStreamer{
		stream:   stream,
		statusCh: make(chan events.StreamStatus, 1),
		closeCtx: closeCtx,
		cancel:   cancel,
	}
	go s.recv()
	err = s.stream.Send(&request)
	if err != nil {
		return nil, trace.NewAggregate(s.Close(ctx), trail.FromGRPC(err))
	}
	return s, nil
}

// ResumeAuditStream resumes existing audit stream
func (c *Client) ResumeAuditStream(ctx context.Context, sid session.ID, uploadID string) (events.Stream, error) {
	return c.createOrResumeAuditStream(ctx, AuditStreamRequest{
		Request: &AuditStreamRequest_ResumeStream{
			ResumeStream: &ResumeStream{
				SessionID: string(sid),
				UploadID:  uploadID,
			}},
	})
}

// CreateAuditStream creates new audit stream
func (c *Client) CreateAuditStream(ctx context.Context, sid session.ID) (events.Stream, error) {
	return c.createOrResumeAuditStream(ctx, AuditStreamRequest{
		Request: &AuditStreamRequest_CreateStream{
			CreateStream: &CreateStream{SessionID: string(sid)}},
	})
}

type auditStreamer struct {
	statusCh chan events.StreamStatus
	mu       sync.RWMutex
	stream   AuthService_CreateAuditStreamClient
	err      error
	closeCtx context.Context
	cancel   context.CancelFunc
}

// Close flushes non-uploaded flight stream data without marking
// the stream completed and closes the stream instance
func (s *auditStreamer) Close(ctx context.Context) error {
	defer s.closeWithError(nil)
	return trail.FromGRPC(s.stream.Send(&AuditStreamRequest{
		Request: &AuditStreamRequest_FlushAndCloseStream{
			FlushAndCloseStream: &FlushAndCloseStream{},
		},
	}))
}

// Complete completes stream
func (s *auditStreamer) Complete(ctx context.Context) error {
	return trail.FromGRPC(s.stream.Send(&AuditStreamRequest{
		Request: &AuditStreamRequest_CompleteStream{
			CompleteStream: &CompleteStream{},
		},
	}))
}

// Status returns channel receiving updates about stream status
// last event index that was uploaded and upload ID
func (s *auditStreamer) Status() <-chan events.StreamStatus {
	return s.statusCh
}

// EmitAuditEvent emits audit event
func (s *auditStreamer) EmitAuditEvent(ctx context.Context, event events.AuditEvent) error {
	oneof, err := events.ToOneOf(event)
	if err != nil {
		return trace.Wrap(err)
	}
	err = trail.FromGRPC(s.stream.Send(&AuditStreamRequest{
		Request: &AuditStreamRequest_Event{Event: oneof},
	}))
	if err != nil {
		s.closeWithError(err)
		return trace.Wrap(err)
	}
	return nil
}

// Done returns channel closed when streamer is closed
// should be used to detect sending errors
func (s *auditStreamer) Done() <-chan struct{} {
	return s.closeCtx.Done()
}

// Error returns last error of the stream
func (s *auditStreamer) Error() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.err
}

// recv is necessary to receive errors from the
// server, otherwise no errors will be propagated
func (s *auditStreamer) recv() {
	for {
		status, err := s.stream.Recv()
		if err != nil {
			s.closeWithError(trail.FromGRPC(err))
			return
		}
		select {
		case <-s.closeCtx.Done():
			return
		case s.statusCh <- *status:
		default:
		}
	}
}

func (s *auditStreamer) closeWithError(err error) {
	s.cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

// EmitAuditEvent sends an auditable event to the auth server
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

func (c *Client) GetAccessRequests(ctx context.Context, filter services.AccessRequestFilter) ([]services.AccessRequest, error) {
	rsp, err := c.grpc.GetAccessRequests(ctx, &filter)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	reqs := make([]services.AccessRequest, 0, len(rsp.AccessRequests))
	for _, req := range rsp.AccessRequests {
		reqs = append(reqs, req)
	}
	return reqs, nil
}

func (c *Client) CreateAccessRequest(ctx context.Context, req services.AccessRequest) error {
	r, ok := req.(*services.AccessRequestV3)
	if !ok {
		return trace.BadParameter("unexpected access request type %T", req)
	}
	_, err := c.grpc.CreateAccessRequest(ctx, r)
	return trail.FromGRPC(err)
}

func (c *Client) RotateResetPasswordTokenSecrets(ctx context.Context, tokenID string) (services.ResetPasswordTokenSecrets, error) {

	secrets, err := c.grpc.RotateResetPasswordTokenSecrets(ctx, &RotateResetPasswordTokenSecretsRequest{
		TokenID: tokenID,
	})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return secrets, nil
}

func (c *Client) GetResetPasswordToken(ctx context.Context, tokenID string) (services.ResetPasswordToken, error) {

	token, err := c.grpc.GetResetPasswordToken(ctx, &GetResetPasswordTokenRequest{
		TokenID: tokenID,
	})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}

	return token, nil
}

// CreateResetPasswordToken creates reset password token
func (c *Client) CreateResetPasswordToken(ctx context.Context, req CreateResetPasswordTokenRequest) (services.ResetPasswordToken, error) {

	token, err := c.grpc.CreateResetPasswordToken(ctx, &req)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}

	return token, nil
}

func (c *Client) DeleteAccessRequest(ctx context.Context, reqID string) error {

	_, err := c.grpc.DeleteAccessRequest(ctx, &RequestID{
		ID: reqID,
	})
	return trail.FromGRPC(err)
}

type contextKey string

const (
	// ContextDelegator is a delegator for access requests set in the context
	// of the request
	ContextDelegator contextKey = "delegator"
)

// getDelegator attempts to load the context value AccessRequestDelegator,
// returning the empty string if mno value was found.
func getDelegator(ctx context.Context) string {
	delegator, ok := ctx.Value(ContextDelegator).(string)
	if !ok {
		return ""
	}
	return delegator
}

func (c *Client) SetAccessRequestState(ctx context.Context, params services.AccessRequestUpdate) error {
	setter := RequestStateSetter{
		ID:          params.RequestID,
		State:       params.State,
		Reason:      params.Reason,
		Annotations: params.Annotations,
		Roles:       params.Roles,
	}
	if d := getDelegator(ctx); d != "" {
		setter.Delegator = d
	}
	_, err := c.grpc.SetAccessRequestState(ctx, &setter)
	return trail.FromGRPC(err)
}

// GetPluginData loads all plugin data matching the supplied filter.
func (c *Client) GetPluginData(ctx context.Context, filter services.PluginDataFilter) ([]services.PluginData, error) {
	seq, err := c.grpc.GetPluginData(ctx, &filter)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	data := make([]services.PluginData, 0, len(seq.PluginData))
	for _, d := range seq.PluginData {
		data = append(data, d)
	}
	return data, nil
}

// UpdatePluginData updates a per-resource PluginData entry.
func (c *Client) UpdatePluginData(ctx context.Context, params services.PluginDataUpdateParams) error {
	_, err := c.grpc.UpdatePluginData(ctx, &params)
	return trail.FromGRPC(err)
}

// AcquireSemaphore acquires lease with requested resources from semaphore.
func (c *Client) AcquireSemaphore(ctx context.Context, params services.AcquireSemaphoreRequest) (*services.SemaphoreLease, error) {
	lease, err := c.grpc.AcquireSemaphore(ctx, &params)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return lease, nil
}

// KeepAliveSemaphoreLease updates semaphore lease.
func (c *Client) KeepAliveSemaphoreLease(ctx context.Context, lease services.SemaphoreLease) error {
	_, err := c.grpc.KeepAliveSemaphoreLease(ctx, &lease)
	return trail.FromGRPC(err)
}

// CancelSemaphoreLease cancels semaphore lease early.
func (c *Client) CancelSemaphoreLease(ctx context.Context, lease services.SemaphoreLease) error {
	_, err := c.grpc.CancelSemaphoreLease(ctx, &lease)
	return trail.FromGRPC(err)
}

// GetSemaphores returns a list of all semaphores matching the supplied filter.
func (c *Client) GetSemaphores(ctx context.Context, filter services.SemaphoreFilter) ([]services.Semaphore, error) {
	rsp, err := c.grpc.GetSemaphores(ctx, &filter)
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	sems := make([]services.Semaphore, 0, len(rsp.Semaphores))
	for _, s := range rsp.Semaphores {
		sems = append(sems, s)
	}
	return sems, nil
}

// DeleteSemaphore deletes a semaphore matching the supplied filter.
func (c *Client) DeleteSemaphore(ctx context.Context, filter services.SemaphoreFilter) error {
	_, err := c.grpc.DeleteSemaphore(ctx, &filter)
	return trail.FromGRPC(err)
}

// UpsertKubeService is used by kubernetes services to report their presence
// to other auth servers in form of hearbeat expiring after ttl period.
func (c *Client) UpsertKubeService(ctx context.Context, s services.Server) error {
	server, ok := s.(*services.ServerV2)
	if !ok {
		return trace.BadParameter("invalid type %T, expected *services.ServerV2", server)
	}
	_, err := c.grpc.UpsertKubeService(ctx, &UpsertKubeServiceRequest{
		Server: server,
	})
	return trace.Wrap(err)
}

// GetKubeServices returns the list of kubernetes services registered in the
// cluster.
func (c *Client) GetKubeServices(ctx context.Context) ([]services.Server, error) {
	resp, err := c.grpc.GetKubeServices(ctx, &GetKubeServicesRequest{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var servers []services.Server
	for _, server := range resp.GetServers() {
		servers = append(servers, server)
	}
	return servers, nil
}

// GetAppServers gets all application servers.
func (c *Client) GetAppServers(ctx context.Context, namespace string, opts ...services.MarshalOption) ([]services.Server, error) {

	cfg, err := services.CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	resp, err := c.grpc.GetAppServers(ctx, &GetAppServersRequest{
		Namespace:      namespace,
		SkipValidation: cfg.SkipValidation,
	})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}

	var servers []services.Server
	for _, server := range resp.GetServers() {
		servers = append(servers, server)
	}

	return servers, nil
}

// UpsertAppServer adds an application server.
func (c *Client) UpsertAppServer(ctx context.Context, server services.Server) (*services.KeepAlive, error) {

	s, ok := server.(*services.ServerV2)
	if !ok {
		return nil, trace.BadParameter("invalid type %T", server)
	}

	keepAlive, err := c.grpc.UpsertAppServer(ctx, &UpsertAppServerRequest{
		Server: s,
	})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return keepAlive, nil
}

// DeleteAppServer removes an application server.
func (c *Client) DeleteAppServer(ctx context.Context, namespace string, name string) error {

	_, err := c.grpc.DeleteAppServer(ctx, &DeleteAppServerRequest{
		Namespace: namespace,
		Name:      name,
	})
	return trail.FromGRPC(err)
}

// DeleteAllAppServers removes all application servers.
func (c *Client) DeleteAllAppServers(ctx context.Context, namespace string) error {

	_, err := c.grpc.DeleteAllAppServers(ctx, &DeleteAllAppServersRequest{
		Namespace: namespace,
	})
	return trail.FromGRPC(err)
}

// GetAppSession gets an application web session.
func (c *Client) GetAppSession(ctx context.Context, req services.GetAppSessionRequest) (services.WebSession, error) {

	resp, err := c.grpc.GetAppSession(ctx, &GetAppSessionRequest{
		SessionID: req.SessionID,
	})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}

	return resp.GetSession(), nil
}

// GetAppSessions gets all application web sessions.
func (c *Client) GetAppSessions(ctx context.Context) ([]services.WebSession, error) {

	resp, err := c.grpc.GetAppSessions(ctx, &empty.Empty{})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}

	out := make([]services.WebSession, 0, len(resp.GetSessions()))
	for _, v := range resp.GetSessions() {
		out = append(out, v)
	}
	return out, nil
}

// CreateAppSession creates an application web session. Application web
// sessions represent a browser session the client holds.
func (c *Client) CreateAppSession(ctx context.Context, req services.CreateAppSessionRequest) (services.WebSession, error) {

	resp, err := c.grpc.CreateAppSession(ctx, &CreateAppSessionRequest{
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
func (c *Client) DeleteAppSession(ctx context.Context, req services.DeleteAppSessionRequest) error {

	_, err := c.grpc.DeleteAppSession(ctx, &DeleteAppSessionRequest{
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
func (c *Client) GenerateAppToken(ctx context.Context, req jwt.GenerateAppTokenRequest) (string, error) {

	resp, err := c.grpc.GenerateAppToken(ctx, &GenerateAppTokenRequest{
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
	_, err := c.grpc.DeleteKubeService(ctx, &DeleteKubeServiceRequest{
		Name: name,
	})
	return trace.Wrap(err)
}

// DeleteAllKubeServices deletes all registered kubernetes services.
func (c *Client) DeleteAllKubeServices(ctx context.Context) error {
	_, err := c.grpc.DeleteAllKubeServices(ctx, &DeleteAllKubeServicesRequest{})
	return trace.Wrap(err)
}
