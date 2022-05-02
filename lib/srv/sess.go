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

package srv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/bpf"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/events/filesessions"
	"github.com/gravitational/teleport/lib/services"
	rsession "github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace/trail"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const sessionRecorderID = "session-recorder"

const PresenceVerifyInterval = time.Second * 15
const PresenceMaxDifference = time.Minute

// SessionControlsInfoBroadcast is sent in tandem with session creation
// to inform any joining users about the session controls.
const SessionControlsInfoBroadcast = "Controls\r\n  - CTRL-C: Leave the session\r\n  - t: Forcefully terminate the session (moderators only)"

var serverSessions = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Name: teleport.MetricServerInteractiveSessions,
		Help: "Number of active sessions to this host",
	},
)

// SessionRegistry holds a map of all active sessions on a given
// SSH server
type SessionRegistry struct {
	SessionRegistryConfig

	// log holds the structured logger
	log *log.Entry

	// sessions holds a map between session ID and the session object. Used to
	// find active sessions as well as close all sessions when the registry
	// is closing.
	sessions    map[rsession.ID]*session
	sessionsMux sync.Mutex
}

type SessionRegistryConfig struct {
	// clock is the registry's internal clock. used in testing.
	clock clockwork.Clock

	// srv refers to the upon which this session registry is created.
	Srv Server

	// sessiontrackerService is used to share session activity to
	// other teleport components through the auth server.
	SessionTrackerService services.SessionTrackerService
}

func (sc *SessionRegistryConfig) CheckAndSetDefaults() error {
	if sc.SessionTrackerService == nil {
		return trace.BadParameter("session tracker service is required")
	}

	if sc.Srv == nil {
		return trace.BadParameter("server is required")
	}

	if sc.Srv.GetSessionServer() == nil {
		return trace.BadParameter("session server is required")
	}

	if sc.clock == nil {
		sc.clock = sc.Srv.GetClock()
	}

	return nil
}

func NewSessionRegistry(cfg SessionRegistryConfig) (*SessionRegistry, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	err := utils.RegisterPrometheusCollectors(serverSessions)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &SessionRegistry{
		SessionRegistryConfig: cfg,
		log: log.WithFields(log.Fields{
			trace.Component: teleport.Component(teleport.ComponentSession, cfg.Srv.Component()),
		}),
		sessions: make(map[rsession.ID]*session),
	}, nil
}

func (s *SessionRegistry) addSession(sess *session) {
	s.sessionsMux.Lock()
	defer s.sessionsMux.Unlock()
	s.sessions[sess.id] = sess
}

func (s *SessionRegistry) removeSession(sess *session) {
	s.sessionsMux.Lock()
	defer s.sessionsMux.Unlock()
	delete(s.sessions, sess.id)
}

func (s *SessionRegistry) findSessionLocked(id rsession.ID) (*session, bool) {
	sess, found := s.sessions[id]
	return sess, found
}

func (s *SessionRegistry) Close() {
	s.sessionsMux.Lock()
	defer s.sessionsMux.Unlock()

	// End all sessions and allow session cleanup
	// goroutines to complete.
	for _, se := range s.sessions {
		se.Stop()
	}

	s.log.Debug("Closing Session Registry.")
}

// OpenSession either joins an existing session or starts a new session.
func (s *SessionRegistry) OpenSession(ch ssh.Channel, ctx *ServerContext) error {
	session := ctx.getSession()
	if session != nil {
		ctx.Infof("Joining existing session %v.", session.id)

		mode := types.SessionParticipantMode(ctx.env[teleport.EnvSSHJoinMode])
		switch mode {
		case types.SessionModeratorMode, types.SessionObserverMode:
		default:
			if mode == types.SessionPeerMode || len(mode) == 0 {
				mode = types.SessionPeerMode
			} else {
				return trace.BadParameter("Unrecognized session participant mode: %v", mode)
			}
		}

		// Update the in-memory data structure that a party member has joined.
		_, err := session.join(ch, ctx, mode)
		if err != nil {
			return trace.Wrap(err)
		}

		return nil
	}
	// session not found? need to create one. start by getting/generating an ID for it
	sid, found := ctx.GetEnv(sshutils.SessionEnvVar)
	if !found {
		sid = string(rsession.NewID())
		ctx.SetEnv(sshutils.SessionEnvVar, sid)
	}
	// This logic allows concurrent request to create a new session
	// to fail, what is ok because we should never have this condition
	sess, err := newSession(rsession.ID(sid), s, ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	ctx.setSession(sess)
	s.addSession(sess)
	ctx.Infof("Creating (interactive) session %v.", sid)

	// Start an interactive session (TTY attached). Close the session if an error
	// occurs, otherwise it will be closed by the callee.
	if err := sess.startInteractive(ch, ctx); err != nil {
		sess.Close()
		return trace.Wrap(err)
	}
	return nil
}

// OpenExecSession opens an non-interactive exec session.
func (s *SessionRegistry) OpenExecSession(channel ssh.Channel, ctx *ServerContext) error {
	// Create a new session ID. These sessions can not be joined so no point in
	// looking for an exisiting one.
	sessionID := rsession.NewID()

	// This logic allows concurrent request to create a new session
	// to fail, what is ok because we should never have this condition.
	sess, err := newSession(sessionID, s, ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	ctx.Infof("Creating (exec) session %v.", sessionID)

	canStart, _, err := sess.checkIfStart()
	if err != nil {
		return trace.Wrap(err)
	}

	if !canStart {
		return trace.AccessDenied("lacking privileges to start unattended session")
	}

	// Start a non-interactive session (TTY attached). Close the session if an error
	// occurs, otherwise it will be closed by the callee.
	ctx.setSession(sess)
	err = sess.startExec(channel, ctx)
	if err != nil {
		sess.Close()
		return trace.Wrap(err)
	}

	return nil
}

func (s *SessionRegistry) ForceTerminate(ctx *ServerContext) error {
	sess := ctx.getSession()
	if sess == nil {
		s.log.Debug("Unable to terminate session, no session found in context.")
		return nil
	}

	sess.BroadcastMessage("Forcefully terminating session...")

	// Stop session, it will be cleaned up in the background to ensure
	// the session recording is uploaded.
	sess.Stop()

	return nil
}

// NotifyWinChange is called to notify all members in the party that the PTY
// size has changed. The notification is sent as a global SSH request and it
// is the responsibility of the client to update it's window size upon receipt.
func (s *SessionRegistry) NotifyWinChange(params rsession.TerminalParams, ctx *ServerContext) error {
	session := ctx.getSession()
	if session == nil {
		s.log.Debug("Unable to update window size, no session found in context.")
		return nil
	}
	sid := session.id

	// Build the resize event.
	resizeEvent := &apievents.Resize{
		Metadata: apievents.Metadata{
			Type:        events.ResizeEvent,
			Code:        events.TerminalResizeCode,
			ClusterName: ctx.ClusterName,
		},
		ServerMetadata: apievents.ServerMetadata{
			ServerID:        ctx.srv.HostUUID(),
			ServerLabels:    ctx.srv.GetInfo().GetAllLabels(),
			ServerNamespace: s.Srv.GetNamespace(),
			ServerHostname:  s.Srv.GetInfo().GetHostname(),
			ServerAddr:      ctx.ServerConn.LocalAddr().String(),
		},
		SessionMetadata: apievents.SessionMetadata{
			SessionID: string(sid),
		},
		UserMetadata: ctx.Identity.GetUserMetadata(),
		TerminalSize: params.Serialize(),
	}

	// Report the updated window size to the event log (this is so the sessions
	// can be replayed correctly).
	if err := session.recorder.EmitAuditEvent(s.Srv.Context(), resizeEvent); err != nil {
		s.log.WithError(err).Warn("Failed to emit resize audit event.")
	}

	// Update the size of the server side PTY.
	err := session.term.SetWinSize(params)
	if err != nil {
		return trace.Wrap(err)
	}

	// If sessions are being recorded at the proxy, sessions can not be shared.
	// In that situation, PTY size information does not need to be propagated
	// back to all clients and we can return right away.
	if services.IsRecordAtProxy(ctx.SessionRecordingConfig.GetMode()) {
		return nil
	}

	// Notify all members of the party (except originator) that the size of the
	// window has changed so the client can update it's own local PTY. Note that
	// OpenSSH clients will ignore this and not update their own local PTY.
	for _, p := range session.getParties() {
		// Don't send the window change notification back to the originator.
		if p.ctx.ID() == ctx.ID() {
			continue
		}

		eventPayload, err := json.Marshal(resizeEvent)
		if err != nil {
			s.log.Warnf("Unable to marshal resize event for %v: %v.", p.sconn.RemoteAddr(), err)
			continue
		}

		// Send the message as a global request.
		_, _, err = p.sconn.SendRequest(teleport.SessionEvent, false, eventPayload)
		if err != nil {
			s.log.Warnf("Unable to resize event to %v: %v.", p.sconn.RemoteAddr(), err)
			continue
		}
		s.log.Debugf("Sent resize event %v to %v.", params, p.sconn.RemoteAddr())
	}

	return nil
}

func (s *SessionRegistry) broadcastResult(sid rsession.ID, r ExecResult) error {
	s.sessionsMux.Lock()
	defer s.sessionsMux.Unlock()

	sess, found := s.findSessionLocked(sid)
	if !found {
		return trace.NotFound("session %v not found", sid)
	}
	sess.broadcastResult(r)
	return nil
}

// session struct describes an active (in progress) SSH session. These sessions
// are managed by 'SessionRegistry' containers which are attached to SSH servers.
type session struct {
	mu sync.RWMutex

	// log holds the structured logger
	log *log.Entry

	// session ID. unique GUID, this is what people use to "join" sessions
	id rsession.ID

	// parent session container
	registry *SessionRegistry

	// parties is the set of current connected clients/users. This map may grow
	// and shrink as members join and leave the session.
	parties map[rsession.ID]*party

	// participants is the set of users that have joined this session. Users are
	// never removed from this map as it's used to report the full list of
	// participants at the end of a session.
	participants map[rsession.ID]*party

	io       *TermManager
	inWriter io.Writer

	term Terminal

	// stopC channel is used to kill all goroutines owned
	// by the session
	stopC chan struct{}

	// startTime is the time when this session was created.
	startTime time.Time

	// login stores the login of the initial session creator
	login string

	recorder events.StreamWriter

	// hasEnhancedRecording returns true if this session has enhanced session
	// recording events associated.
	hasEnhancedRecording bool

	// serverCtx is used to control clean up of internal resources
	serverCtx context.Context

	access auth.SessionAccessEvaluator

	tracker *sessionTrackerServiceWithCond

	initiator string

	scx *ServerContext

	presenceEnabled bool

	started bool

	doneCh chan struct{}

	bpfContext *bpf.SessionContext

	cgroupID uint64

	displayParticipantRequirements bool

	// endingContext is the server context which closed this session.
	endingContext *ServerContext

	// lingerAndDieCancel is a context cancel func which will cancel
	// an ongoing lingerAndDie goroutine. This is used by joining parties
	// to cancel the goroutine and prevent the session from closing prematurely.
	lingerAndDieCancel func()
}

// newSession creates a new session with a given ID within a given context.
func newSession(id rsession.ID, r *SessionRegistry, ctx *ServerContext) (*session, error) {
	serverSessions.Inc()
	startTime := time.Now().UTC()
	rsess := rsession.Session{
		ID: id,
		TerminalParams: rsession.TerminalParams{
			W: teleport.DefaultTerminalWidth,
			H: teleport.DefaultTerminalHeight,
		},
		Login:          ctx.Identity.Login,
		Created:        startTime,
		LastActive:     startTime,
		ServerID:       ctx.srv.ID(),
		Namespace:      r.Srv.GetNamespace(),
		ServerHostname: ctx.srv.GetInfo().GetHostname(),
		ServerAddr:     ctx.ServerConn.LocalAddr().String(),
		ClusterName:    ctx.ClusterName,
	}

	term := ctx.GetTerm()
	if term != nil {
		winsize, err := term.GetWinSize()
		if err != nil {
			return nil, trace.Wrap(err)
		}
		rsess.TerminalParams.W = int(winsize.Width)
		rsess.TerminalParams.H = int(winsize.Height)
	}

	// get the session server where session information lives. if the recording
	// proxy is being used and this is a node, then a discard session server will
	// be returned here.
	sessionServer := r.Srv.GetSessionServer()

	err := sessionServer.CreateSession(rsess)
	if err != nil {
		if trace.IsAlreadyExists(err) {
			// if session already exists, make sure they are compatible
			// Login matches existing login
			existing, err := sessionServer.GetSession(r.Srv.GetNamespace(), id)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			if existing.Login != rsess.Login {
				return nil, trace.AccessDenied(
					"can't switch users from %v to %v for session %v",
					rsess.Login, existing.Login, id)
			}
		}
		// return nil, trace.Wrap(err)
		// No need to abort. Perhaps the auth server is down?
		// Log the error and continue:
		r.log.Errorf("Failed to create new session: %v.", err)
	}

	var policySets []*types.SessionTrackerPolicySet
	for _, role := range ctx.Identity.RoleSet {
		policySet := role.GetSessionPolicySet()
		policySets = append(policySets, &policySet)
	}

	sess := &session{
		log: log.WithFields(log.Fields{
			trace.Component: teleport.Component(teleport.ComponentSession, r.Srv.Component()),
		}),
		id:                             id,
		registry:                       r,
		parties:                        make(map[rsession.ID]*party),
		participants:                   make(map[rsession.ID]*party),
		login:                          ctx.Identity.Login,
		stopC:                          make(chan struct{}),
		startTime:                      startTime,
		serverCtx:                      ctx.srv.Context(),
		access:                         auth.NewSessionAccessEvaluator(policySets, types.SSHSessionKind),
		scx:                            ctx,
		presenceEnabled:                ctx.Identity.Certificate.Extensions[teleport.CertExtensionMFAVerified] != "",
		io:                             NewTermManager(),
		doneCh:                         make(chan struct{}),
		initiator:                      ctx.Identity.TeleportUser,
		displayParticipantRequirements: utils.AsBool(ctx.env[teleport.EnvSSHSessionDisplayParticipantRequirements]),
	}

	sess.io.OnWriteError = func(idString string, err error) {
		if idString == sessionRecorderID {
			sess.log.Error("Failed to write to session recorder, stopping session.")
			// stop in goroutine to avoid deadlock
			go sess.Stop()
		}
	}

	go func() {
		if _, open := <-sess.io.TerminateNotifier(); open {
			err := sess.registry.ForceTerminate(sess.scx)
			if err != nil {
				sess.log.Errorf("Failed to terminate session: %v.", err)
			}
		}
	}()

	if err = sess.trackSession(ctx.Identity.TeleportUser, policySets); err != nil {
		if trace.IsNotImplemented(err) {
			return nil, trace.NotImplemented("Attempted to use Moderated Sessions with an Auth Server below the minimum version of 9.0.0.")
		}
		return nil, trace.Wrap(err)
	}

	return sess, nil
}

// ID returns a string representation of the session ID.
func (s *session) ID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.id.String()
}

// PID returns the PID of the Teleport process under which the shell is running.
func (s *session) PID() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.term.PID()
}

// Recorder returns a StreamWriter which can be used to emit events
// to a session as well as the audit log.
func (s *session) Recorder() events.StreamWriter {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.recorder
}

// Stop ends the active session and forces all clients to disconnect.
// This will trigger background goroutines to complete session cleanup.
func (s *session) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	select {
	case <-s.stopC:
		return
	default:
		close(s.stopC)
	}

	s.BroadcastMessage("Stopping session...")
	s.log.Infof("Stopping session %v.", s.id)

	// close io copy loops
	s.io.Close()

	// Close and kill terminal
	if s.term != nil {
		if err := s.term.Close(); err != nil {
			s.log.Debugf("Failed to close the shell: %v", err)
		}
		if err := s.term.Kill(); err != nil {
			s.log.Debugf("Failed to kill the shell: %v", err)
		}
	}

	// Remove session parties and close client connections.
	for _, p := range s.parties {
		p.closeUnderSessionLock()
	}
}

// Close ends the active session and frees all resources. This should only be called
// by the creator of the session, other closers should use Stop instead. Calling this
// prematurely can result in missing audit events, session recordings, and other
// unexpected errors.
func (s *session) Close() error {
	s.Stop()

	s.BroadcastMessage("Closing session...")
	s.log.Infof("Closing session %v.", s.id)

	serverSessions.Dec()

	// Remove session from registry
	s.registry.removeSession(s)

	// Remove the session from the backend.
	if s.scx.srv.GetSessionServer() != nil {
		err := s.scx.srv.GetSessionServer().DeleteSession(s.getNamespace(), s.id)
		if err != nil {
			s.log.Errorf("Failed to remove active session: %v: %v. "+
				"Access to backend may be degraded, check connectivity to backend.",
				s.id, err)
		}
	}

	// Complete the session recording
	if s.recorder != nil {
		if err := s.recorder.Complete(s.serverCtx); err != nil {
			s.log.WithError(err).Warn("Failed to close recorder.")
		}
	}

	return nil
}

func (s *session) waitOnAccess() error {
	s.io.Off()
	s.BroadcastMessage("Session paused, Waiting for required participants...")

	s.tracker.stateUpdate.L.Lock()
	defer s.tracker.stateUpdate.L.Unlock()
outer:
	for {
		switch s.tracker.state {
		case types.SessionState_SessionStatePending:
			continue
		case types.SessionState_SessionStateTerminated:
			return nil
		case types.SessionState_SessionStateRunning:
			break outer
		}

		s.tracker.stateUpdate.Wait()
	}

	s.BroadcastMessage("Resuming session...")
	s.io.On()
	return nil
}

func (s *session) BroadcastMessage(format string, args ...interface{}) {
	if s.access.IsModerated() && !services.IsRecordAtProxy(s.scx.SessionRecordingConfig.GetMode()) {
		s.io.BroadcastMessage(fmt.Sprintf(format, args...))
	}
}

// emitSessionStartEvent emits a session start event.
func (s *session) emitSessionStartEvent(ctx *ServerContext) {
	sessionStartEvent := &apievents.SessionStart{
		Metadata: apievents.Metadata{
			Type:        events.SessionStartEvent,
			Code:        events.SessionStartCode,
			ClusterName: ctx.ClusterName,
			ID:          uuid.New().String(),
		},
		ServerMetadata: apievents.ServerMetadata{
			ServerID:        ctx.srv.HostUUID(),
			ServerLabels:    ctx.srv.GetInfo().GetAllLabels(),
			ServerHostname:  ctx.srv.GetInfo().GetHostname(),
			ServerAddr:      ctx.ServerConn.LocalAddr().String(),
			ServerNamespace: ctx.srv.GetNamespace(),
		},
		SessionMetadata: apievents.SessionMetadata{
			SessionID: string(s.id),
		},
		UserMetadata: ctx.Identity.GetUserMetadata(),
		ConnectionMetadata: apievents.ConnectionMetadata{
			RemoteAddr: ctx.ServerConn.RemoteAddr().String(),
		},
		SessionRecording: ctx.SessionRecordingConfig.GetMode(),
	}

	if s.term != nil {
		params := s.term.GetTerminalParams()
		sessionStartEvent.TerminalSize = params.Serialize()
	}

	// Local address only makes sense for non-tunnel nodes.
	if !ctx.srv.UseTunnel() {
		sessionStartEvent.ConnectionMetadata.LocalAddr = ctx.ServerConn.LocalAddr().String()
	}

	if err := s.recorder.EmitAuditEvent(ctx.srv.Context(), sessionStartEvent); err != nil {
		s.log.WithError(err).Warn("Failed to emit session start event.")
	}
}

// emitSessionJoinEvent emits a session join event to both the Audit Log as
// well as sending a "x-teleport-event" global request on the SSH connection.
// Must be called under session Lock.
func (s *session) emitSessionJoinEvent(ctx *ServerContext) {
	sessionJoinEvent := &apievents.SessionJoin{
		Metadata: apievents.Metadata{
			Type:        events.SessionJoinEvent,
			Code:        events.SessionJoinCode,
			ClusterName: ctx.ClusterName,
		},
		ServerMetadata: apievents.ServerMetadata{
			ServerID:        ctx.srv.HostUUID(),
			ServerLabels:    ctx.srv.GetInfo().GetAllLabels(),
			ServerNamespace: s.getNamespace(),
			ServerHostname:  s.getHostname(),
			ServerAddr:      ctx.ServerConn.LocalAddr().String(),
		},
		SessionMetadata: apievents.SessionMetadata{
			SessionID: string(ctx.SessionID()),
		},
		UserMetadata: ctx.Identity.GetUserMetadata(),
		ConnectionMetadata: apievents.ConnectionMetadata{
			RemoteAddr: ctx.ServerConn.RemoteAddr().String(),
		},
	}
	// Local address only makes sense for non-tunnel nodes.
	if !ctx.srv.UseTunnel() {
		sessionJoinEvent.ConnectionMetadata.LocalAddr = ctx.ServerConn.LocalAddr().String()
	}

	// Emit session join event to Audit Log.
	if err := s.recorder.EmitAuditEvent(ctx.srv.Context(), sessionJoinEvent); err != nil {
		s.log.WithError(err).Warn("Failed to emit session join event.")
	}

	// Notify all members of the party that a new member has joined over the
	// "x-teleport-event" channel.
	for _, p := range s.parties {
		eventPayload, err := json.Marshal(sessionJoinEvent)
		if err != nil {
			s.log.Warnf("Unable to marshal %v for %v: %v.", events.SessionJoinEvent, p.sconn.RemoteAddr(), err)
			continue
		}
		_, _, err = p.sconn.SendRequest(teleport.SessionEvent, false, eventPayload)
		if err != nil {
			s.log.Warnf("Unable to send %v to %v: %v.", events.SessionJoinEvent, p.sconn.RemoteAddr(), err)
			continue
		}
		s.log.Debugf("Sent %v to %v.", events.SessionJoinEvent, p.sconn.RemoteAddr())
	}
}

// emitSessionLeaveEvent emits a session leave event to both the Audit Log as
// well as sending a "x-teleport-event" global request on the SSH connection.
// Must be called under session Lock.
func (s *session) emitSessionLeaveEvent(ctx *ServerContext) {
	sessionLeaveEvent := &apievents.SessionLeave{
		Metadata: apievents.Metadata{
			Type:        events.SessionLeaveEvent,
			Code:        events.SessionLeaveCode,
			ClusterName: ctx.ClusterName,
		},
		ServerMetadata: apievents.ServerMetadata{
			ServerID:        ctx.srv.HostUUID(),
			ServerLabels:    ctx.srv.GetInfo().GetAllLabels(),
			ServerNamespace: s.getNamespace(),
			ServerHostname:  s.getHostname(),
			ServerAddr:      ctx.ServerConn.LocalAddr().String(),
		},
		SessionMetadata: apievents.SessionMetadata{
			SessionID: string(s.id),
		},
		UserMetadata: ctx.Identity.GetUserMetadata(),
	}

	// Emit session leave event to Audit Log.
	if err := s.recorder.EmitAuditEvent(ctx.srv.Context(), sessionLeaveEvent); err != nil {
		s.log.WithError(err).Warn("Failed to emit session leave event.")
	}

	// Notify all members of the party that a new member has left over the
	// "x-teleport-event" channel.
	for _, p := range s.parties {
		eventPayload, err := utils.FastMarshal(sessionLeaveEvent)
		if err != nil {
			s.log.Warnf("Unable to marshal %v for %v: %v.", events.SessionLeaveEvent, p.sconn.RemoteAddr(), err)
			continue
		}
		_, _, err = p.sconn.SendRequest(teleport.SessionEvent, false, eventPayload)
		if err != nil {
			s.log.Warnf("Unable to send %v to %v: %v.", events.SessionLeaveEvent, p.sconn.RemoteAddr(), err)
			continue
		}
		s.log.Debugf("Sent %v to %v.", events.SessionLeaveEvent, p.sconn.RemoteAddr())
	}
}

// emitSessionEndEvent emits a session end event.
func (s *session) emitSessionEndEvent() {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := s.scx
	if s.endingContext != nil {
		ctx = s.endingContext
	}

	start, end := s.startTime, time.Now().UTC()
	sessionEndEvent := &apievents.SessionEnd{
		Metadata: apievents.Metadata{
			Type:        events.SessionEndEvent,
			Code:        events.SessionEndCode,
			ClusterName: ctx.ClusterName,
		},
		ServerMetadata: apievents.ServerMetadata{
			ServerID:        ctx.srv.HostUUID(),
			ServerLabels:    ctx.srv.GetInfo().GetAllLabels(),
			ServerNamespace: s.getNamespace(),
			ServerHostname:  s.getHostname(),
			ServerAddr:      ctx.ServerConn.LocalAddr().String(),
		},
		SessionMetadata: apievents.SessionMetadata{
			SessionID: string(s.id),
		},
		UserMetadata:      ctx.Identity.GetUserMetadata(),
		EnhancedRecording: s.hasEnhancedRecording,
		Interactive:       s.term != nil,
		StartTime:         start,
		EndTime:           end,
		SessionRecording:  ctx.SessionRecordingConfig.GetMode(),
	}

	for _, p := range s.participants {
		sessionEndEvent.Participants = append(sessionEndEvent.Participants, p.user)
	}

	// If there are 0 participants, this is an exec session.
	// Use the user from the session context.
	if len(s.participants) == 0 {
		sessionEndEvent.Participants = []string{s.scx.Identity.TeleportUser}
	}

	if err := s.recorder.EmitAuditEvent(ctx.srv.Context(), sessionEndEvent); err != nil {
		s.log.WithError(err).Warn("Failed to emit session end event.")
	}
}

func (s *session) setEndingContext(ctx *ServerContext) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.endingContext = ctx
}

func (s *session) launch(ctx *ServerContext) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.log.Debugf("Launching session %v.", s.id)
	s.BroadcastMessage("Connecting to %v over SSH", ctx.srv.GetInfo().GetHostname())

	s.io.On()

	if err := s.tracker.updateState(types.SessionState_SessionStateRunning); err != nil {
		s.log.Warnf("Failed to set tracker state to %v", types.SessionState_SessionStateRunning)
	}

	// If the identity is verified with an MFA device, we enabled MFA-based presence for the session.
	if s.presenceEnabled {
		go func() {
			ticker := time.NewTicker(PresenceVerifyInterval)
			defer ticker.Stop()
		outer:
			for {
				select {
				case <-ticker.C:
					err := s.checkPresence()
					if err != nil {
						s.log.WithError(err).Error("Failed to check presence, terminating session as a security measure")
						s.Stop()
					}
				case <-s.stopC:
					break outer
				}
			}
		}()
	}

	// copy everything from the pty to the writer. this lets us capture all input
	// and output of the session (because input is echoed to stdout in the pty).
	// the writer contains multiple writers: the session logger and a direct
	// connection to members of the "party" (other people in the session).
	s.term.AddParty(1)
	go func() {
		defer s.term.AddParty(-1)

		// once everything has been copied, notify the goroutine below. if this code
		// is running in a teleport node, when the exec.Cmd is done it will close
		// the PTY, allowing io.Copy to return. if this is a teleport forwarding
		// node, when the remote side closes the channel (which is what s.term.PTY()
		// returns) io.Copy will return.
		defer close(s.doneCh)

		_, err := io.Copy(s.io, s.term.PTY())
		s.log.Debugf("Copying from PTY to writer completed with error %v.", err)
	}()

	s.term.AddParty(1)
	go func() {
		defer s.term.AddParty(-1)

		_, err := io.Copy(s.term.PTY(), s.io)
		s.log.Debugf("Copying from reader to PTY completed with error %v.", err)
	}()

	// wait for exec.Cmd (or receipt of "exit-status" for a forwarding node),
	// once it is received wait for the io.Copy above to finish, then broadcast
	// the "exit-status" to the client.
	go func() {
		result, err := s.term.Wait()
		if err != nil {
			ctx.Errorf("Received error waiting for the interactive session %v to finish: %v.", s.id, err)
		}

		// wait for copying from the pty to be complete or a timeout before
		// broadcasting the result (which will close the pty) if it has not been
		// closed already.
		select {
		case <-time.After(defaults.WaitCopyTimeout):
			s.log.Errorf("Timed out waiting for PTY copy to finish, session data for %v may be missing.", s.id)
		case <-s.doneCh:
		}

		ctx.srv.GetRestrictedSessionManager().CloseSession(s.bpfContext, s.cgroupID)

		// Close the BPF recording session. If BPF was not configured, not available,
		// or running in a recording proxy, this is simply a NOP.
		err = ctx.srv.GetBPF().CloseSession(s.bpfContext)
		if err != nil {
			ctx.Errorf("Failed to close enhanced recording (interactive) session: %v: %v.", s.id, err)
		}

		if ctx.ExecRequest.GetCommand() != "" {
			emitExecAuditEvent(ctx, ctx.ExecRequest.GetCommand(), err)
		}

		if result != nil {
			if err := s.registry.broadcastResult(s.id, *result); err != nil {
				s.log.Warningf("Failed to broadcast session result: %v", err)
			}
		}

		s.emitSessionEndEvent()
		s.Close()
	}()

	return nil
}

// startInteractive starts a new interactive process (or a shell) in the
// current session.
func (s *session) startInteractive(ch ssh.Channel, ctx *ServerContext) error {
	// create a new "party" (connected client)
	p := newParty(s, types.SessionPeerMode, ch, ctx)

	rec, err := newRecorder(s, ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	s.recorder = rec

	// allocate a terminal or take the one previously allocated via a
	// seaprate "allocate TTY" SSH request
	if ctx.GetTerm() != nil {
		s.term = ctx.GetTerm()
		ctx.SetTerm(nil)
	} else {
		if s.term, err = NewTerminal(ctx); err != nil {
			ctx.Infof("Unable to allocate new terminal: %v", err)
			return trace.Wrap(err)
		}
	}

	// Emit a session.start event for the interactive session.
	s.emitSessionStartEvent(ctx)

	inReader, inWriter := io.Pipe()
	s.inWriter = inWriter
	s.io.AddReader("reader", inReader)
	s.io.AddWriter(sessionRecorderID, utils.WriteCloserWithContext(ctx.srv.Context(), s.recorder))
	s.BroadcastMessage("Creating session with ID: %v...", s.id)
	s.BroadcastMessage(SessionControlsInfoBroadcast)

	if err := s.term.Run(); err != nil {
		ctx.Errorf("Unable to run shell command: %v.", err)
		return trace.ConvertSystemError(err)
	}

	if err := s.addParty(p, types.SessionPeerMode); err != nil {
		return trace.Wrap(err)
	}

	// Open a BPF recording session. If BPF was not configured, not available,
	// or running in a recording proxy, OpenSession is a NOP.
	s.bpfContext = &bpf.SessionContext{
		Context:   ctx.srv.Context(),
		PID:       s.term.PID(),
		Emitter:   s.recorder,
		Namespace: ctx.srv.GetNamespace(),
		SessionID: s.id.String(),
		ServerID:  ctx.srv.HostUUID(),
		Login:     ctx.Identity.Login,
		User:      ctx.Identity.TeleportUser,
		Events:    ctx.Identity.RoleSet.EnhancedRecordingSet(),
	}
	s.cgroupID, err = ctx.srv.GetBPF().OpenSession(s.bpfContext)
	if err != nil {
		ctx.Errorf("Failed to open enhanced recording (interactive) session: %v: %v.", s.id, err)
		return trace.Wrap(err)
	}

	// If a cgroup ID was assigned then enhanced session recording was enabled.
	if s.cgroupID > 0 {
		s.hasEnhancedRecording = true
		ctx.srv.GetRestrictedSessionManager().OpenSession(s.bpfContext, s.cgroupID)
	}

	ctx.Debug("Waiting for continue signal")

	// Process has been placed in a cgroup, continue execution.
	s.term.Continue()

	ctx.Debug("Got continue signal")

	// Start a heartbeat that marks this session as active with current members
	// of party in the backend.
	go s.heartbeat(ctx)
	return nil
}

// newRecorder creates a new events.StreamWriter to be used as the recorder
// of the passed in session.
func newRecorder(s *session, ctx *ServerContext) (events.StreamWriter, error) {
	// Nodes discard events in cases when proxies are already recording them.
	if s.registry.Srv.Component() == teleport.ComponentNode &&
		services.IsRecordAtProxy(ctx.SessionRecordingConfig.GetMode()) {
		return &events.DiscardStream{}, nil
	}

	streamer, err := s.newStreamer(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	rec, err := events.NewAuditWriter(events.AuditWriterConfig{
		// Audit stream is using server context, not session context,
		// to make sure that session is uploaded even after it is closed
		Context:      ctx.srv.Context(),
		Streamer:     streamer,
		SessionID:    s.id,
		Clock:        s.registry.clock,
		Namespace:    ctx.srv.GetNamespace(),
		ServerID:     ctx.srv.HostUUID(),
		RecordOutput: ctx.SessionRecordingConfig.GetMode() != types.RecordOff,
		Component:    teleport.Component(teleport.ComponentSession, ctx.srv.Component()),
		ClusterName:  ctx.ClusterName,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return rec, nil
}

func (s *session) startExec(channel ssh.Channel, ctx *ServerContext) error {
	rec, err := newRecorder(s, ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	s.recorder = rec

	// Emit a session.start event for the exec session.
	s.emitSessionStartEvent(ctx)

	// Start execution. If the program failed to start, send that result back.
	// Note this is a partial start. Teleport will have re-exec'ed itself and
	// wait until it's been placed in a cgroup and told to continue.
	result, err := ctx.ExecRequest.Start(channel)
	if err != nil {
		return trace.Wrap(err)
	}
	if result != nil {
		ctx.Debugf("Exec request (%v) result: %v.", ctx.ExecRequest, result)
		ctx.SendExecResult(*result)
	}

	// Open a BPF recording session. If BPF was not configured, not available,
	// or running in a recording proxy, OpenSession is a NOP.
	sessionContext := &bpf.SessionContext{
		Context:   ctx.srv.Context(),
		PID:       ctx.ExecRequest.PID(),
		Emitter:   s.recorder,
		Namespace: ctx.srv.GetNamespace(),
		SessionID: string(s.id),
		ServerID:  ctx.srv.HostUUID(),
		Login:     ctx.Identity.Login,
		User:      ctx.Identity.TeleportUser,
		Events:    ctx.Identity.RoleSet.EnhancedRecordingSet(),
	}
	cgroupID, err := ctx.srv.GetBPF().OpenSession(sessionContext)
	if err != nil {
		ctx.Errorf("Failed to open enhanced recording (exec) session: %v: %v.", ctx.ExecRequest.GetCommand(), err)
		return trace.Wrap(err)
	}

	// If a cgroup ID was assigned then enhanced session recording was enabled.
	if cgroupID > 0 {
		s.hasEnhancedRecording = true
		ctx.srv.GetRestrictedSessionManager().OpenSession(sessionContext, cgroupID)
	}

	// Process has been placed in a cgroup, continue execution.
	ctx.ExecRequest.Continue()

	// Process is running, wait for it to stop.
	go func() {
		result = ctx.ExecRequest.Wait()
		if result != nil {
			ctx.SendExecResult(*result)
		}

		// Wait a little bit to let all events filter through before closing the
		// BPF session so everything can be recorded.
		time.Sleep(2 * time.Second)

		ctx.srv.GetRestrictedSessionManager().CloseSession(sessionContext, cgroupID)

		// Close the BPF recording session. If BPF was not configured, not available,
		// or running in a recording proxy, this is simply a NOP.
		err = ctx.srv.GetBPF().CloseSession(sessionContext)
		if err != nil {
			ctx.Errorf("Failed to close enhanced recording (exec) session: %v: %v.", s.id, err)
		}

		s.emitSessionEndEvent()
		s.Close()
	}()

	return nil
}

// newStreamer returns sync or async streamer based on the configuration
// of the server and the session, sync streamer sends the events
// directly to the auth server and blocks if the events can not be received,
// async streamer buffers the events to disk and uploads the events later
func (s *session) newStreamer(ctx *ServerContext) (events.Streamer, error) {
	mode := ctx.SessionRecordingConfig.GetMode()
	if services.IsRecordSync(mode) {
		s.log.Debugf("Using sync streamer for session %v.", s.id)
		return ctx.srv, nil
	}

	if ctx.IsTestStub {
		s.log.Debugf("Using discard streamer for test")
		return events.NewDiscardEmitter(), nil
	}

	s.log.Debugf("Using async streamer for session %v.", s.id)
	fileStreamer, err := filesessions.NewStreamer(sessionsStreamingUploadDir(ctx))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// TeeStreamer sends non-print and non disk events
	// to the audit log in async mode, while buffering all
	// events on disk for further upload at the end of the session.
	return events.NewTeeStreamer(fileStreamer, ctx.srv), nil
}

func sessionsStreamingUploadDir(ctx *ServerContext) string {
	return filepath.Join(
		ctx.srv.GetDataDir(), teleport.LogsDir, teleport.ComponentUpload,
		events.StreamingLogsDir, ctx.srv.GetNamespace(),
	)
}

func (s *session) broadcastResult(r ExecResult) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, p := range s.parties {
		p.ctx.SendExecResult(r)
	}
}

func (s *session) String() string {
	return fmt.Sprintf("session(id=%v, parties=%v)", s.id, len(s.parties))
}

// removePartyUnderLock removes the party from the in-memory map that holds all party members
// and closes their underlying ssh channels. This may also trigger the session to end
// if the party is the last in the session or has policies that dictate it to end.
// Must be called under session Lock.
func (s *session) removePartyUnderLock(p *party) error {
	s.log.Infof("Removing party %v from session %v", p, s.id)

	// Remove participant from in-memory map of party members.
	delete(s.parties, p.id)

	// Update session tracker
	if err := s.tracker.removeParty(p.user); err != nil {
		return trace.Wrap(err)
	}

	// Remove party for the term writer
	s.io.DeleteWriter(string(p.id))

	canRun, policyOptions, err := s.checkIfStart()
	if err != nil {
		return trace.Wrap(err)
	}

	s.tracker.stateUpdate.L.Lock()
	defer s.tracker.stateUpdate.L.Unlock()

	if !canRun && s.tracker.state == types.SessionState_SessionStateRunning {
		if policyOptions.TerminateOnLeave {
			// Force termination in goroutine to avoid deadlock
			go s.registry.ForceTerminate(s.scx)
			return nil
		}

		err := s.tracker.updateStateUnderLock(types.SessionState_SessionStatePending)
		if err != nil {
			s.log.Warnf("Failed to set tracker state to %v", types.SessionState_SessionStatePending)
		}

		go s.waitOnAccess()
	}

	s.BroadcastMessage("User %v left the session.", p.user)

	// Emit session leave event to both the Audit Log as well as over the
	// "x-teleport-event" channel in the SSH connection.
	s.emitSessionLeaveEvent(p.ctx)

	// If the leaving party was the last one in the session, start the lingerAndDie
	// goroutine. Parties that join during the linger duration will cancel the
	// goroutine to prevent the session from ending with active parties.
	if len(s.parties) == 0 && !s.isStopped() {
		ctx, cancel := context.WithCancel(s.serverCtx)
		s.lingerAndDieCancel = cancel
		go s.lingerAndDie(ctx, p)
	}

	return nil
}

func (s *session) isStopped() bool {
	select {
	case <-s.stopC:
		return true
	default:
		return false
	}
}

// lingerAndDie will let the party-less session linger for a short
// duration, and then die if no parties have joined.
func (s *session) lingerAndDie(ctx context.Context, party *party) {
	s.log.Debugf("Session %v has no active party members.", s.id)

	select {
	case <-s.registry.clock.After(defaults.SessionIdlePeriod):
		s.log.Infof("Session %v will be garbage collected.", s.id)

		// set closing context to the leaving party to show who ended the session.
		s.setEndingContext(party.ctx)

		// Stop the session, and let the background processes
		// complete cleanup and close the session.
		s.Stop()
	case <-ctx.Done():
		s.log.Infof("Session %v has become active again.", s.id)
		return
	case <-s.stopC:
		return
	}
}

func (s *session) getNamespace() string {
	return s.registry.Srv.GetNamespace()
}

func (s *session) getHostname() string {
	return s.registry.Srv.GetInfo().GetHostname()
}

// exportPartyMembers exports participants in the in-memory map of party
// members.
func (s *session) exportPartyMembers() []rsession.Party {
	s.mu.Lock()
	defer s.mu.Unlock()

	var partyList []rsession.Party
	for _, p := range s.parties {
		partyList = append(partyList, rsession.Party{
			ID:         p.id,
			User:       p.user,
			ServerID:   p.serverID,
			RemoteAddr: p.site,
			LastActive: p.getLastActive(),
		})
	}

	return partyList
}

// heartbeat will loop as long as the session is not closed and mark it as
// active and update the list of party members. If the session are recorded at
// the proxy, then this function does nothing as it's counterpart
// in the proxy will do this work.
func (s *session) heartbeat(ctx *ServerContext) {
	// If sessions are being recorded at the proxy, an identical version of this
	// goroutine is running in the proxy, which means it does not need to run here.
	if services.IsRecordAtProxy(ctx.SessionRecordingConfig.GetMode()) &&
		s.registry.Srv.Component() == teleport.ComponentNode {
		return
	}

	// If no session server (endpoint interface for active sessions) is passed in
	// (for example Teleconsole does this) then nothing to sync.
	sessionServer := s.registry.Srv.GetSessionServer()
	if sessionServer == nil {
		return
	}

	s.log.Debugf("Starting poll and sync of terminal size to all parties.")
	defer s.log.Debugf("Stopping poll and sync of terminal size to all parties.")

	tickerCh := time.NewTicker(defaults.SessionRefreshPeriod)
	defer tickerCh.Stop()

	// Loop as long as the session is active, updating the session in the backend.
	for {
		select {
		case <-tickerCh.C:
			partyList := s.exportPartyMembers()

			err := sessionServer.UpdateSession(rsession.UpdateRequest{
				Namespace: s.getNamespace(),
				ID:        s.id,
				Parties:   &partyList,
			})
			if err != nil {
				s.log.Warnf("Unable to update session %v as active: %v", s.id, err)
			}
		case <-s.stopC:
			return
		}
	}
}

func (s *session) checkPresence() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tracker, err := s.tracker.get()
	if err != nil {
		return trace.Wrap(err)
	}

	for _, participant := range tracker.GetParticipants() {
		if participant.User == s.initiator {
			continue
		}

		if participant.Mode == string(types.SessionModeratorMode) && time.Now().UTC().After(participant.LastActive.Add(PresenceMaxDifference)) {
			s.log.Warnf("Participant %v is not active, kicking.", participant.ID)
			party := s.parties[rsession.ID(participant.ID)]
			if party != nil {
				party.closeUnderSessionLock()
			}
		}
	}

	return nil
}

func (s *session) checkIfStart() (bool, auth.PolicyOptions, error) {
	var participants []auth.SessionAccessContext

	for _, party := range s.parties {
		if party.ctx.Identity.TeleportUser == s.initiator {
			continue
		}

		participants = append(participants, auth.SessionAccessContext{
			Username: party.ctx.Identity.TeleportUser,
			Roles:    party.ctx.Identity.RoleSet,
			Mode:     party.mode,
		})
	}

	shouldStart, policyOptions, err := s.access.FulfilledFor(participants)
	if err != nil {
		return false, auth.PolicyOptions{}, trace.Wrap(err)
	}

	return shouldStart, policyOptions, nil
}

// addParty is called when a new party joins the session.
func (s *session) addParty(p *party, mode types.SessionParticipantMode) error {
	if s.login != p.login {
		return trace.AccessDenied(
			"can't switch users from %v to %v for session %v",
			s.login, p.login, s.id)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.parties) == 0 {
		canStart, _, err := s.checkIfStart()
		if err != nil {
			return trace.Wrap(err)
		}

		if !canStart && services.IsRecordAtProxy(p.ctx.SessionRecordingConfig.GetMode()) {
			go s.Stop()
			return trace.AccessDenied("session requires additional moderation but is in proxy-record mode")
		}
	}

	// Cancel lingerAndDie goroutine if one is running.
	if s.lingerAndDieCancel != nil {
		s.lingerAndDieCancel()
		s.lingerAndDieCancel = nil
	}

	// Adds participant to in-memory map of party members.
	s.parties[p.id] = p
	s.participants[p.id] = p
	p.ctx.AddCloser(p)

	if err := s.tracker.addParty(p); err != nil {
		return trace.Wrap(err)
	}

	// Write last chunk (so the newly joined parties won't stare at a blank
	// screen).
	if _, err := p.Write(s.io.GetRecentHistory()); err != nil {
		return trace.Wrap(err)
	}

	// Register this party as one of the session writers (output will go to it).
	s.io.AddWriter(string(p.id), p)
	s.term.AddParty(1)

	s.BroadcastMessage("User %v joined the session.", p.user)
	s.log.Infof("New party %v joined session: %v", p.String(), s.id)

	if mode == types.SessionPeerMode {
		// This goroutine keeps pumping party's input into the session.
		go func() {
			defer s.term.AddParty(-1)
			_, err := io.Copy(s.inWriter, p)
			s.log.Debugf("Copying from Party %v to session writer completed with error %v.", p.id, err)
		}()
	}

	s.tracker.stateUpdate.L.Lock()
	defer s.tracker.stateUpdate.L.Unlock()
	if s.tracker.state == types.SessionState_SessionStatePending {
		canStart, _, err := s.checkIfStart()
		if err != nil {
			return trace.Wrap(err)
		}

		if canStart {
			if !s.started {
				s.started = true

				go func() {
					err := s.launch(s.scx)
					if err != nil {
						s.log.Errorf("Failed to launch session %v: %v", s.id, err)
					}
				}()
			} else {
				err := s.tracker.updateStateUnderLock(types.SessionState_SessionStateRunning)
				if err != nil {
					s.log.Warnf("Failed to set tracker state to %v", types.SessionState_SessionStateRunning)
				}
			}
		} else if !s.started {
			base := "Waiting for required participants..."

			if s.displayParticipantRequirements {
				s.BroadcastMessage(base+"\r\n%v", s.access.PrettyRequirementsList())
			} else {
				s.BroadcastMessage(base)
			}
		}
	}

	return nil
}

func (s *session) join(ch ssh.Channel, ctx *ServerContext, mode types.SessionParticipantMode) (*party, error) {
	if ctx.Identity.TeleportUser != s.initiator {
		roles := []types.Role(ctx.Identity.RoleSet)
		accessContext := auth.SessionAccessContext{
			Roles: roles,
		}

		modes, err := s.access.CanJoin(accessContext)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		if !auth.SliceContainsMode(modes, mode) {
			return nil, trace.AccessDenied("insufficient permissions to join session %v", s.id)
		}

		if s.presenceEnabled {
			_, err := ch.SendRequest(teleport.MFAPresenceRequest, false, nil)
			if err != nil {
				return nil, trace.WrapWithMessage(err, "failed to send MFA presence request")
			}
		}
	}

	p := newParty(s, mode, ch, ctx)
	if err := s.addParty(p, mode); err != nil {
		return nil, trace.Wrap(err)
	}

	// Emit session join event to both the Audit Log as well as over the
	// "x-teleport-event" channel in the SSH connection.
	s.emitSessionJoinEvent(p.ctx)

	return p, nil
}

func (s *session) getParties() (parties []*party) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.parties {
		parties = append(parties, p)
	}
	return parties
}

type party struct {
	sync.Mutex

	log        *log.Entry
	login      string
	user       string
	serverID   string
	site       string
	id         rsession.ID
	s          *session
	sconn      *ssh.ServerConn
	ch         ssh.Channel
	ctx        *ServerContext
	lastActive time.Time
	mode       types.SessionParticipantMode
	closeOnce  sync.Once
}

func newParty(s *session, mode types.SessionParticipantMode, ch ssh.Channel, ctx *ServerContext) *party {
	return &party{
		log: log.WithFields(log.Fields{
			trace.Component: teleport.Component(teleport.ComponentSession, ctx.srv.Component()),
		}),
		user:     ctx.Identity.TeleportUser,
		login:    ctx.Identity.Login,
		serverID: s.registry.Srv.ID(),
		site:     ctx.ServerConn.RemoteAddr().String(),
		id:       rsession.NewID(),
		ch:       ch,
		ctx:      ctx,
		s:        s,
		sconn:    ctx.ServerConn,
		mode:     mode,
	}
}

func (p *party) updateActivity() {
	p.Lock()
	defer p.Unlock()
	p.lastActive = time.Now()
}

func (p *party) getLastActive() time.Time {
	p.Lock()
	defer p.Unlock()
	return p.lastActive
}

func (p *party) Read(bytes []byte) (int, error) {
	p.updateActivity()
	return p.ch.Read(bytes)
}

func (p *party) Write(bytes []byte) (int, error) {
	return p.ch.Write(bytes)
}

func (p *party) String() string {
	return fmt.Sprintf("%v party(id=%v)", p.ctx, p.id)
}

// Close is called when the party's session ctx is closed.
func (p *party) Close() error {
	p.s.mu.Lock()
	defer p.s.mu.Unlock()
	p.closeUnderSessionLock()
	return nil
}

// closeUnderSessionLock closes the party, and removes it from it's session.
// Must be called under session Lock.
func (p *party) closeUnderSessionLock() {
	p.closeOnce.Do(func() {
		p.log.Infof("Closing party %v", p.id)
		// Remove party from its session
		if err := p.s.removePartyUnderLock(p); err != nil {
			p.ctx.Errorf("Failed to remove party %v: %v", p.id, err)
		}
		p.ch.Close()
	})
}

// trackSession creates a new session tracker for the ssh session.
// While ctx is open, the session tracker's expiration will be extended
// on an interval. Once the ctx is closed, the session tracker's state
// will be updated to terminated.
func (s *session) trackSession(teleportUser string, policySet []*types.SessionTrackerPolicySet) error {
	s.log.Debugf("Starting session tracker for session %v", s.id)

	s.tracker = &sessionTrackerServiceWithCond{
		closeCtx:              s.serverCtx,
		sessID:                s.ID(),
		log:                   s.log,
		SessionTrackerService: s.registry.SessionTrackerService,
		state:                 types.SessionState_SessionStatePending,
		stateUpdate:           sync.NewCond(&sync.Mutex{}),
	}

	initiator := &types.Participant{
		ID:         teleportUser,
		User:       teleportUser,
		LastActive: s.registry.clock.Now(),
	}

	reason := s.scx.env[teleport.EnvSSHSessionReason]
	var invited []string

	if s.scx.env[teleport.EnvSSHSessionInvited] != "" {
		err := json.Unmarshal([]byte(s.scx.env[teleport.EnvSSHSessionInvited]), &invited)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	tracker, err := types.NewSessionTracker(types.SessionTrackerSpecV1{
		SessionID:    s.id.String(),
		Kind:         string(types.SSHSessionKind),
		State:        types.SessionState_SessionStatePending,
		Hostname:     s.registry.Srv.GetInfo().GetHostname(),
		Address:      s.scx.ServerConn.LocalAddr().String(),
		ClusterName:  s.scx.ClusterName,
		Login:        s.login,
		Participants: []types.Participant{*initiator},
		HostUser:     initiator.User,
		Reason:       reason,
		Invited:      invited,
		HostPolicies: policySet,
		Created:      s.registry.clock.Now(),
	})
	if err != nil {
		return trail.FromGRPC(err)
	}

	go func() {
		ticker := s.registry.clock.NewTicker(defaults.SessionTrackerExpirationUpdateInterval)
		defer ticker.Stop()
		if err := services.TrackSession(s.serverCtx, s.tracker, tracker, ticker, s.stopC); err != nil {
			s.log.Debugf("Error tracking session state for session %v", s.id)
		}
	}()

	return nil
}

// sessionTrackerServiceWithCond is a tracker service for a specific session.
// state updates are controlled with a sync.Cond.
type sessionTrackerServiceWithCond struct {
	services.SessionTrackerService

	closeCtx context.Context
	log      *log.Entry
	sessID   string

	state       types.SessionState
	stateUpdate *sync.Cond
}

// UpdateSessionTracker updates the session tracker, locking
// on the stateUpdate condition for state updates.
func (s *sessionTrackerServiceWithCond) UpdateSessionTracker(ctx context.Context, req *proto.UpdateSessionTrackerRequest) error {
	if req.GetUpdateState() != nil {
		return s.updateState(req.GetUpdateState().GetState())
	}
	return s.SessionTrackerService.UpdateSessionTracker(ctx, req)
}

func (s *sessionTrackerServiceWithCond) get() (types.SessionTracker, error) {
	sess, err := s.GetSessionTracker(s.closeCtx, s.sessID)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return sess, nil
}
func (s *sessionTrackerServiceWithCond) addParty(p *party) error {
	s.log.Debugf("Tracking participant: %v", p.user)
	err := services.AddSessionTrackerParticipant(s.closeCtx, s, s.sessID, &types.Participant{
		ID:         p.user,
		User:       p.user,
		Mode:       string(p.mode),
		LastActive: time.Now().UTC(),
	})
	return trace.Wrap(err)
}

func (s *sessionTrackerServiceWithCond) removeParty(partyID string) error {
	s.log.Debugf("Not tracking participant: %v", partyID)
	err := services.RemoveSessionTrackerParticipant(s.closeCtx, s, s.sessID, partyID)
	return trace.Wrap(err)
}

func (s *sessionTrackerServiceWithCond) updateState(state types.SessionState) error {
	s.stateUpdate.L.Lock()
	defer s.stateUpdate.L.Unlock()

	err := s.updateStateUnderLock(state)
	return trace.Wrap(err)
}

// updateStateUnderLock Must be called under stateUpdate lock
func (s *sessionTrackerServiceWithCond) updateStateUnderLock(state types.SessionState) error {
	s.state = state
	s.stateUpdate.Broadcast()

	err := services.UpdateSessionTrackerState(s.closeCtx, s.SessionTrackerService, s.sessID, state)
	return trace.Wrap(err)
}
