/*
Copyright 2015-2017 Gravitational, Inc.

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

// Package service implements teleport running service, takes care
// of initialization, cleanup and shutdown procedures
package service

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/boltbk"
	"github.com/gravitational/teleport/lib/backend/dir"
	"github.com/gravitational/teleport/lib/backend/dynamo"
	"github.com/gravitational/teleport/lib/backend/etcdbk"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/limiter"
	"github.com/gravitational/teleport/lib/multiplexer"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/srv/regular"
	"github.com/gravitational/teleport/lib/sshca"
	"github.com/gravitational/teleport/lib/state"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/web"
	"github.com/gravitational/trace"

	"github.com/jonboulle/clockwork"
	"github.com/pborman/uuid"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithFields(logrus.Fields{
	trace.Component: teleport.ComponentProcess,
})

const (
	// ProxyReverseTunnelServerEvent is generated supervisor when proxy
	// has initialized reverse tunnel server
	ProxyReverseTunnelServerEvent = "ProxyReverseTunnelServer"
	// ProxyWebServerEvent is generated supervisor when proxy
	// has initialized web tunnel server
	ProxyWebServerEvent = "ProxyWebServer"
	// ProxyIdentityEvent is generated by supervisor when proxy's identity has been initialized
	ProxyIdentityEvent = "ProxyIdentity"
	// SSHIdentityEvent is generated when node's identity has been received
	SSHIdentityEvent = "SSHIdentity"
	// TeleportExitEvent is generated when someone is askign Teleport Process to close
	// all listening sockets and exit
	TeleportExitEvent = "TeleportExit"
	// AuthIdentityEvent is generated when auth's identity has been initialized
	AuthIdentityEvent = "AuthIdentity"
)

// RoleConfig is a configuration for a server role (either proxy or node)
type RoleConfig struct {
	DataDir     string
	HostUUID    string
	HostName    string
	AuthServers []utils.NetAddr
	Auth        AuthConfig
	Console     io.Writer
}

// Connector has all resources process needs to connect
// to other parts of the cluster: client and identity
type Connector struct {
	Identity *auth.Identity
	Client   *auth.Client
}

// TeleportProcess structure holds the state of the Teleport daemon, controlling
// execution and configuration of the teleport services: ssh, auth and proxy.
type TeleportProcess struct {
	clockwork.Clock
	sync.Mutex
	Supervisor
	Config *Config
	// localAuth has local auth server listed in case if this process
	// has started with auth server role enabled
	localAuth *auth.AuthServer
	// backend is the process' backend
	backend backend.Backend
	// auditLog is the initialized audit log
	auditLog events.IAuditLog

	// identities of this process (credentials to auth sever, basically)
	Identities map[teleport.Role]*auth.Identity
}

// GetAuthServer returns the process' auth server
func (process *TeleportProcess) GetAuthServer() *auth.AuthServer {
	return process.localAuth
}

// GetAuditLog returns the process' audit log
func (process *TeleportProcess) GetAuditLog() events.IAuditLog {
	return process.auditLog
}

// GetBackend returns the process' backend
func (process *TeleportProcess) GetBackend() backend.Backend {
	return process.backend
}

func (process *TeleportProcess) findStaticIdentity(id auth.IdentityID) (*auth.Identity, error) {
	for i := range process.Config.Identities {
		identity := process.Config.Identities[i]
		if identity.ID.Equals(id) {
			return identity, nil
		}
	}
	return nil, trace.NotFound("identity %v not found", &id)
}

// readIdentity reads identity from disk and resets the local state
func (process *TeleportProcess) readIdentity(role teleport.Role) (*auth.Identity, error) {
	process.Lock()
	defer process.Unlock()

	id := auth.IdentityID{HostUUID: process.Config.HostUUID, Role: role}
	identity, err := auth.ReadIdentity(process.Config.DataDir, id)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	process.Identities[role] = identity
	return identity, nil
}

// GetIdentity returns the process identity (credentials to the auth server) for a given
// teleport Role. A teleport process can have any combination of 3 roles: auth, node, proxy
// and they have their own identities
func (process *TeleportProcess) GetIdentity(role teleport.Role) (i *auth.Identity, err error) {
	var found bool

	process.Lock()
	defer process.Unlock()

	i, found = process.Identities[role]
	if found {
		return i, nil
	}

	id := auth.IdentityID{HostUUID: process.Config.HostUUID, Role: role}
	i, err = auth.ReadIdentity(process.Config.DataDir, id)
	if err != nil {
		if trace.IsNotFound(err) {
			// try to locate static identity provided in the file
			i, err = process.findStaticIdentity(id)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			log.Infof("Found static identity %v in the config file, writing to disk.", &id)
			if err = auth.WriteIdentity(process.Config.DataDir, i); err != nil {
				return nil, trace.Wrap(err)
			}
		} else {
			return nil, trace.Wrap(err)
		}
	}
	process.Identities[role] = i
	return i, nil
}

// connectToAuthService attempts to login into the auth servers specified in the
// configuration. Returns 'true' if successful
func (process *TeleportProcess) connectToAuthService(role teleport.Role, additionalPrincipals []string) (*Connector, error) {
	identity, err := process.GetIdentity(role)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsConfig, err := identity.TLSConfig()
	if err != nil {
		if !trace.IsNotFound(err) {
			return nil, trace.Wrap(err)
		}
		// connect using legacy SSH and get new set of TLS credentials
		storage := utils.NewFileAddrStorage(
			filepath.Join(process.Config.DataDir, "authservers.json"))

		authUser := identity.Cert.ValidPrincipals[0]
		log.Infof("Connecting to the cluster as %v to fetch TLS certificates.", authUser)
		authClient, err := auth.NewTunClient(
			string(role),
			process.Config.AuthServers,
			authUser,
			[]ssh.AuthMethod{ssh.PublicKeys(identity.KeySigner)},
			auth.TunClientStorage(storage),
			auth.TunDisableRefresh(),
		)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		defer authClient.Close()
		if err := auth.ReRegister(process.Config.DataDir, authClient, identity.ID, additionalPrincipals); err != nil {
			return nil, trace.Wrap(err)
		}
		if identity, err = process.readIdentity(role); err != nil {
			return nil, trace.Wrap(err)
		}
		tlsConfig, err = identity.TLSConfig()
		if err != nil {
			return nil, trace.Wrap(err)
		}
		log.WithFields(logrus.Fields{"host": identity.ID.HostUUID, "role": identity.ID.Role}).Infof("Received new TLS identity.")
	}
	log.Infof("Connecting to the cluster %v with TLS client certificate.", identity.ClusterName)
	client, err := auth.NewTLSClient(process.Config.AuthServers, tlsConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if len(additionalPrincipals) != 0 && !identity.HasPrincipals(additionalPrincipals) {
		log.Infof("Identity %v needs principals %v, going to re-register.", identity.ID, additionalPrincipals)
		if err := auth.ReRegister(process.Config.DataDir, client, identity.ID, additionalPrincipals); err != nil {
			return nil, trace.Wrap(err)
		}
		if identity, err = process.readIdentity(role); err != nil {
			return nil, trace.Wrap(err)
		}
		tlsConfig, err = identity.TLSConfig()
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	// success ? we're logged in!
	return &Connector{Client: client, Identity: identity}, nil
}

// NewTeleport takes the daemon configuration, instantiates all required services
// and starts them under a supervisor, returning the supervisor object
func NewTeleport(cfg *Config) (*TeleportProcess, error) {
	// before we do anything reset the SIGINT handler back to the default
	utils.ResetInterruptSignalHandler()

	if err := validateConfig(cfg); err != nil {
		return nil, trace.Wrap(err, "configuration error")
	}

	// create the data directory if it's missing
	_, err := os.Stat(cfg.DataDir)
	if os.IsNotExist(err) {
		err := os.MkdirAll(cfg.DataDir, os.ModeDir|0700)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	// if there's no host uuid initialized yet, try to read one from the
	// one of the identities
	cfg.HostUUID, err = utils.ReadHostUUID(cfg.DataDir)
	if err != nil {
		if !trace.IsNotFound(err) {
			return nil, trace.Wrap(err)
		}
		if len(cfg.Identities) != 0 {
			cfg.HostUUID = cfg.Identities[0].ID.HostUUID
			log.Infof("Taking host UUID from first identity: %v.", cfg.HostUUID)
		} else {
			cfg.HostUUID = uuid.New()
			log.Infof("Generating new host UUID: %v.", cfg.HostUUID)
		}
		if err := utils.WriteHostUUID(cfg.DataDir, cfg.HostUUID); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	// if user started auth and another service (without providing the auth address for
	// that service, the address of the in-process auth will be used
	if cfg.Auth.Enabled && len(cfg.AuthServers) == 0 {
		cfg.AuthServers = []utils.NetAddr{cfg.Auth.SSHAddr}
	}

	// if user did not provide auth domain name, use this host's name
	if cfg.Auth.Enabled && cfg.Auth.ClusterName == nil {
		cfg.Auth.ClusterName, err = services.NewClusterName(services.ClusterNameSpecV2{
			ClusterName: cfg.Hostname,
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	process := &TeleportProcess{
		Clock:      clockwork.NewRealClock(),
		Supervisor: NewSupervisor(),
		Config:     cfg,
		Identities: make(map[teleport.Role]*auth.Identity),
	}

	serviceStarted := false

	if cfg.Auth.Enabled {
		if cfg.Keygen == nil {
			cfg.Keygen = native.New()
		}
		if err := process.initAuthService(cfg.Keygen); err != nil {
			return nil, trace.Wrap(err)
		}
		serviceStarted = true
	}

	if cfg.SSH.Enabled {
		if err := process.initSSH(); err != nil {
			return nil, err
		}
		serviceStarted = true
	}

	if cfg.Proxy.Enabled {
		if err := process.initProxy(); err != nil {
			return nil, err
		}
		serviceStarted = true
	}

	if !serviceStarted {
		return nil, trace.BadParameter("all services failed to start")
	}

	return process, nil
}

func (process *TeleportProcess) setLocalAuth(a *auth.AuthServer) {
	process.Lock()
	defer process.Unlock()
	process.localAuth = a
}

func (process *TeleportProcess) getLocalAuth() *auth.AuthServer {
	process.Lock()
	defer process.Unlock()
	return process.localAuth
}

// initAuthService can be called to initialize auth server service
func (process *TeleportProcess) initAuthService(authority sshca.Authority) error {
	var (
		askedToExit = false
		err         error
	)
	cfg := process.Config

	// Initialize the storage back-ends for keys, events and records
	b, err := process.initAuthStorage()
	if err != nil {
		return trace.Wrap(err)
	}
	process.backend = b

	// create the audit log, which will be consuming (and recording) all events
	// and recording all sessions.
	if cfg.Auth.NoAudit {
		// this is for teleconsole
		process.auditLog = events.NewDiscardAuditLog()

		warningMessage := "Warning: Teleport audit and session recording have been " +
			"turned off. This is dangerous, you will not be able to view audit events " +
			"or save and playback recorded sessions."
		log.Warn(warningMessage)
	} else {
		// check if session recording has been disabled. note, we will continue
		// logging audit events, we just won't record sessions.
		recordSessions := true
		if cfg.Auth.ClusterConfig.GetSessionRecording() == services.RecordOff {
			recordSessions = false

			warningMessage := "Warning: Teleport session recording have been turned off. " +
				"This is dangerous, you will not be able to save and playback sessions."
			log.Warn(warningMessage)
		}

		auditConfig := events.AuditLogConfig{
			DataDir:        filepath.Join(cfg.DataDir, "log"),
			RecordSessions: recordSessions,
			ServerID:       cfg.HostUUID,
		}
		if runtime.GOOS == teleport.LinuxOS {
			// if the user member of adm linux group,
			// make audit log folder readable by admins
			isAdmin, err := utils.IsGroupMember(teleport.LinuxAdminGID)
			if err != nil {
				return trace.Wrap(err)
			}
			if isAdmin {
				uid := os.Getuid()
				gid := teleport.LinuxAdminGID
				auditConfig.UID = &uid
				auditConfig.GID = &gid
			}
		}
		process.auditLog, err = events.NewAuditLog(auditConfig)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	// first, create the AuthServer
	authServer, identity, err := auth.Init(auth.InitConfig{
		Backend:         b,
		Authority:       authority,
		ClusterConfig:   cfg.Auth.ClusterConfig,
		ClusterName:     cfg.Auth.ClusterName,
		AuthServiceName: cfg.Hostname,
		DataDir:         cfg.DataDir,
		HostUUID:        cfg.HostUUID,
		NodeName:        cfg.Hostname,
		Authorities:     cfg.Auth.Authorities,
		ReverseTunnels:  cfg.ReverseTunnels,
		Trust:           cfg.Trust,
		Presence:        cfg.Presence,
		Provisioner:     cfg.Provisioner,
		Identity:        cfg.Identity,
		Access:          cfg.Access,
		StaticTokens:    cfg.Auth.StaticTokens,
		Roles:           cfg.Auth.Roles,
		AuthPreference:  cfg.Auth.Preference,
		OIDCConnectors:  cfg.OIDCConnectors,
		AuditLog:        process.auditLog,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	process.setLocalAuth(authServer)

	// second, create the API Server: it's actually a collection of API servers,
	// each serving requests for a "role" which is assigned to every connected
	// client based on their certificate (user, server, admin, etc)
	sessionService, err := session.New(b, authServer.GetCachedClusterConfig)
	if err != nil {
		return trace.Wrap(err)
	}
	authorizer, err := auth.NewAuthorizer(authServer.Access, authServer.Identity, authServer.Trust)
	if err != nil {
		return trace.Wrap(err)
	}
	apiConf := &auth.APIConfig{
		AuthServer:     authServer,
		SessionService: sessionService,
		Authorizer:     authorizer,
		AuditLog:       process.auditLog,
	}

	sshLimiter, err := limiter.NewLimiter(cfg.Auth.Limiter)
	if err != nil {
		return trace.Wrap(err)
	}

	// auth server listens on SSH and TLS, reusing the same socket
	listener, err := net.Listen("tcp", cfg.Auth.SSHAddr.Addr)
	if err != nil {
		utils.Consolef(cfg.Console, "[AUTH] failed to bind to address %v, exiting", cfg.Auth.SSHAddr.Addr, err)
		return trace.Wrap(err)
	}
	process.onExit(func(payload interface{}) {
		log.Debugf("Closing listener: %v.", listener.Addr())
		listener.Close()
	})
	if cfg.Auth.EnableProxyProtocol {
		log.Infof("Starting Auth service with PROXY protocol support.")
	}
	mux, err := multiplexer.New(multiplexer.Config{
		EnableProxyProtocol: cfg.Auth.EnableProxyProtocol,
		Listener:            listener,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	go mux.Serve()

	// Register an SSH endpoint which is used to create an SSH tunnel to send HTTP
	// requests to the Auth API
	var authTunnel *auth.AuthTunnel
	process.RegisterFunc("auth.ssh", func() error {
		utils.Consolef(cfg.Console, "[AUTH]  Auth service is starting on %v", cfg.Auth.SSHAddr.Addr)
		authTunnel, err = auth.NewTunnel(
			cfg.Auth.SSHAddr,
			identity.KeySigner,
			apiConf,
			auth.SetLimiter(sshLimiter),
		)
		if err != nil {
			utils.Consolef(cfg.Console, "[AUTH] Error: %v", err)
			return trace.Wrap(err)
		}
		if err := authTunnel.Serve(mux.SSH()); err != nil {
			if askedToExit {
				log.Infof("Auth tunnel exited.")
				return nil
			}
			utils.Consolef(cfg.Console, "[AUTH] Error: %v", err)
			return trace.Wrap(err)
		}
		return nil
	})

	// Register TLS endpoint of the auth service
	tlsConfig, err := identity.TLSConfig()
	if err != nil {
		return trace.Wrap(err)
	}
	tlsServer, err := auth.NewTLSServer(auth.TLSServerConfig{
		TLS:           tlsConfig,
		APIConfig:     *apiConf,
		LimiterConfig: cfg.Auth.Limiter,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	process.RegisterFunc("auth.tls", func() error {
		err := tlsServer.Serve(mux.TLS())
		if err != nil {
			log.Warningf("TLS server exited with error: %v.", err)
		}
		return nil
	})

	process.RegisterFunc("auth.heartbeat.broadcast", func() error {
		// Heart beat auth server presence, this is not the best place for this
		// logic, consolidate it into auth package later
		connector, err := process.connectToAuthService(teleport.RoleAdmin, nil)
		if err != nil {
			return trace.Wrap(err)
		}
		// External integrations rely on this event:
		process.BroadcastEvent(Event{Name: AuthIdentityEvent, Payload: connector})
		process.onExit(func(payload interface{}) {
			connector.Client.Close()
		})
		return nil
	})

	process.RegisterFunc("auth.heartbeat", func() error {
		srv := services.ServerV2{
			Kind:    services.KindAuthServer,
			Version: services.V2,
			Metadata: services.Metadata{
				Namespace: defaults.Namespace,
				Name:      process.Config.HostUUID,
			},
			Spec: services.ServerSpecV2{
				Addr:     cfg.Auth.SSHAddr.Addr,
				Hostname: process.Config.Hostname,
			},
		}
		host, port, err := net.SplitHostPort(srv.GetAddr())
		// advertise-ip is explicitly set:
		if process.Config.AdvertiseIP != nil {
			if err != nil {
				return trace.Wrap(err)
			}
			srv.SetAddr(fmt.Sprintf("%v:%v", process.Config.AdvertiseIP.String(), port))
		} else {
			// advertise-ip is not set, while the CA is listening on 0.0.0.0? lets try
			// to guess the 'advertise ip' then:
			if net.ParseIP(host).IsUnspecified() {
				ip, err := utils.GuessHostIP()
				if err != nil {
					log.Warn(err)
				} else {
					srv.SetAddr(net.JoinHostPort(ip.String(), port))
				}
			}
			log.Warnf("Parameter advertise_ip is not set for this auth server. Trying to guess the IP this server can be reached at: %v.", srv.GetAddr())
		}
		// immediately register, and then keep repeating in a loop:
		for !askedToExit {
			srv.SetTTL(process, defaults.ServerHeartbeatTTL)
			err := authServer.UpsertAuthServer(&srv)
			if err != nil {
				log.Warningf("Failed to announce presence: %v.", err)
			}
			sleepTime := defaults.ServerHeartbeatTTL/2 + utils.RandomDuration(defaults.ServerHeartbeatTTL/10)
			time.Sleep(sleepTime)
		}
		log.Infof("Heartbeat to other auth servers exited.")
		return nil
	})

	// execute this when process is asked to exit:
	process.onExit(func(payload interface{}) {
		askedToExit = true
		mux.Close()
		authTunnel.Close()
		tlsServer.Close()
		log.Infof("Auth service exited.")
	})
	return nil
}

// onExit allows individual services to register a callback function which will be
// called when Teleport Process is asked to exit. Usually services terminate themselves
// when the callback is called
func (process *TeleportProcess) onExit(callback func(interface{})) {
	go func() {
		eventC := make(chan Event)
		process.WaitForEvent(TeleportExitEvent, eventC, make(chan struct{}))
		select {
		case event := <-eventC:
			callback(event.Payload)
		}
	}()
}

// newLocalCache returns new local cache access point
func (process *TeleportProcess) newLocalCache(clt auth.ClientI, cacheName []string) (auth.AccessPoint, error) {
	// if caching is disabled, return access point
	if !process.Config.CachePolicy.Enabled {
		return clt, nil
	}

	path := filepath.Join(append([]string{process.Config.DataDir, "cache"}, cacheName...)...)
	cacheBackend, err := dir.New(backend.Params{"path": path})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return state.NewCachingAuthClient(state.Config{
		AccessPoint:  clt,
		Backend:      cacheBackend,
		NeverExpires: process.Config.CachePolicy.NeverExpires,
		CacheTTL:     process.Config.CachePolicy.TTL,
	})
}

// initSSH initializes the "node" role, i.e. a simple SSH server connected to the auth server.
func (process *TeleportProcess) initSSH() error {
	process.RegisterWithAuthServer(
		process.Config.Token, teleport.RoleNode, SSHIdentityEvent, nil)
	eventsC := make(chan Event)
	process.WaitForEvent(SSHIdentityEvent, eventsC, make(chan struct{}))

	var s *regular.Server

	process.RegisterFunc("ssh.node", func() error {
		event := <-eventsC
		log.Infof("SSH node received %v", &event)
		conn, ok := (event.Payload).(*Connector)
		if !ok {
			return trace.BadParameter("unsupported connector type: %T", event.Payload)
		}

		cfg := process.Config

		limiter, err := limiter.NewLimiter(cfg.SSH.Limiter)
		if err != nil {
			return trace.Wrap(err)
		}

		authClient, err := process.newLocalCache(conn.Client, []string{"node"})
		if err != nil {
			return trace.Wrap(err)
		}

		// make sure the namespace exists
		namespace := services.ProcessNamespace(cfg.SSH.Namespace)
		_, err = authClient.GetNamespace(namespace)
		if err != nil {
			if trace.IsNotFound(err) {
				return trace.NotFound(
					"namespace %v is not found, ask your system administrator to create this namespace so you can register nodes there.", namespace)
			}
			return trace.Wrap(err)
		}

		s, err = regular.New(cfg.SSH.Addr,
			cfg.Hostname,
			[]ssh.Signer{conn.Identity.KeySigner},
			authClient,
			cfg.DataDir,
			cfg.AdvertiseIP,
			cfg.Proxy.PublicAddr,
			regular.SetLimiter(limiter),
			regular.SetShell(cfg.SSH.Shell),
			regular.SetAuditLog(conn.Client),
			regular.SetSessionServer(conn.Client),
			regular.SetLabels(cfg.SSH.Labels, cfg.SSH.CmdLabels),
			regular.SetNamespace(namespace),
			regular.SetPermitUserEnvironment(cfg.SSH.PermitUserEnvironment),
			regular.SetCiphers(cfg.Ciphers),
			regular.SetKEXAlgorithms(cfg.KEXAlgorithms),
			regular.SetMACAlgorithms(cfg.MACAlgorithms),
		)
		if err != nil {
			return trace.Wrap(err)
		}

		utils.Consolef(cfg.Console, "[SSH]   Service is starting on %v using %v", cfg.SSH.Addr.Addr, process.Config.CachePolicy)
		if err := s.Start(); err != nil {
			utils.Consolef(cfg.Console, "[SSH]   Error: %v", err)
			return trace.Wrap(err)
		}
		s.Wait()
		log.Infof("[SSH] node service exited")
		return nil
	})
	// execute this when process is asked to exit:
	process.onExit(func(payload interface{}) {
		if s != nil {
			s.Close()
		}
	})
	return nil
}

// RegisterWithAuthServer uses one time provisioning token obtained earlier
// from the server to get a pair of SSH keys signed by Auth server host
// certificate authority
func (process *TeleportProcess) RegisterWithAuthServer(token string, role teleport.Role, eventName string, additionalPrincipals []string) {
	cfg := process.Config
	identityID := auth.IdentityID{Role: role, HostUUID: cfg.HostUUID, NodeName: cfg.Hostname}

	// this means the server has not been initialized yet, we are starting
	// the registering client that attempts to connect to the auth server
	// and provision the keys
	var authClient *auth.Client
	process.RegisterFunc(fmt.Sprintf("register.%v", strings.ToLower(role.String())), func() error {
		retryTime := defaults.ServerHeartbeatTTL / 3
		for {
			connector, err := process.connectToAuthService(role, additionalPrincipals)
			if err == nil {
				process.BroadcastEvent(Event{Name: eventName, Payload: connector})
				authClient = connector.Client
				return nil
			}
			if trace.IsConnectionProblem(err) {
				utils.Consolef(cfg.Console, "[%v] connecting to auth server: %v", role, err)
				time.Sleep(retryTime)
				continue
			}
			if !trace.IsNotFound(err) {
				return trace.Wrap(err)
			}
			//  we haven't connected yet, so we expect the token to exist
			if process.getLocalAuth() != nil {
				// Auth service is on the same host, no need to go though the invitation
				// procedure
				log.Debugf("This server has local Auth server started, using it to add role to the cluster.")
				err = auth.LocalRegister(cfg.DataDir, identityID, process.getLocalAuth(), additionalPrincipals)
			} else {
				// Auth server is remote, so we need a provisioning token
				if token == "" {
					return trace.BadParameter("%v must join a cluster and needs a provisioning token", role)
				}
				log.Infof("Joining the cluster with a token %v.", token)
				err = auth.Register(cfg.DataDir, token, identityID, cfg.AuthServers, additionalPrincipals)
			}
			if err != nil {
				log.Errorf("Failed to join the cluster: %v.", err)
				time.Sleep(retryTime)
			} else {
				utils.Consolef(cfg.Console, "[%v] Successfully registered with the cluster", role)
				continue
			}
		}
	})

	process.onExit(func(interface{}) {
		if authClient != nil {
			authClient.Close()
		}
	})
}

// initProxy gets called if teleport runs with 'proxy' role enabled.
// this means it will do two things:
//    1. serve a web UI
//    2. proxy SSH connections to nodes running with 'node' role
//    3. take care of reverse tunnels
func (process *TeleportProcess) initProxy() error {
	// if no TLS key was provided for the web UI, generate a self signed cert
	if process.Config.Proxy.TLSKey == "" && !process.Config.Proxy.DisableTLS && !process.Config.Proxy.DisableWebService {
		err := initSelfSignedHTTPSCert(process.Config)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	var additionalPrincipals []string
	if process.Config.Proxy.PublicAddr.Addr != "" {
		host, err := utils.Host(process.Config.Proxy.PublicAddr.Addr)
		if err != nil {
			return trace.Wrap(err)
		}
		additionalPrincipals = []string{host}
	}

	process.RegisterWithAuthServer(process.Config.Token, teleport.RoleProxy, ProxyIdentityEvent, additionalPrincipals)
	process.RegisterFunc("proxy.init", func() error {
		eventsC := make(chan Event)
		process.WaitForEvent(ProxyIdentityEvent, eventsC, make(chan struct{}))

		event := <-eventsC
		log.Debugf("Received event %v.", &event)
		conn, ok := (event.Payload).(*Connector)
		if !ok {
			return trace.BadParameter("unsupported connector type: %T", event.Payload)
		}
		return trace.Wrap(process.initProxyEndpoint(conn))
	})
	return nil
}

type proxyListeners struct {
	mux           *multiplexer.Mux
	web           net.Listener
	reverseTunnel net.Listener
}

func (l *proxyListeners) Close() {
	if l.mux != nil {
		l.mux.Close()
	}
	if l.web != nil {
		l.web.Close()
	}
	if l.reverseTunnel != nil {
		l.reverseTunnel.Close()
	}
}

// setupProxyListeners sets up web proxy listeners based on the configuration
func (process *TeleportProcess) setupProxyListeners() (*proxyListeners, error) {
	cfg := process.Config
	log.Debugf("Setup Proxy: Web Proxy Address: %v, Reverse Tunnel Proxy Address: %v", cfg.Proxy.WebAddr.Addr, cfg.Proxy.ReverseTunnelListenAddr.Addr)
	var err error
	var listeners proxyListeners
	switch {
	case cfg.Proxy.DisableWebService && cfg.Proxy.DisableReverseTunnel:
		log.Debugf("Setup Proxy: Reverse tunnel proxy and web proxy are disabled.")
		return &listeners, nil
	case cfg.Proxy.ReverseTunnelListenAddr.Equals(cfg.Proxy.WebAddr):
		log.Debugf("Setup Proxy: Reverse tunnel proxy and web proxy listen on the same port, multiplexing is on.")
		listener, err := net.Listen("tcp", cfg.Proxy.WebAddr.Addr)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		listeners.mux, err = multiplexer.New(multiplexer.Config{
			EnableProxyProtocol: cfg.Proxy.EnableProxyProtocol,
			Listener:            listener,
			DisableTLS:          cfg.Proxy.DisableWebService,
			DisableSSH:          cfg.Proxy.DisableReverseTunnel,
		})
		if err != nil {
			listener.Close()
			return nil, trace.Wrap(err)
		}
		listeners.web = listeners.mux.TLS()
		listeners.reverseTunnel = listeners.mux.SSH()
		go listeners.mux.Serve()
		return &listeners, nil
	case cfg.Proxy.EnableProxyProtocol && !cfg.Proxy.DisableWebService:
		log.Debugf("Setup Proxy: Proxy protocol is enabled for web service, multiplexing is on.")
		listener, err := net.Listen("tcp", cfg.Proxy.WebAddr.Addr)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		listeners.mux, err = multiplexer.New(multiplexer.Config{
			EnableProxyProtocol: cfg.Proxy.EnableProxyProtocol,
			Listener:            listener,
			DisableTLS:          false,
			DisableSSH:          true,
		})
		if err != nil {
			listener.Close()
			return nil, trace.Wrap(err)
		}
		listeners.web = listeners.mux.TLS()
		listeners.reverseTunnel, err = net.Listen("tcp", cfg.Proxy.ReverseTunnelListenAddr.Addr)
		if err != nil {
			listener.Close()
			listeners.Close()
			return nil, trace.Wrap(err)
		}
		go listeners.mux.Serve()
		return &listeners, nil
	default:
		log.Debugf("Proxy reverse tunnel are listening on the separate ports")
		if !cfg.Proxy.DisableReverseTunnel {
			listeners.reverseTunnel, err = net.Listen("tcp", cfg.Proxy.ReverseTunnelListenAddr.Addr)
			if err != nil {
				listeners.Close()
				return nil, trace.Wrap(err)
			}
		}
		if !cfg.Proxy.DisableWebService {
			listeners.web, err = net.Listen("tcp", cfg.Proxy.WebAddr.Addr)
			if err != nil {
				listeners.Close()
				return nil, trace.Wrap(err)
			}
		}
		return &listeners, nil
	}
}

func (process *TeleportProcess) initProxyEndpoint(conn *Connector) error {
	var (
		askedToExit = true
		err         error
	)
	cfg := process.Config

	proxyLimiter, err := limiter.NewLimiter(cfg.Proxy.Limiter)
	if err != nil {
		return trace.Wrap(err)
	}

	reverseTunnelLimiter, err := limiter.NewLimiter(cfg.Proxy.Limiter)
	if err != nil {
		return trace.Wrap(err)
	}

	// make a caching auth client for the auth server:
	accessPoint, err := process.newLocalCache(conn.Client, []string{"proxy"})
	if err != nil {
		return trace.Wrap(err)
	}

	tlsConfig, err := conn.Identity.TLSConfig()
	if err != nil {
		return trace.Wrap(err)
	}

	listeners, err := process.setupProxyListeners()
	if err != nil {
		return trace.Wrap(err)
	}

	// Register reverse tunnel agents pool
	agentPool, err := reversetunnel.NewAgentPool(reversetunnel.AgentPoolConfig{
		HostUUID:    conn.Identity.ID.HostUUID,
		Client:      conn.Client,
		AccessPoint: accessPoint,
		HostSigners: []ssh.Signer{conn.Identity.KeySigner},
		Cluster:     conn.Identity.Cert.Extensions[utils.CertExtensionAuthority],
	})
	if err != nil {
		return trace.Wrap(err)
	}

	// register SSH reverse tunnel server that accepts connections
	// from remote teleport nodes
	var tsrv reversetunnel.Server
	if !process.Config.Proxy.DisableReverseTunnel {
		tsrv, err = reversetunnel.NewServer(
			reversetunnel.Config{
				ID:                    process.Config.HostUUID,
				ClusterName:           conn.Identity.Cert.Extensions[utils.CertExtensionAuthority],
				ClientTLS:             tlsConfig,
				Listener:              listeners.reverseTunnel,
				HostSigners:           []ssh.Signer{conn.Identity.KeySigner},
				LocalAuthClient:       conn.Client,
				LocalAccessPoint:      accessPoint,
				NewCachingAccessPoint: process.newLocalCache,
				Limiter:               reverseTunnelLimiter,
				DirectClusters: []reversetunnel.DirectCluster{
					{
						Name:   conn.Identity.Cert.Extensions[utils.CertExtensionAuthority],
						Client: conn.Client,
					},
				},
				Ciphers:       cfg.Ciphers,
				KEXAlgorithms: cfg.KEXAlgorithms,
				MACAlgorithms: cfg.MACAlgorithms,
			})
		if err != nil {
			return trace.Wrap(err)
		}
		process.RegisterFunc("proxy.reveresetunnel.server", func() error {
			utils.Consolef(cfg.Console, "Starting reverse tunnel service is starting on %v using %v", cfg.Proxy.ReverseTunnelListenAddr.Addr, process.Config.CachePolicy)
			if err := tsrv.Start(); err != nil {
				utils.Consolef(cfg.Console, "Error: %v", err)
				return trace.Wrap(err)
			}
			// notify parties that we've started reverse tunnel server
			process.BroadcastEvent(Event{Name: ProxyReverseTunnelServerEvent, Payload: tsrv})
			tsrv.Wait()
			if askedToExit {
				log.Infof("Reverse tunnel exited.")
			}
			return nil
		})
	}

	// Register web proxy server
	if !process.Config.Proxy.DisableWebService {
		process.RegisterFunc("proxy.web", func() error {
			utils.Consolef(cfg.Console, "Web proxy service is starting on %v.", cfg.Proxy.WebAddr.Addr)
			webHandler, err := web.NewHandler(
				web.Config{
					Proxy:        tsrv,
					AuthServers:  cfg.AuthServers[0],
					DomainName:   cfg.Hostname,
					ProxyClient:  conn.Client,
					DisableUI:    process.Config.Proxy.DisableWebInterface,
					ProxySSHAddr: cfg.Proxy.SSHAddr,
					ProxyWebAddr: cfg.Proxy.WebAddr,
				})
			if err != nil {
				return trace.Wrap(err)
			}
			defer webHandler.Close()

			proxyLimiter.WrapHandle(webHandler)
			process.BroadcastEvent(Event{Name: ProxyWebServerEvent, Payload: webHandler})

			if !process.Config.Proxy.DisableTLS {
				tlsConfig, err := utils.CreateTLSConfiguration(cfg.Proxy.TLSCert, cfg.Proxy.TLSKey)
				if err != nil {
					return trace.Wrap(err)
				}
				listeners.web = tls.NewListener(listeners.web, tlsConfig)
			}
			if err = http.Serve(listeners.web, proxyLimiter); err != nil {
				if askedToExit {
					log.Infof("Proxy web server exited.")
					return nil
				}
				log.Error(err)
			}
			return nil
		})
	} else {
		log.Infof("Web UI is disabled.")
	}

	// Register SSH proxy server - SSH jumphost proxy server
	sshProxy, err := regular.New(cfg.Proxy.SSHAddr,
		cfg.Hostname,
		[]ssh.Signer{conn.Identity.KeySigner},
		accessPoint,
		cfg.DataDir,
		nil,
		cfg.Proxy.PublicAddr,
		regular.SetLimiter(proxyLimiter),
		regular.SetProxyMode(tsrv),
		regular.SetSessionServer(conn.Client),
		regular.SetAuditLog(conn.Client),
		regular.SetCiphers(cfg.Ciphers),
		regular.SetKEXAlgorithms(cfg.KEXAlgorithms),
		regular.SetMACAlgorithms(cfg.MACAlgorithms),
		regular.SetNamespace(defaults.Namespace),
	)
	if err != nil {
		return trace.Wrap(err)
	}

	process.RegisterFunc("proxy.ssh", func() error {
		utils.Consolef(cfg.Console, "[PROXY] SSH proxy service is starting on %v", cfg.Proxy.SSHAddr.Addr)
		if err := sshProxy.Start(); err != nil {
			if askedToExit {
				log.Infof("SSH proxy exited")
				return nil
			}
			utils.Consolef(cfg.Console, "[PROXY] Error: %v", err)
			return trace.Wrap(err)
		}
		return nil
	})

	process.RegisterFunc("proxy.reversetunnel.agent", func() error {
		log.Infof("Starting reverse tunnel agent pool.")
		if err := agentPool.Start(); err != nil {
			log.Fatalf("Failed to start: %v.", err)
			return trace.Wrap(err)
		}
		agentPool.Wait()
		return nil
	})

	// execute this when process is asked to exit:
	process.onExit(func(payload interface{}) {
		listeners.Close()
		if tsrv != nil {
			tsrv.Close()
		}
		sshProxy.Close()
		agentPool.Stop()
		log.Infof("Proxy service exited.")
	})
	return nil
}

// initAuthStorage initializes the storage backend for the auth service.
func (process *TeleportProcess) initAuthStorage() (bk backend.Backend, err error) {
	bc := &process.Config.Auth.StorageConfig

	switch bc.Type {
	// legacy bolt backend:
	case boltbk.GetName():
		bk, err = boltbk.New(bc.Params)
	// filesystem backend:
	case dir.GetName():
		bk, err = dir.New(bc.Params)
	// DynamoDB bakcend:
	case dynamo.GetName():
		bk, err = dynamo.New(bc.Params)
	// etcd backend:
	case etcdbk.GetName():
		bk, err = etcdbk.New(bc.Params)
	default:
		err = trace.BadParameter("unsupported secrets storage type: %q", bc.Type)
	}
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return bk, nil
}

func (process *TeleportProcess) Close() error {
	process.BroadcastEvent(Event{Name: TeleportExitEvent})
	localAuth := process.getLocalAuth()
	if localAuth != nil {
		return trace.Wrap(process.localAuth.Close())
	}
	return nil
}

func validateConfig(cfg *Config) error {
	if !cfg.Auth.Enabled && !cfg.SSH.Enabled && !cfg.Proxy.Enabled {
		return trace.BadParameter(
			"config: supply at least one of Auth, SSH or Proxy roles")
	}

	if cfg.DataDir == "" {
		return trace.BadParameter("config: please supply data directory")
	}

	if cfg.Console == nil {
		cfg.Console = ioutil.Discard
	}

	if (cfg.Proxy.TLSKey == "" && cfg.Proxy.TLSCert != "") || (cfg.Proxy.TLSKey != "" && cfg.Proxy.TLSCert == "") {
		return trace.BadParameter("please supply both TLS key and certificate")
	}

	if len(cfg.AuthServers) == 0 {
		return trace.BadParameter("auth_servers is empty")
	}
	for i := range cfg.Auth.Authorities {
		if err := cfg.Auth.Authorities[i].Check(); err != nil {
			return trace.Wrap(err)
		}
	}
	for _, tun := range cfg.ReverseTunnels {
		if err := tun.Check(); err != nil {
			return trace.Wrap(err)
		}
	}

	cfg.SSH.Namespace = services.ProcessNamespace(cfg.SSH.Namespace)

	return nil
}

// initSelfSignedHTTPSCert generates and self-signs a TLS key+cert pair for https connection
// to the proxy server.
func initSelfSignedHTTPSCert(cfg *Config) (err error) {
	log.Warningf("[CONFIG] NO TLS Keys provided, using self signed certificate")

	keyPath := filepath.Join(cfg.DataDir, defaults.SelfSignedKeyPath)
	certPath := filepath.Join(cfg.DataDir, defaults.SelfSignedCertPath)

	cfg.Proxy.TLSKey = keyPath
	cfg.Proxy.TLSCert = certPath

	// return the existing pair if they have already been generated:
	_, err = tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return trace.Wrap(err, "unrecognized error reading certs")
	}
	log.Warningf("[CONFIG] Generating self signed key and cert to %v %v", keyPath, certPath)

	creds, err := utils.GenerateSelfSignedCert([]string{cfg.Hostname, "localhost"})
	if err != nil {
		return trace.Wrap(err)
	}

	if err := ioutil.WriteFile(keyPath, creds.PrivateKey, 0600); err != nil {
		return trace.Wrap(err, "error writing key PEM")
	}
	if err := ioutil.WriteFile(certPath, creds.Cert, 0600); err != nil {
		return trace.Wrap(err, "error writing key PEM")
	}
	return nil
}
