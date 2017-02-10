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
	"sync"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/boltbk"
	"github.com/gravitational/teleport/lib/backend/consulbk"
	"github.com/gravitational/teleport/lib/backend/dir"
	"github.com/gravitational/teleport/lib/backend/dynamo"
	"github.com/gravitational/teleport/lib/backend/etcdbk"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/limiter"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/srv"
	"github.com/gravitational/teleport/lib/state"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/web"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"github.com/pborman/uuid"
	"golang.org/x/crypto/ssh"
)

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
	Client   *auth.TunClient
}

// TeleportProcess structure holds the state of the Teleport daemon, controlling
// execution and configuration of the teleport services: ssh, auth and proxy.
type TeleportProcess struct {
	sync.Mutex
	Supervisor
	Config *Config
	// localAuth has local auth server listed in case if this process
	// has started with auth server role enabled
	localAuth *auth.AuthServer

	// identities of this process (credentials to auth sever, basically)
	Identities map[teleport.Role]*auth.Identity
}

func (process *TeleportProcess) GetAuthServer() *auth.AuthServer {
	return process.localAuth
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
			// try to locate static identity provide in the file
			i, err = process.findStaticIdentity(id)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			log.Infof("found static identity %v in the config file, writing to disk", &id)
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
func (process *TeleportProcess) connectToAuthService(role teleport.Role) (*Connector, error) {
	identity, err := process.GetIdentity(role)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	storage := utils.NewFileAddrStorage(
		filepath.Join(process.Config.DataDir, "authservers.json"))

	authUser := identity.Cert.ValidPrincipals[0]
	authClient, err := auth.NewTunClient(
		string(role),
		process.Config.AuthServers,
		authUser,
		[]ssh.AuthMethod{ssh.PublicKeys(identity.KeySigner)},
		auth.TunClientStorage(storage),
	)
	// success?
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// try calling a test method via auth api:
	//
	// ??? in case of failure it never gets back here!!!
	dn, err := authClient.GetDomainName()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// success ? we're logged in!
	log.Infof("[Node] %s connected to the cluster '%s'", authUser, dn)
	return &Connector{Client: authClient, Identity: identity}, nil
}

// NewTeleport takes the daemon configuration, instantiates all required services
// and starts them under a supervisor, returning the supervisor object
func NewTeleport(cfg *Config) (*TeleportProcess, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, trace.Wrap(err, "Configuration error")
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
			log.Infof("[INIT] taking host uuid from first identity: %v", cfg.HostUUID)
		} else {
			cfg.HostUUID = uuid.New()
			log.Infof("[INIT] generating new host UUID: %v", cfg.HostUUID)
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

	// if user did not provide auth domain name, use this host UUID
	if cfg.Auth.Enabled && cfg.Auth.DomainName == "" {
		cfg.Auth.DomainName = cfg.HostUUID
	}

	// try to login into the auth service:

	// if there are no certificates, use self signed
	process := &TeleportProcess{
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
		return nil, trace.Errorf("all services failed to start")
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
func (process *TeleportProcess) initAuthService(authority auth.Authority) error {
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

	// create the audit log, which will be consuming (and recording) all events
	// and record sessions
	var auditLog events.IAuditLog
	if cfg.Auth.NoAudit {
		auditLog = &events.DiscardAuditLog{}
		log.Warn("the audit and session recording are turned off")
	} else {
		auditLog, err = events.NewAuditLog(filepath.Join(cfg.DataDir, "log"))
		if err != nil {
			return trace.Wrap(err)
		}
	}

	// first, create the AuthServer
	authServer, identity, err := auth.Init(auth.InitConfig{
		Backend:         b,
		Authority:       authority,
		DomainName:      cfg.Auth.DomainName,
		AuthServiceName: cfg.Hostname,
		DataDir:         cfg.DataDir,
		HostUUID:        cfg.HostUUID,
		NodeName:        cfg.Hostname,
		Authorities:     cfg.Auth.Authorities,
		ReverseTunnels:  cfg.ReverseTunnels,
		OIDCConnectors:  cfg.OIDCConnectors,
		Trust:           cfg.Trust,
		Presence:        cfg.Presence,
		Provisioner:     cfg.Provisioner,
		Identity:        cfg.Identity,
		Access:          cfg.Access,
		StaticTokens:    cfg.Auth.StaticTokens,
		U2F:             cfg.Auth.U2F,
		Roles:           cfg.Auth.Roles,
	}, cfg.SeedConfig)
	if err != nil {
		return trace.Wrap(err)
	}
	process.setLocalAuth(authServer)

	// second, create the API Server: it's actually a collection of API servers,
	// each serving requests for a "role" which is assigned to every connected
	// client based on their certificate (user, server, admin, etc)
	sessionService, err := session.New(b)
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
		AuditLog:       auditLog,
	}

	limiter, err := limiter.NewLimiter(cfg.Auth.Limiter)
	if err != nil {
		return trace.Wrap(err)
	}

	// Register an SSH endpoint which is used to create an SSH tunnel to send HTTP
	// requests to the Auth API
	var authTunnel *auth.AuthTunnel
	process.RegisterFunc(func() error {
		utils.Consolef(cfg.Console, "[AUTH]  Auth service is starting on %v", cfg.Auth.SSHAddr.Addr)
		authTunnel, err = auth.NewTunnel(
			cfg.Auth.SSHAddr,
			identity.KeySigner,
			apiConf,
			auth.SetLimiter(limiter),
		)
		if err != nil {
			utils.Consolef(cfg.Console, "[AUTH] Error: %v", err)
			return trace.Wrap(err)
		}
		if err := authTunnel.Start(); err != nil {
			if askedToExit {
				log.Infof("[AUTH] Auth Tunnel exited")
				return nil
			}
			utils.Consolef(cfg.Console, "[AUTH] Error: %v", err)
			return trace.Wrap(err)
		}
		return nil
	})

	process.RegisterFunc(func() error {
		// Heart beat auth server presence, this is not the best place for this
		// logic, consolidate it into auth package later
		connector, err := process.connectToAuthService(teleport.RoleAdmin)
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

	process.RegisterFunc(func() error {
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
			log.Warnf("advertise_ip is not set for this auth server. Trying to guess the IP this server can be reached at: %v", srv.GetAddr())
		}
		// immediately register, and then keep repeating in a loop:
		for !askedToExit {
			err := authServer.UpsertAuthServer(&srv, defaults.ServerHeartbeatTTL)
			if err != nil {
				log.Warningf("failed to announce presence: %v", err)
			}
			sleepTime := defaults.ServerHeartbeatTTL/2 + utils.RandomDuration(defaults.ServerHeartbeatTTL/10)
			time.Sleep(sleepTime)
		}
		log.Infof("[AUTH] heartbeat to other auth servers exited")
		return nil
	})

	// execute this when process is asked to exit:
	process.onExit(func(payload interface{}) {
		askedToExit = true
		authTunnel.Close()
		log.Infof("[AUTH] auth service exited")
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

// initSSH initializes the "node" role, i.e. a simple SSH server connected to the auth server.
func (process *TeleportProcess) initSSH() error {
	process.RegisterWithAuthServer(
		process.Config.Token, teleport.RoleNode, SSHIdentityEvent)
	eventsC := make(chan Event)
	process.WaitForEvent(SSHIdentityEvent, eventsC, make(chan struct{}))

	var s *srv.Server

	process.RegisterFunc(func() error {
		event := <-eventsC
		log.Infof("[SSH] received %v", &event)
		conn, ok := (event.Payload).(*Connector)
		if !ok {
			return trace.BadParameter("unsupported connector type: %T", event.Payload)
		}

		cfg := process.Config

		limiter, err := limiter.NewLimiter(cfg.SSH.Limiter)
		if err != nil {
			return trace.Wrap(err)
		}

		authClient, err := state.NewCachingAuthClient(conn.Client)
		if err != nil {
			return trace.Wrap(err)
		}

		// make sure the namespace exists
		namespace := services.ProcessNamespace(cfg.SSH.Namespace)
		_, err = conn.Client.GetNamespace(namespace)
		if err != nil {
			if trace.IsNotFound(err) {
				return trace.NotFound(
					"namespace %v is not found, ask your system administrator to create this namespace so you can register nodes there.", namespace)
			}
			return trace.Wrap(err)
		}

		alog := state.MakeCachingAuditLog(conn.Client)
		defer alog.Close()

		s, err = srv.New(cfg.SSH.Addr,
			cfg.Hostname,
			[]ssh.Signer{conn.Identity.KeySigner},
			authClient,
			cfg.DataDir,
			cfg.AdvertiseIP,
			srv.SetLimiter(limiter),
			srv.SetShell(cfg.SSH.Shell),
			srv.SetAuditLog(alog),
			srv.SetSessionServer(conn.Client),
			srv.SetLabels(cfg.SSH.Labels, cfg.SSH.CmdLabels),
			srv.SetNamespace(namespace),
		)
		if err != nil {
			return trace.Wrap(err)
		}

		utils.Consolef(cfg.Console, "[SSH]   Service is starting on %v", cfg.SSH.Addr.Addr)
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
		s.Close()
	})
	return nil
}

// RegisterWithAuthServer uses one time provisioning token obtained earlier
// from the server to get a pair of SSH keys signed by Auth server host
// certificate authority
func (process *TeleportProcess) RegisterWithAuthServer(token string, role teleport.Role, eventName string) {
	cfg := process.Config
	identityID := auth.IdentityID{Role: role, HostUUID: cfg.HostUUID, NodeName: cfg.Hostname}

	// this means the server has not been initialized yet, we are starting
	// the registering client that attempts to connect to the auth server
	// and provision the keys
	var authClient *auth.TunClient
	process.RegisterFunc(func() error {
		retryTime := defaults.ServerHeartbeatTTL / 3
		for {
			connector, err := process.connectToAuthService(role)
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
				log.Debugf("[Node] this server has local Auth server started, using it to add role to the cluster")
				err = auth.LocalRegister(cfg.DataDir, identityID, process.getLocalAuth())
			} else {
				// Auth server is remote, so we need a provisioning token
				if token == "" {
					return trace.BadParameter("%v must join a cluster and needs a provisioning token", role)
				}
				log.Infof("[Node] %v joining the cluster with a token %v", role, token)
				err = auth.Register(cfg.DataDir, token, identityID, cfg.AuthServers)
			}
			if err != nil {
				log.Errorf("[%v] failed to join the cluster: %v", role, err)
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
//    3. take care of revse tunnels
func (process *TeleportProcess) initProxy() error {
	// if no TLS key was provided for the web UI, generate a self signed cert
	if process.Config.Proxy.TLSKey == "" && !process.Config.Proxy.DisableWebUI {
		err := initSelfSignedHTTPSCert(process.Config)
		if err != nil {
			return trace.Wrap(err)
		}
	}
	myRole := teleport.RoleProxy

	process.RegisterWithAuthServer(process.Config.Token, myRole, ProxyIdentityEvent)
	process.RegisterFunc(func() error {
		eventsC := make(chan Event)
		process.WaitForEvent(ProxyIdentityEvent, eventsC, make(chan struct{}))

		event := <-eventsC
		log.Infof("[SSH] received %v", &event)
		conn, ok := (event.Payload).(*Connector)
		if !ok {
			return trace.BadParameter("unsupported connector type: %T", event.Payload)
		}
		return trace.Wrap(process.initProxyEndpoint(conn))
	})
	return nil
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
	authClient, err := state.NewCachingAuthClient(conn.Client)
	if err != nil {
		return trace.Wrap(err)
	}

	tsrv, err := reversetunnel.NewServer(
		cfg.Proxy.ReverseTunnelListenAddr,
		[]ssh.Signer{conn.Identity.KeySigner},
		authClient,
		reversetunnel.SetLimiter(reverseTunnelLimiter),
		reversetunnel.DirectSite(conn.Identity.Cert.Extensions[utils.CertExtensionAuthority],
			conn.Client),
	)
	if err != nil {
		return trace.Wrap(err)
	}

	SSHProxy, err := srv.New(cfg.Proxy.SSHAddr,
		cfg.Hostname,
		[]ssh.Signer{conn.Identity.KeySigner},
		authClient,
		cfg.DataDir,
		nil,
		srv.SetLimiter(proxyLimiter),
		srv.SetProxyMode(tsrv),
		srv.SetSessionServer(conn.Client),
		srv.SetAuditLog(conn.Client),
	)
	if err != nil {
		return trace.Wrap(err)
	}

	// Register reverse tunnel agents pool
	agentPool, err := reversetunnel.NewAgentPool(reversetunnel.AgentPoolConfig{
		HostUUID:    conn.Identity.ID.HostUUID,
		Client:      conn.Client,
		HostSigners: []ssh.Signer{conn.Identity.KeySigner},
	})
	if err != nil {
		return trace.Wrap(err)
	}

	// register SSH reverse tunnel server that accepts connections
	// from remote teleport nodes
	process.RegisterFunc(func() error {
		utils.Consolef(cfg.Console, "[PROXY] Reverse tunnel service is starting on %v", cfg.Proxy.ReverseTunnelListenAddr.Addr)
		if err := tsrv.Start(); err != nil {
			utils.Consolef(cfg.Console, "[PROXY] Error: %v", err)
			return trace.Wrap(err)
		}
		// notify parties that we've started reverse tunnel server
		process.BroadcastEvent(Event{Name: ProxyReverseTunnelServerEvent, Payload: tsrv})
		tsrv.Wait()
		if askedToExit {
			log.Infof("[PROXY] Reverse tunnel exited")
		}
		return nil
	})

	// Register web proxy server
	var webListener net.Listener
	if !process.Config.Proxy.DisableWebUI {
		process.RegisterFunc(func() error {
			utils.Consolef(cfg.Console, "[PROXY] Web proxy service is starting on %v", cfg.Proxy.WebAddr.Addr)
			webHandler, err := web.NewHandler(
				web.Config{
					Proxy:        tsrv,
					AuthServers:  cfg.AuthServers[0],
					DomainName:   cfg.Hostname,
					ProxyClient:  conn.Client,
					DisableUI:    cfg.Proxy.DisableWebUI,
					ProxySSHAddr: cfg.Proxy.SSHAddr,
					ProxyWebAddr: cfg.Proxy.WebAddr,
				})
			if err != nil {
				utils.Consolef(cfg.Console, "[PROXY] starting the web server: %v", err)
				return trace.Wrap(err)
			}
			defer webHandler.Close()

			proxyLimiter.WrapHandle(webHandler)
			process.BroadcastEvent(Event{Name: ProxyWebServerEvent, Payload: webHandler})

			log.Infof("[PROXY] init TLS listeners")
			webListener, err = utils.ListenTLS(
				cfg.Proxy.WebAddr.Addr,
				cfg.Proxy.TLSCert,
				cfg.Proxy.TLSKey)
			if err != nil {
				return trace.Wrap(err)
			}
			if err = http.Serve(webListener, proxyLimiter); err != nil {
				if askedToExit {
					log.Infof("[PROXY] web server exited")
					return nil
				}
				log.Error(err)
			}
			return nil
		})
	} else {
		log.Infof("[WEB] Web UI is disabled")
	}

	// Register ssh proxy server
	process.RegisterFunc(func() error {
		utils.Consolef(cfg.Console, "[PROXY] SSH proxy service is starting on %v", cfg.Proxy.SSHAddr.Addr)
		if err := SSHProxy.Start(); err != nil {
			if askedToExit {
				log.Infof("[PROXY] SSH proxy exited")
				return nil
			}
			utils.Consolef(cfg.Console, "[PROXY] Error: %v", err)
			return trace.Wrap(err)
		}
		return nil
	})

	process.RegisterFunc(func() error {
		log.Infof("[PROXY] starting reverse tunnel agent pool")
		if err := agentPool.Start(); err != nil {
			log.Fatalf("failed to start: %v", err)
			return trace.Wrap(err)
		}
		agentPool.Wait()
		return nil
	})

	// execute this when process is asked to exit:
	process.onExit(func(payload interface{}) {
		tsrv.Close()
		SSHProxy.Close()
		agentPool.Stop()
		if webListener != nil {
			webListener.Close()
		}
		log.Infof("[PROXY] proxy service exited")
	})
	return nil
}

// initAuthStorage initializes the storage backend for the auth. service
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
	// consul backend:
	case consulbk.GetName():
		bk, err = consulbk.New(bc.Params)
	default:
		err = trace.Errorf("unsupported secrets storage type: '%v'", bc.Type)
	}
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return bk, nil
}

func (process *TeleportProcess) Close() error {
	process.BroadcastEvent(Event{Name: TeleportExitEvent})
	return trace.Wrap(process.localAuth.Close())
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

	// return the existing pair if they ahve already been generated:
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
