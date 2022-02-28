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

package proxy

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/metadata"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

const (
	peerKeepAlive = time.Second * 10
	peerTimeout   = time.Second * 20
)

// ServerConfig configures a Server instance.
type ServerConfig struct {
	AccessCache   auth.AccessCache
	Listener      net.Listener
	TLSConfig     *tls.Config
	ClusterDialer ClusterDialer
	Log           logrus.FieldLogger

	// getConfigForClient gets the client tls config.
	// configurable for testing purposes.
	getConfigForClient func(*tls.ClientHelloInfo) (*tls.Config, error)

	// getService returns a custom ProxyServiceServer
	// configurable for testing purposes.
	getService func() proto.ProxyServiceServer
}

// checkAndSetDefaults checks and sets default values
func (c *ServerConfig) checkAndSetDefaults() error {
	if c.AccessCache == nil {
		return trace.BadParameter("missing access cache")
	}
	if c.Listener == nil {
		return trace.BadParameter("missing listener")
	}
	if c.ClusterDialer == nil {
		return trace.BadParameter("missing cluster dialer server")
	}

	if c.TLSConfig == nil {
		return trace.BadParameter("missing tls config")
	}
	if len(c.TLSConfig.Certificates) == 0 {
		return trace.BadParameter("missing tls certificate")
	}
	if c.Log == nil {
		c.Log = logrus.New()
	}
	c.Log = c.Log.WithField(
		trace.Component,
		teleport.Component(teleport.ComponentProxy, "peer"),
	)

	c.TLSConfig = c.TLSConfig.Clone()
	c.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert

	if c.getConfigForClient == nil {
		c.getConfigForClient = getConfigForClient(c.TLSConfig, c.AccessCache, c.Log)
	}

	c.TLSConfig.GetConfigForClient = c.getConfigForClient

	return nil
}

// Server is a proxy service server using grpc and tls.
type Server struct {
	config  ServerConfig
	server  *grpc.Server
	metrics *serverMetrics
}

// NewServer creates a new proxy server instance.
func NewServer(config ServerConfig) (*Server, error) {
	err := config.checkAndSetDefaults()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	metrics, err := newServerMetrics()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	transportCreds := newProxyCredentials(credentials.NewTLS(config.TLSConfig))
	server := grpc.NewServer(
		grpc.Creds(transportCreds),
		grpc.ChainStreamInterceptor(metadata.StreamServerInterceptor, streamServerInterceptor(metrics)),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    peerKeepAlive,
			Timeout: peerTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             peerKeepAlive,
			PermitWithoutStream: true,
		}),
	)

	if config.getService != nil {
		proto.RegisterProxyServiceServer(server, config.getService())
	} else {
		service := &proxyService{
			config.ClusterDialer,
			config.Log,
		}
		proto.RegisterProxyServiceServer(server, service)
	}

	return &Server{
		config:  config,
		server:  server,
		metrics: metrics,
	}, nil
}

// Serve starts the proxy server.
func (s *Server) Serve() error {
	if err := s.server.Serve(s.config.Listener); err != nil && err != grpc.ErrServerStopped {
		return trace.Wrap(err)
	}
	return nil
}

// Close closes the proxy server immediately.
func (s *Server) Close() error {
	s.server.Stop()
	return nil
}

// Shutdown does a graceful shutdown of the proxy server.
func (s *Server) Shutdown() error {
	s.server.GracefulStop()
	return nil
}
