/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package tbot

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/reversetunnelclient"
	"github.com/gravitational/teleport/lib/srv/alpnproxy"
	"github.com/gravitational/teleport/lib/srv/alpnproxy/common"
	"github.com/gravitational/teleport/lib/tbot/config"
	"github.com/gravitational/teleport/lib/tbot/identity"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
)

var _ alpnproxy.LocalProxyMiddleware = (*alpnProxyMiddleware)(nil)

type alpnProxyMiddleware struct {
	onNewConnection func(ctx context.Context, lp *alpnproxy.LocalProxy, conn net.Conn) error
	onStart         func(ctx context.Context, lp *alpnproxy.LocalProxy) error
}

func (a alpnProxyMiddleware) OnNewConnection(ctx context.Context, lp *alpnproxy.LocalProxy, conn net.Conn) error {
	if a.onNewConnection != nil {
		return a.onNewConnection(ctx, lp, conn)
	}
	return nil
}

func (a alpnProxyMiddleware) OnStart(ctx context.Context, lp *alpnproxy.LocalProxy) error {
	if a.onStart != nil {
		return a.onStart(ctx, lp)
	}
	return nil
}

// DatabaseTunnelService is a service that listens on a local port and forwards
// connections to a remote database service. It is an authenticating tunnel and
// will automatically issue and renew certificates as needed.
type DatabaseTunnelService struct {
	botCfg         *config.BotConfig
	cfg            *config.DatabaseTunnelService
	proxyPingCache *proxyPingCache
	log            logrus.FieldLogger
	resolver       reversetunnelclient.Resolver
	botClient      *authclient.Client
	getBotIdentity getBotIdentityFn
}

// buildLocalProxyConfig initializes the service, fetching any initial information and setting
// up the localproxy.
func (s *DatabaseTunnelService) buildLocalProxyConfig(ctx context.Context) (lpCfg alpnproxy.LocalProxyConfig, err error) {
	ctx, span := tracer.Start(ctx, "DatabaseTunnelService/buildLocalProxyConfig")
	defer span.End()

	// Determine the roles to use for the impersonated db access user. We fall
	// back to all the roles the bot has if none are configured.
	roles := s.cfg.Roles
	if len(roles) == 0 {
		roles, err = fetchDefaultRoles(ctx, s.botClient, s.getBotIdentity())
		if err != nil {
			return alpnproxy.LocalProxyConfig{}, trace.Wrap(err, "fetching default roles")
		}
		s.log.WithField("roles", roles).Debug("No roles configured, using all roles available.")
	}

	proxyPing, err := s.proxyPingCache.ping(ctx)
	if err != nil {
		return alpnproxy.LocalProxyConfig{}, trace.Wrap(err, "pinging proxy")
	}
	proxyAddr := proxyPing.Proxy.SSH.PublicAddr

	// Fetch information about the database and then issue the initial
	// certificate. We issue the initial certificate to allow us to fail faster.
	// We cache the routeToDatabase as these will not change during the lifetime
	// of the service and this reduces the time needed to issue a new
	// certificate.
	s.log.Debug("Determining route to database.")
	routeToDatabase, err := s.getRouteToDatabaseWithImpersonation(ctx, roles)
	if err != nil {
		return alpnproxy.LocalProxyConfig{}, trace.Wrap(err)
	}
	s.log.WithFields(logrus.Fields{
		"serviceName": routeToDatabase.ServiceName,
		"protocol":    routeToDatabase.Protocol,
		"database":    routeToDatabase.Database,
		"username":    routeToDatabase.Username,
	}).Debug("Identified route to database.")

	s.log.Debug("Issuing initial certificate for local proxy.")
	dbCert, err := s.issueCert(ctx, routeToDatabase, roles)
	if err != nil {
		return alpnproxy.LocalProxyConfig{}, trace.Wrap(err)
	}
	s.log.Debug("Issued initial certificate for local proxy.")

	middleware := alpnProxyMiddleware{
		onNewConnection: func(ctx context.Context, lp *alpnproxy.LocalProxy, conn net.Conn) error {
			ctx, span := tracer.Start(ctx, "DatabaseTunnelService/OnNewConnection")
			defer span.End()

			// Check if the certificate needs reissuing, if so, reissue.
			if err := lp.CheckDBCerts(tlsca.RouteToDatabase{
				ServiceName: routeToDatabase.ServiceName,
				Protocol:    routeToDatabase.Protocol,
				Database:    routeToDatabase.Database,
				Username:    routeToDatabase.Username,
			}); err != nil {
				s.log.WithField("reason", err.Error()).Info("Certificate for tunnel needs reissuing.")
				cert, err := s.issueCert(ctx, routeToDatabase, roles)
				if err != nil {
					return trace.Wrap(err, "issuing cert")
				}
				lp.SetCerts([]tls.Certificate{*cert})
			}
			return nil
		},
	}

	alpnProtocol, err := common.ToALPNProtocol(routeToDatabase.Protocol)
	if err != nil {
		return alpnproxy.LocalProxyConfig{}, trace.Wrap(err)

	}
	lpConfig := alpnproxy.LocalProxyConfig{
		Middleware: middleware,

		RemoteProxyAddr:    proxyAddr,
		ParentContext:      ctx,
		Protocols:          []common.Protocol{alpnProtocol},
		Certs:              []tls.Certificate{*dbCert},
		InsecureSkipVerify: s.botCfg.Insecure,
	}
	if client.IsALPNConnUpgradeRequired(
		ctx,
		proxyAddr,
		s.botCfg.Insecure,
	) {
		lpConfig.ALPNConnUpgradeRequired = true
		// If ALPN Conn Upgrade will be used, we need to set the cluster CAs
		// to validate the Proxy's auth issued host cert.
		lpConfig.RootCAs = s.getBotIdentity().TLSCAPool
	}

	return lpConfig, nil
}

func createListener(log logrus.FieldLogger, addr string) (net.Listener, error) {
	parsed, err := url.Parse(addr)
	if err != nil {
		return nil, trace.Wrap(err, "parsing %q", addr)
	}

	switch parsed.Scheme {
	// If no scheme is provided, default to TCP.
	case "tcp", "":
		return net.Listen("tcp", parsed.Host)
	case "unix":
		absPath, err := filepath.Abs(parsed.Path)
		if err != nil {
			return nil, trace.Wrap(err, "resolving absolute path for %q", parsed.Path)
		}

		// Remove the file if it already exists. This is necessary to handle
		// unclean exits.
		if err := os.Remove(absPath); err != nil && !os.IsNotExist(err) {
			log.WithError(err).Warn("Failed to remove existing socket file")
		}

		return net.ListenUnix("unix", &net.UnixAddr{
			Net:  "unix",
			Name: absPath,
		})
	default:
		return nil, trace.BadParameter("unsupported scheme %q", parsed.Scheme)
	}
}

func (s *DatabaseTunnelService) Run(ctx context.Context) error {
	ctx, span := tracer.Start(ctx, "DatabaseTunnelService/Run")
	defer span.End()

	l := s.cfg.Listener
	if l == nil {
		s.log.WithField("address", s.cfg.Listen).Debug("Opening listener for database tunnel.")
		var err error
		l, err = createListener(s.log, s.cfg.Listen)
		if err != nil {
			return trace.Wrap(err, "opening listener")
		}
		defer func() {
			if err := l.Close(); err != nil && !utils.IsUseOfClosedNetworkError(err) {
				s.log.WithError(err).Error("Failed to close listener")
			}
		}()
	}

	lpCfg, err := s.buildLocalProxyConfig(ctx)
	if err != nil {
		return trace.Wrap(err, "building local proxy config")
	}
	lpCfg.Listener = l

	lp, err := alpnproxy.NewLocalProxy(lpCfg)
	if err != nil {
		return trace.Wrap(err, "creating local proxy")
	}
	defer func() {
		if err := lp.Close(); err != nil {
			s.log.WithError(err).Error("Failed to close local proxy")
		}
	}()
	// Closed further down.

	// lp.Start will block and continues to block until lp.Close() is called.
	// Despite taking a context, it will not exit until the first connection is
	// made after the context is canceled.
	var errCh = make(chan error, 1)
	go func() {
		errCh <- lp.Start(ctx)
	}()
	s.log.WithField("address", l.Addr().String()).Info("Listening for connections.")

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return trace.Wrap(err, "local proxy failed")
	}
}

// getRouteToDatabaseWithImpersonation fetches the route to the database with
// impersonation of roles. This ensures that the user's selected roles actually
// grant access to the database.
func (s *DatabaseTunnelService) getRouteToDatabaseWithImpersonation(ctx context.Context, roles []string) (proto.RouteToDatabase, error) {
	ctx, span := tracer.Start(ctx, "DatabaseTunnelService/getRouteToDatabaseWithImpersonation")
	defer span.End()

	impersonatedIdentity, err := generateIdentity(
		ctx,
		s.botClient,
		s.getBotIdentity(),
		roles,
		s.botCfg.CertificateTTL,
		nil,
	)
	if err != nil {
		return proto.RouteToDatabase{}, trace.Wrap(err)
	}

	impersonatedClient, err := clientForFacade(
		ctx,
		s.log,
		s.botCfg,
		identity.NewFacade(s.botCfg.FIPS, s.botCfg.Insecure, impersonatedIdentity),
		s.resolver,
	)
	if err != nil {
		return proto.RouteToDatabase{}, trace.Wrap(err)
	}
	defer func() {
		if err := impersonatedClient.Close(); err != nil {
			s.log.WithError(err).Error("Failed to close impersonated client.")
		}
	}()

	return getRouteToDatabase(ctx, s.log, impersonatedClient, s.cfg.Service, s.cfg.Username, s.cfg.Database)
}

func (s *DatabaseTunnelService) issueCert(
	ctx context.Context,
	route proto.RouteToDatabase,
	roles []string,
) (*tls.Certificate, error) {
	ctx, span := tracer.Start(ctx, "DatabaseTunnelService/issueCert")
	defer span.End()

	s.log.Debug("Requesting issuance of certificate for tunnel proxy.")
	ident, err := generateIdentity(
		ctx,
		s.botClient,
		s.getBotIdentity(),
		roles,
		s.botCfg.CertificateTTL,
		func(req *proto.UserCertsRequest) {
			req.RouteToDatabase = route
		})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	s.log.Info("Certificate issued for tunnel proxy.")

	return ident.TLSCert, nil
}

// String returns a human-readable string that can uniquely identify the
// service.
func (s *DatabaseTunnelService) String() string {
	return fmt.Sprintf("%s:%s:%s", config.DatabaseTunnelServiceType, s.cfg.Listen, s.cfg.Service)
}
