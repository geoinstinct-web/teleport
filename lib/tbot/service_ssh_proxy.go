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
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh/agent"
	"google.golang.org/grpc"

	proxyclient "github.com/gravitational/teleport/api/client/proxy"
	"github.com/gravitational/teleport/api/observability/tracing"
	"github.com/gravitational/teleport/api/utils/grpc/interceptors"
	"github.com/gravitational/teleport/lib/auth/authclient"
	libclient "github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/resumption"
	"github.com/gravitational/teleport/lib/reversetunnelclient"
	"github.com/gravitational/teleport/lib/tbot/config"
	"github.com/gravitational/teleport/lib/utils"
)

// SSHProxyService
type SSHProxyService struct {
	cfg              *config.SSHProxyService
	botCfg           *config.BotConfig
	svcIdentity      *config.UnstableClientCredentialOutput
	log              *slog.Logger
	proxyPingCache   *proxyPingCache
	alpnUpgradeCache *alpnProxyConnUpgradeRequiredCache
	resolver         reversetunnelclient.Resolver

	// Fields below here are initialized by the service itself on startup.
	authClient  *authclient.Client
	proxyClient *proxyclient.Client
	tshConfig   *libclient.TSHConfig
	proxyHost   string
	clusterName string
}

func (s *SSHProxyService) setup(ctx context.Context) (net.Listener, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(10 * time.Second):
		return nil, trace.BadParameter("timeout waiting for identity to be ready")
	case <-s.svcIdentity.Ready():
	}
	facade, err := s.svcIdentity.Facade()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	sshConfig, err := facade.SSHClientConfig()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	s.clusterName = facade.Get().ClusterName

	proxyPing, err := s.proxyPingCache.ping(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	proxyAddr := proxyPing.Proxy.SSH.PublicAddr
	proxyHost, _, err := net.SplitHostPort(proxyPing.Proxy.SSH.PublicAddr)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	s.proxyHost = proxyHost

	connUpgradeRequired := false
	if proxyPing.Proxy.TLSRoutingEnabled {
		connUpgradeRequired, err = s.alpnUpgradeCache.isUpgradeRequired(
			ctx, proxyAddr, s.botCfg.Insecure,
		)
		if err != nil {
			return nil, trace.Wrap(err, "determining if ALPN upgrade is required")
		}
	}

	proxyClient, err := proxyclient.NewClient(ctx, proxyclient.ClientConfig{
		ProxyAddress:      proxyAddr,
		TLSRoutingEnabled: proxyPing.Proxy.TLSRoutingEnabled,
		TLSConfigFunc: func(cluster string) (*tls.Config, error) {
			cfg, err := facade.TLSConfig()
			if err != nil {
				return nil, trace.Wrap(err)
			}

			// The facade TLS config is tailored toward connections to the Auth service.
			// Override the server name to be the proxy and blank out the next protos to
			// avoid hitting the proxy web listener.
			cfg.ServerName = proxyHost
			cfg.NextProtos = nil
			return cfg, nil
		},
		UnaryInterceptors: []grpc.UnaryClientInterceptor{
			interceptors.GRPCClientUnaryErrorInterceptor,
		},
		StreamInterceptors: []grpc.StreamClientInterceptor{
			interceptors.GRPCClientStreamErrorInterceptor,
		},
		SSHConfig:               sshConfig,
		InsecureSkipVerify:      s.botCfg.Insecure,
		ALPNConnUpgradeRequired: connUpgradeRequired,

		DialContext: dialCycling,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer proxyClient.Close()
	s.proxyClient = proxyClient

	authClient, err := clientForFacade(
		ctx, s.log, s.botCfg, facade, s.resolver,
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	s.authClient = authClient

	dest := s.cfg.Destination.(*config.DestinationDirectory)
	l, err := createListener(ctx, s.log, fmt.Sprintf("unix://%s", dest.Path))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return l, nil
}

func (s *SSHProxyService) Run(ctx context.Context) error {
	l, err := s.setup(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	defer context.AfterFunc(ctx, func() { _ = l.Close() })()
	for {
		downstream, err := l.Accept()
		if err != nil {
			s.log.WarnContext(ctx, "Accept error, sleeping and continuing", "error", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}

		go func() {
			err := s.handleConn(ctx, downstream)
			if err != nil {
				s.log.WarnContext(ctx, "Handler exited", "error", err)
			}
		}()
	}
}

func (s *SSHProxyService) handleConn(
	ctx context.Context,
	downstream net.Conn,
) (err error) {
	ctx, span := tracer.Start(ctx, "SPIFFEWorkloadAPIService/handleConn")
	defer func() { tracing.EndSpan(span, err) }()
	defer downstream.Close()

	buf := bufio.NewReader(downstream)
	hostPort, err := buf.ReadString('\n')
	if err != nil {
		return trace.Wrap(err)
	}
	hostPort = hostPort[:len(hostPort)-1]

	s.log.Info("handling new connection", "host_port", hostPort)
	defer s.log.Info("finished handling connection", "host_port", hostPort)

	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return trace.Wrap(err)
	}

	clusterName := s.clusterName
	expanded, matched := s.tshConfig.ProxyTemplates.Apply(hostPort)
	if matched {
		s.log.DebugContext(
			ctx,
			"proxy templated matched",
			"populated_template", expanded,
		)
		if expanded.Cluster != "" {
			clusterName = expanded.Cluster
		}

		if expanded.Host != "" {
			host = expanded.Host
		}
	}

	var target string
	if expanded == nil || (len(expanded.Search) == 0 && expanded.Query == "") {
		host = cleanTargetHost(host, s.proxyHost, clusterName)
		target = net.JoinHostPort(host, port)
	} else {
		node, err := resolveTargetHostWithClient(ctx, s.authClient, expanded.Search, expanded.Query)
		if err != nil {
			return trace.Wrap(err)
		}

		s.log.DebugContext(
			ctx,
			"found matching SSH host",
			"host_uuid", node.GetName(),
			"host_name", node.GetHostname(),
		)

		target = net.JoinHostPort(node.GetName(), "0")
	}

	upstream, _, err := s.proxyClient.DialHost(ctx, target, clusterName, nil)
	if err != nil {
		return trace.Wrap(err)
	}
	if s.cfg.EnableResumption {
		upstream, err = resumption.WrapSSHClientConn(
			ctx,
			upstream,
			func(ctx context.Context, hostID string) (net.Conn, error) {
				// if the connection is being resumed, it means that
				// we didn't need the agent in the first place
				var noAgent agent.ExtendedAgent
				conn, _, err := s.proxyClient.DialHost(ctx, net.JoinHostPort(hostID, "0"), clusterName, noAgent)
				return conn, err
			})
		if err != nil {
			return trace.Wrap(err)
		}
	}
	defer upstream.Close()

	// This AfterFunc exists to interrupt the copy operations if the context is
	// cancelled
	defer context.AfterFunc(ctx, func() {
		_ = upstream.Close()
		_ = downstream.Close()
	})()
	errC := make(chan error, 2)
	go func() {
		defer upstream.Close()
		defer downstream.Close()
		_, err := io.CopyN(upstream, buf, int64(buf.Buffered()))
		if err != nil {
			errC <- err
			return
		}
		_, err = io.Copy(upstream, downstream)
		errC <- err
	}()
	go func() {
		defer upstream.Close()
		defer downstream.Close()
		_, err := io.Copy(downstream, upstream)
		errC <- err
	}()

	err = trace.NewAggregate(<-errC, <-errC)
	if utils.IsOKNetworkError(err) {
		err = nil
	}
	return err
}

func (s *SSHProxyService) String() string {
	return config.SSHProxyServiceType
}
