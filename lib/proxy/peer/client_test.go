/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
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

package peer

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/connectivity"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
)

// TestClientConn checks the client's connection caching capabilities
func TestClientConn(t *testing.T) {
	ca := newSelfSignedCA(t)

	client := setupClient(t, ca, ca, types.RoleProxy)
	_, def1 := setupServer(t, "s1", ca, ca, types.RoleProxy)
	server2, def2 := setupServer(t, "s2", ca, ca, types.RoleProxy)

	// simulate watcher finding two servers
	err := client.updateConnections([]types.Server{def1, def2})
	require.NoError(t, err)
	require.Len(t, client.conns, 2)

	// dial first server and send a test data frame
	stream, cached, err := client.dial([]string{"s1"}, &proto.DialRequest{})
	require.NoError(t, err)
	require.True(t, cached)
	require.NotNil(t, stream)
	stream.CloseSend()

	// dial second server
	stream, cached, err = client.dial([]string{"s2"}, &proto.DialRequest{})
	require.NoError(t, err)
	require.True(t, cached)
	require.NotNil(t, stream)
	stream.CloseSend()

	// redial second server
	stream, cached, err = client.dial([]string{"s2"}, &proto.DialRequest{})
	require.NoError(t, err)
	require.True(t, cached)
	require.NotNil(t, stream)
	stream.CloseSend()

	// close second server
	// and attempt to redial it
	server2.Shutdown()
	stream, cached, err = client.dial([]string{"s2"}, &proto.DialRequest{})
	require.Error(t, err)
	require.True(t, cached)
	require.Nil(t, stream)
}

// TestClientUpdate checks the client's watcher update behavior
func TestClientUpdate(t *testing.T) {
	ca := newSelfSignedCA(t)

	client := setupClient(t, ca, ca, types.RoleProxy)
	_, def1 := setupServer(t, "s1", ca, ca, types.RoleProxy)
	server2, def2 := setupServer(t, "s2", ca, ca, types.RoleProxy)

	// watcher finds two servers
	err := client.updateConnections([]types.Server{def1, def2})
	require.NoError(t, err)
	require.Len(t, client.conns, 2)
	require.Contains(t, client.conns, "s1")
	require.Contains(t, client.conns, "s2")

	s1, _, err := client.dial([]string{"s1"}, &proto.DialRequest{})
	require.NoError(t, err)
	require.NotNil(t, s1)
	s2, _, err := client.dial([]string{"s2"}, &proto.DialRequest{})
	require.NoError(t, err)
	require.NotNil(t, s2)

	// watcher finds one of the two servers
	err = client.updateConnections([]types.Server{def1})
	require.NoError(t, err)
	require.Len(t, client.conns, 1)
	require.Contains(t, client.conns, "s1")
	sendMsg(t, s1) // stream is not broken across updates
	sendMsg(t, s2) // stream is not forcefully closed. ClientConn waits for a graceful shutdown before it closes.

	s2.CloseSend()

	// watcher finds two servers with one broken connection
	server2.Shutdown()
	err = client.updateConnections([]types.Server{def1, def2})
	require.NoError(t, err) // server2 is in a transient failure state but not reported as an error
	require.Len(t, client.conns, 2)
	require.Contains(t, client.conns, "s1")
	sendMsg(t, s1) // stream is still going strong
	_, _, err = client.dial([]string{"s2"}, &proto.DialRequest{})
	require.Error(t, err) // can't dial server2, obviously

	// peer address change
	_, def3 := setupServer(t, "s1", ca, ca, types.RoleProxy)
	err = client.updateConnections([]types.Server{def3})
	require.NoError(t, err)
	require.Len(t, client.conns, 1)
	require.Contains(t, client.conns, "s1")
	sendMsg(t, s1) // stream is not forcefully closed. ClientConn waits for a graceful shutdown before it closes.
	s3, _, err := client.dial([]string{"s1"}, &proto.DialRequest{})
	require.NoError(t, err)
	require.NotNil(t, s3)

	s1.CloseSend()
	s3.CloseSend()
}

func TestCAChange(t *testing.T) {
	clientCA := newSelfSignedCA(t)
	serverCA := newSelfSignedCA(t)

	client := setupClient(t, clientCA, serverCA, types.RoleProxy)
	server, _ := setupServer(t, "s1", serverCA, clientCA, types.RoleProxy)

	// dial server and send a test data frame
	conn, err := client.connect("s1", server.config.Listener.Addr().String())
	require.NoError(t, err)
	require.NotNil(t, conn)
	stream, err := client.startStream(conn)
	require.NoError(t, err)
	require.NotNil(t, stream)
	stream.CloseSend()

	// rotate server ca
	require.NoError(t, server.Close())
	newServerCA := newSelfSignedCA(t)
	server, _ = setupServer(t, "s1", newServerCA, clientCA, types.RoleProxy)

	// new connection should fail because client tls config still references old
	// RootCAs.
	conn, err = client.connect("s1", server.config.Listener.Addr().String())
	require.NoError(t, err)
	require.NotNil(t, conn)
	stream, err = client.startStream(conn)
	require.Error(t, err)
	require.Nil(t, stream)

	// new connection should succeed because client tls config references new
	// RootCAs.
	client.config.getConfigForServer = func() (*tls.Config, error) {
		config := client.config.TLSConfig.Clone()
		rootCAs := x509.NewCertPool()
		rootCAs.AddCert(newServerCA.Cert)
		config.RootCAs = rootCAs
		return config, nil
	}

	conn, err = client.connect("s1", server.config.Listener.Addr().String())
	require.NoError(t, err)
	require.NotNil(t, conn)
	stream, err = client.startStream(conn)
	require.NoError(t, err)
	require.NotNil(t, stream)
	stream.CloseSend()
}

func TestBackupClient(t *testing.T) {
	ca := newSelfSignedCA(t)
	client := setupClient(t, ca, ca, types.RoleProxy)
	dialCalled := false

	// Force the first client connection to fail.
	_, def1 := setupServer(t, "s1", ca, ca, types.RoleProxy, func(c *ServerConfig) {
		c.service = &mockProxyService{
			mockDialNode: func(stream proto.ProxyService_DialNodeServer) error {
				dialCalled = true
				return trace.NotFound("tunnel not found")
			},
		}
	})
	_, def2 := setupServer(t, "s2", ca, ca, types.RoleProxy)

	err := client.updateConnections([]types.Server{def1, def2})
	require.NoError(t, err)
	waitForConns(t, client.conns, time.Second*2)

	_, _, err = client.dial([]string{def1.GetName(), def2.GetName()}, &proto.DialRequest{})
	require.NoError(t, err)
	require.True(t, dialCalled)
}

func waitForConns(t *testing.T, conns map[string]*clientConn, d time.Duration) {
	require.Eventually(t, func() bool {
		for _, conn := range conns {
			if conn.GetState() != connectivity.Ready {
				return false
			}
		}
		return true
	}, d, time.Millisecond*5)
}
