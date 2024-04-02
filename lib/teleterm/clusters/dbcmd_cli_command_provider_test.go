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

package clusters

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/teleterm/api/uri"
	"github.com/gravitational/teleport/lib/teleterm/cmd/cmds"
	"github.com/gravitational/teleport/lib/teleterm/gateway"
	"github.com/gravitational/teleport/lib/teleterm/gatewaytest"
	"github.com/gravitational/teleport/lib/tlsca"
)

type fakeExec struct{}

func (f fakeExec) RunCommand(cmd string, _ ...string) ([]byte, error) {
	return []byte(""), nil
}

func (f fakeExec) LookPath(path string) (string, error) {
	return "", nil
}

func (f fakeExec) Command(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	cmd.Path = filepath.Base(cmd.Path)
	return cmd
}

type fakeStorage struct {
	clusters []*Cluster
}

func (f fakeStorage) GetByResourceURI(resourceURI string) (*Cluster, error) {
	for _, cluster := range f.clusters {
		if strings.HasPrefix(resourceURI, cluster.URI.String()) {
			return cluster, nil
		}
	}

	return nil, trace.NotFound("not found")
}

func TestDbcmdCLICommandProviderGetCommand(t *testing.T) {
	testCases := []struct {
		name                  string
		targetSubresourceName string
		argsCount             int
		protocol              string
		checkCmds             func(*testing.T, *gateway.Gateway, cmds.Cmds)
	}{
		{
			name:                  "empty name",
			protocol:              defaults.ProtocolMongoDB,
			targetSubresourceName: "",
			checkCmds:             checkMongoCmds,
		},
		{
			name:                  "with name",
			protocol:              defaults.ProtocolMongoDB,
			targetSubresourceName: "bar",
			checkCmds:             checkMongoCmds,
		},
		{
			name:                  "custom handling of DynamoDB does not blow up",
			targetSubresourceName: "bar",
			protocol:              defaults.ProtocolDynamoDB,
			checkCmds:             checkArgsNotEmpty,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cluster := Cluster{
				URI:  uri.NewClusterURI("quux"),
				Name: "quux",
				clusterClient: &client.TeleportClient{
					Config: client.Config{
						SiteName: "",
					},
				},
			}
			fakeStorage := fakeStorage{
				clusters: []*Cluster{&cluster},
			}
			dbcmdCLICommandProvider := NewDbcmdCLICommandProvider(fakeStorage, fakeExec{})

			keyPairPaths := gatewaytest.MustGenAndSaveCert(t, tlsca.Identity{
				Username: "alice",
				Groups:   []string{"test-group"},
				RouteToDatabase: tlsca.RouteToDatabase{
					ServiceName: "foo",
					Protocol:    tc.protocol,
					Username:    "alice",
				},
			})

			gateway, err := gateway.New(
				gateway.Config{
					TargetURI:             cluster.URI.AppendDB("foo").String(),
					TargetName:            "foo",
					TargetUser:            "alice",
					TargetSubresourceName: tc.targetSubresourceName,
					Protocol:              tc.protocol,
					LocalAddress:          "localhost",
					WebProxyAddr:          "localhost:1337",
					Insecure:              true,
					CertPath:              keyPairPaths.CertPath,
					KeyPath:               keyPairPaths.KeyPath,
					CLICommandProvider:    dbcmdCLICommandProvider,
					TCPPortAllocator:      gateway.NetTCPPortAllocator{},
				},
			)
			require.NoError(t, err)
			t.Cleanup(func() { gateway.Close() })

			cmds, err := dbcmdCLICommandProvider.GetCommand(gateway)

			require.NoError(t, err)

			tc.checkCmds(t, gateway, cmds)
		})
	}
}

func TestDbcmdCLICommandProviderGetCommand_ReturnsErrorIfClusterIsNotFound(t *testing.T) {
	fakeStorage := fakeStorage{
		clusters: []*Cluster{},
	}
	dbcmdCLICommandProvider := NewDbcmdCLICommandProvider(fakeStorage, fakeExec{})

	keyPairPaths := gatewaytest.MustGenAndSaveCert(t, tlsca.Identity{
		Username: "alice",
		Groups:   []string{"test-group"},
		RouteToDatabase: tlsca.RouteToDatabase{
			ServiceName: "foo",
			Protocol:    defaults.ProtocolPostgres,
			Username:    "alice",
		},
	})

	gateway, err := gateway.New(
		gateway.Config{
			TargetURI:             uri.NewClusterURI("quux").AppendDB("foo").String(),
			TargetName:            "foo",
			TargetUser:            "alice",
			TargetSubresourceName: "",
			Protocol:              defaults.ProtocolPostgres,
			LocalAddress:          "localhost",
			WebProxyAddr:          "localhost:1337",
			Insecure:              true,
			CertPath:              keyPairPaths.CertPath,
			KeyPath:               keyPairPaths.KeyPath,
			CLICommandProvider:    dbcmdCLICommandProvider,
			TCPPortAllocator:      gateway.NetTCPPortAllocator{},
		},
	)
	require.NoError(t, err)
	t.Cleanup(func() { gateway.Close() })

	_, err = dbcmdCLICommandProvider.GetCommand(gateway)
	require.Error(t, err)
	require.True(t, trace.IsNotFound(err), "err is not trace.NotFound")
}

func checkMongoCmds(t *testing.T, gw *gateway.Gateway, cmds cmds.Cmds) {
	t.Helper()
	require.Len(t, cmds.Exec.Args, 2)
	require.Len(t, cmds.Preview.Args, 2)

	execConnString := cmds.Exec.Args[1]
	previewConnString := cmds.Preview.Args[1]

	require.Contains(t, execConnString, gw.TargetSubresourceName())
	require.Contains(t, previewConnString, gw.TargetSubresourceName())
	require.Contains(t, execConnString, gw.LocalPort())
	require.Contains(t, previewConnString, gw.LocalPort())

	// Verify that the preview cmd has exec cmd conn string wrapped in quotes.
	require.NotContains(t, execConnString, "\"")
	expectedPreviewConnString := fmt.Sprintf("%q", execConnString)
	require.Equal(t, expectedPreviewConnString, previewConnString)
}

func checkArgsNotEmpty(t *testing.T, gw *gateway.Gateway, cmds cmds.Cmds) {
	t.Helper()
	require.NotEmpty(t, cmds.Exec.Args)
	require.NotEmpty(t, cmds.Preview.Args)
}
