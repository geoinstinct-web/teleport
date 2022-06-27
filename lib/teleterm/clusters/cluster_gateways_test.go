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
	"testing"

	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/teleterm/api/uri"
	"github.com/gravitational/teleport/lib/teleterm/gateway"

	"github.com/stretchr/testify/require"
)

type mockCLICommandProvider struct{}

func (m mockCLICommandProvider) GetCommand(cluster *Cluster, gateway *gateway.Gateway) (*string, error) {
	command := fmt.Sprintf("%s/%s", gateway.TargetName, gateway.TargetSubresourceName)
	return &command, nil
}

func TestSetGatewayTargetSubresourceName(t *testing.T) {
	clusterClient := client.TeleportClient{Config: client.Config{}}

	cluster := Cluster{
		URI:                uri.NewClusterURI("test"),
		Name:               "test",
		clusterClient:      &clusterClient,
		cliCommandProvider: &mockCLICommandProvider{},
	}

	gateway := gateway.Gateway{
		CLICommand: "",
		Config: gateway.Config{
			TargetName: "foo",
			Protocol:   defaults.ProtocolPostgres,
		},
	}

	err := cluster.SetGatewayTargetSubresourceName(&gateway, "bar")
	require.NoError(t, err)

	require.Equal(t, "bar", gateway.TargetSubresourceName)
	require.Equal(t, "foo/bar", gateway.CLICommand)
}
