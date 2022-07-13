/*
Copyright 2017-2018 Gravitational, Inc.

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

package local

import (
	"context"
	"testing"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/memory"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/suite"

	"github.com/google/go-cmp/cmp"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

type configContext struct {
	bk backend.Backend
}

func setupConfigContext(ctx context.Context, t *testing.T) *configContext {
	var tt configContext
	t.Cleanup(func() { tt.Close() })

	clock := clockwork.NewFakeClock()

	var err error
	tt.bk, err = memory.New(memory.Config{
		Context: context.Background(),
		Clock:   clock,
	})
	require.NoError(t, err)

	return &tt
}

func (tt *configContext) Close() error {
	return tt.bk.Close()
}

func TestAuthPreference(t *testing.T) {
	tt := setupConfigContext(context.Background(), t)

	clusterConfig, err := NewClusterConfigurationService(tt.bk)
	require.NoError(t, err)

	suite := &suite.ServicesTestSuite{
		ConfigS: clusterConfig,
	}
	suite.AuthPreference(t)
}

func TestClusterName(t *testing.T) {
	tt := setupConfigContext(context.Background(), t)

	clusterConfig, err := NewClusterConfigurationService(tt.bk)
	require.NoError(t, err)

	suite := &suite.ServicesTestSuite{
		ConfigS: clusterConfig,
	}
	suite.ClusterName(t)
}

func TestClusterNetworkingConfig(t *testing.T) {
	tt := setupConfigContext(context.Background(), t)

	clusterConfig, err := NewClusterConfigurationService(tt.bk)
	require.NoError(t, err)

	suite := &suite.ServicesTestSuite{
		ConfigS: clusterConfig,
	}
	suite.ClusterNetworkingConfig(t)
}

func TestSessionRecordingConfig(t *testing.T) {
	tt := setupConfigContext(context.Background(), t)

	clusterConfig, err := NewClusterConfigurationService(tt.bk)
	require.NoError(t, err)

	suite := &suite.ServicesTestSuite{
		ConfigS: clusterConfig,
	}
	suite.SessionRecordingConfig(t)
}

func TestStaticTokens(t *testing.T) {
	tt := setupConfigContext(context.Background(), t)

	clusterConfig, err := NewClusterConfigurationService(tt.bk)
	require.NoError(t, err)

	suite := &suite.ServicesTestSuite{
		ConfigS: clusterConfig,
	}
	suite.StaticTokens(t)
}

func TestSessionRecording(t *testing.T) {
	// don't allow invalid session recording values
	_, err := types.NewSessionRecordingConfigFromConfigFile(types.SessionRecordingConfigSpecV2{
		Mode: "foo",
	})
	require.Error(t, err)

	// default is to record at the node
	recConfig, err := types.NewSessionRecordingConfigFromConfigFile(types.SessionRecordingConfigSpecV2{})
	require.NoError(t, err)
	require.Equal(t, recConfig.GetMode(), types.RecordAtNode)

	// update sessions to be recorded at the proxy and check again
	recConfig.SetMode(types.RecordAtProxy)
	require.Equal(t, recConfig.GetMode(), types.RecordAtProxy)
}

func TestAuditConfig(t *testing.T) {
	testCases := []struct {
		spec   types.ClusterAuditConfigSpecV2
		config string
	}{
		{
			spec: types.ClusterAuditConfigSpecV2{
				Region:           "us-west-1",
				Type:             "dynamodb",
				AuditSessionsURI: "file:///home/log",
				AuditEventsURI:   []string{"dynamodb://audit_table_name", "file:///home/log"},
			},
			config: `
region: 'us-west-1'
type: 'dynamodb'
audit_sessions_uri: file:///home/log
audit_events_uri: ['dynamodb://audit_table_name', 'file:///home/log']
`,
		},
		{
			spec: types.ClusterAuditConfigSpecV2{
				Region:           "us-west-1",
				Type:             "dir",
				AuditSessionsURI: "file:///home/log",
				AuditEventsURI:   []string{"dynamodb://audit_table_name"},
			},
			config: `
region: 'us-west-1'
type: 'dir'
audit_sessions_uri: file:///home/log
audit_events_uri: 'dynamodb://audit_table_name'
`,
		},
	}

	for _, tc := range testCases {
		in, err := types.NewClusterAuditConfig(tc.spec)
		require.NoError(t, err)

		var data map[string]interface{}
		err = yaml.Unmarshal([]byte(tc.config), &data)
		require.NoError(t, err)

		configSpec, err := services.ClusterAuditConfigSpecFromObject(data)
		require.NoError(t, err)

		out, err := types.NewClusterAuditConfig(*configSpec)
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(out, in))
	}
}

func TestAuditConfigMarshal(t *testing.T) {
	// single audit_events uri value
	auditConfig, err := types.NewClusterAuditConfig(types.ClusterAuditConfigSpecV2{
		Region:           "us-west-1",
		Type:             "dynamodb",
		AuditSessionsURI: "file:///home/log",
		AuditEventsURI:   []string{"dynamodb://audit_table_name"},
	})
	require.NoError(t, err)

	data, err := services.MarshalClusterAuditConfig(auditConfig)
	require.NoError(t, err)

	out, err := services.UnmarshalClusterAuditConfig(data)
	require.NoError(t, err)
	require.Empty(t, cmp.Diff(auditConfig, out))

	// multiple events uri values
	auditConfig, err = types.NewClusterAuditConfig(types.ClusterAuditConfigSpecV2{
		Region:           "us-west-1",
		Type:             "dynamodb",
		AuditSessionsURI: "file:///home/log",
		AuditEventsURI:   []string{"dynamodb://audit_table_name", "file:///home/test/log"},
	})
	require.NoError(t, err)

	data, err = services.MarshalClusterAuditConfig(auditConfig)
	require.NoError(t, err)

	out, err = services.UnmarshalClusterAuditConfig(data)
	require.NoError(t, err)
	require.Empty(t, cmp.Diff(auditConfig, out))
}
