/*
Copyright 2023 Gravitational, Inc.

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
package service

import (
	"context"
	"testing"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	clusterconfigpb "github.com/gravitational/teleport/api/gen/proto/go/teleport/clusterconfig/v1"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/service/servicecfg"
	"github.com/gravitational/teleport/lib/srv/discovery"
)

func TestTeleportProcessIntegrationsOnly(t *testing.T) {
	for _, tt := range []struct {
		name              string
		inputFeatureCloud bool
		inputAuthEnabled  bool
		integrationOnly   bool
	}{
		{
			name:              "self-hosted",
			inputFeatureCloud: false,
			inputAuthEnabled:  false,
			integrationOnly:   false,
		},
		{
			name:              "cloud but discovery service is not running side-by-side with Auth",
			inputFeatureCloud: false,
			inputAuthEnabled:  true,
			integrationOnly:   false,
		},
		{
			name:              "cloud and discovery service is not running side-by-side with Auth",
			inputFeatureCloud: false,
			inputAuthEnabled:  true,
			integrationOnly:   false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := TeleportProcess{
				Config: &servicecfg.Config{
					Auth: servicecfg.AuthConfig{
						Enabled: tt.inputAuthEnabled,
					},
				},
			}

			modules.SetTestModules(t, &modules.TestModules{TestFeatures: modules.Features{
				Cloud: tt.inputFeatureCloud,
			}})

			require.Equal(t, tt.integrationOnly, p.integrationOnlyCredentials())
		})
	}
}

func TestTeleportProcess_initDiscoveryService(t *testing.T) {

	tests := []struct {
		name      string
		cfg       servicecfg.AccessGraphConfig
		rsp       *clusterconfigpb.AccessGraphConfig
		err       error
		want      discovery.AccessGraphConfig
		assertErr require.ErrorAssertionFunc
	}{
		{
			name: "local access graph",
			cfg: servicecfg.AccessGraphConfig{
				Enabled:  true,
				Addr:     "localhost:5000",
				Insecure: true,
			},
			rsp: nil,
			err: nil,
			want: discovery.AccessGraphConfig{
				Enabled:  true,
				Addr:     "localhost:5000",
				Insecure: true,
			},
			assertErr: require.NoError,
		},
		{
			name: "access graph disabled locally but enabled in auth",
			cfg: servicecfg.AccessGraphConfig{
				Enabled: false,
			},
			rsp: &clusterconfigpb.AccessGraphConfig{
				Enabled:  true,
				Address:  "localhost:5000",
				Insecure: true,
			},
			err: nil,
			want: discovery.AccessGraphConfig{
				Enabled:  true,
				Addr:     "localhost:5000",
				Insecure: true,
			},
			assertErr: require.NoError,
		},
		{
			name: "access graph disabled locally and auth doesn't implement GetClusterAccessGraphConfig",
			cfg: servicecfg.AccessGraphConfig{
				Enabled: false,
			},
			rsp: nil,
			err: trace.NotImplemented("err"),
			want: discovery.AccessGraphConfig{
				Enabled: false,
			},
			assertErr: require.NoError,
		},
		{
			name: "access graph disabled locally and auth call fails",
			cfg: servicecfg.AccessGraphConfig{
				Enabled: false,
			},
			rsp: nil,
			err: trace.BadParameter("err"),
			want: discovery.AccessGraphConfig{
				Enabled: false,
			},
			assertErr: require.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accessGraphCfg, err := buildAccessGraphFromTAGOrFallbackToAuth(
				context.Background(),
				&servicecfg.Config{
					AccessGraph: tt.cfg,
				},
				&fakeClient{
					rsp: tt.rsp,
					err: tt.err,
				},
				logrus.StandardLogger(),
			)
			tt.assertErr(t, err)
			require.Equal(t, tt.want, accessGraphCfg)
		})
	}
}

type fakeClient struct {
	authclient.ClientI
	rsp *clusterconfigpb.AccessGraphConfig
	err error
}

func (f *fakeClient) GetClusterAccessGraphConfig(ctx context.Context) (*clusterconfigpb.AccessGraphConfig, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.rsp, nil
}
