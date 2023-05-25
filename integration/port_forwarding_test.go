/*
Copyright 2021 Gravitational, Inc.

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

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/user"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/integration/helpers"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/utils"
)

func extractPort(svr *httptest.Server) (int, error) {
	u, err := url.Parse(svr.URL)
	if err != nil {
		return 0, trace.Wrap(err)
	}
	n, err := strconv.Atoi(u.Port())
	if err != nil {
		return 0, trace.Wrap(err)
	}
	return n, nil
}

func waitForSessionToBeEstablished(ctx context.Context, namespace string, site auth.ClientI) ([]types.SessionTracker, error) {

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()

		case <-ticker.C:
			ss, err := site.GetActiveSessionTrackers(ctx)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			if len(ss) > 0 {
				return ss, nil
			}
		}
	}
}

func testPortForwarding(t *testing.T, suite *integrationTestSuite) {
	invalidOSLogin := uuid.NewString()[:12]
	notFound := false
	for i := 0; i < 10; i++ {
		if _, err := user.Lookup(invalidOSLogin); err == nil {
			invalidOSLogin = uuid.NewString()[:12]
			continue
		}
		notFound = true
		break
	}
	require.True(t, notFound, "unable to locate invalid os user")

	// Providing our own logins to Teleport so we can verify that a user
	// that exists within Teleport but does not exist on the local node
	// cannot port forward.
	logins := []string{
		invalidOSLogin,
		suite.Me.Username,
	}

	testCases := []struct {
		desc                  string
		portForwardingAllowed bool
		expectSuccess         bool
		login                 string
		labels                map[string]string
	}{
		{
			desc:                  "Enabled",
			portForwardingAllowed: true,
			expectSuccess:         true,
			login:                 suite.Me.Username,
		},
		{
			desc:                  "Disabled",
			portForwardingAllowed: false,
			expectSuccess:         false,
			login:                 suite.Me.Username,
		},
		{
			desc:                  "Enabled with invalid user",
			portForwardingAllowed: true,
			expectSuccess:         false,
			login:                 invalidOSLogin,
		},
		{
			desc:                  "Enabled with labels",
			portForwardingAllowed: true,
			expectSuccess:         true,
			login:                 suite.Me.Username,
			labels:                map[string]string{"foo": "bar"},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.desc, func(t *testing.T) {
			// Given a running teleport instance with port forwarding
			// permissions set per the test case
			recCfg, err := types.NewSessionRecordingConfigFromConfigFile(types.SessionRecordingConfigSpecV2{
				Mode: types.RecordOff,
			})
			require.NoError(t, err)

			cfg := suite.defaultServiceConfig()
			cfg.Auth.Enabled = true
			cfg.Auth.Preference.SetSecondFactor("off")
			cfg.Auth.NoAudit = true
			cfg.Auth.SessionRecordingConfig = recCfg
			cfg.Proxy.Enabled = true
			cfg.Proxy.DisableWebService = false
			cfg.Proxy.DisableWebInterface = true
			cfg.SSH.Enabled = true
			cfg.SSH.AllowTCPForwarding = tt.portForwardingAllowed
			cfg.SSH.Labels = map[string]string{"foo": "bar"}

			privateKey, publicKey, err := testauthority.New().GenerateKeyPair()
			require.NoError(t, err)

			instance := helpers.NewInstance(t, helpers.InstanceConfig{
				ClusterName: helpers.Site,
				HostID:      uuid.New().String(),
				NodeName:    Host,
				Priv:        privateKey,
				Pub:         publicKey,
				Log:         utils.NewLoggerForTests(),
			})

			for _, login := range logins {
				instance.AddUser(login, []string{login})
			}

			// create and launch the auth server
			err = instance.CreateEx(t, nil, cfg)
			require.NoError(t, err)

			require.NoError(t, instance.Start())
			t.Cleanup(func() {
				require.NoError(t, instance.StopAll())
			})

			// create an node instance
			privateKey, publicKey, err = testauthority.New().GenerateKeyPair()
			require.NoError(t, err)

			node := helpers.NewInstance(t, helpers.InstanceConfig{
				ClusterName: helpers.Site,
				HostID:      uuid.New().String(),
				NodeName:    Host,
				Priv:        privateKey,
				Pub:         publicKey,
				Log:         utils.NewLoggerForTests(),
			})

			// Create node config.
			nodeCfg := service.MakeDefaultConfig()
			nodeCfg.SetAuthServerAddress(cfg.Auth.ListenAddr)
			nodeCfg.SetToken("token")
			nodeCfg.CachePolicy.Enabled = true
			nodeCfg.DataDir = t.TempDir()
			nodeCfg.Console = nil
			nodeCfg.Auth.Enabled = false
			nodeCfg.Proxy.Enabled = false
			nodeCfg.SSH.Enabled = true
			nodeCfg.SSH.AllowTCPForwarding = tt.portForwardingAllowed
			nodeCfg.SSH.Labels = map[string]string{"foo": "bar"}

			err = node.CreateWithConf(t, nodeCfg)
			require.NoError(t, err)

			require.NoError(t, node.Start())
			t.Cleanup(func() {
				require.NoError(t, node.StopAll())
			})

			site := instance.GetSiteAPI(helpers.Site)

			// ...and a running dummy server
			remoteSvr := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Hello, World"))
				}))
			defer remoteSvr.Close()

			// ... and a client connection that was launched with port
			// forwarding enabled to that dummy server
			localPort := newPortValue()
			remotePort, err := extractPort(remoteSvr)
			require.NoError(t, err)

			nodeSSHPort := helpers.Port(t, instance.SSH)
			cl, err := instance.NewClient(helpers.ClientConfig{
				Login:   tt.login,
				Cluster: helpers.Site,
				Host:    Host,
				Port:    nodeSSHPort,
			})
			require.NoError(t, err)
			cl.Config.LocalForwardPorts = []client.ForwardedPort{
				{
					SrcIP:    "127.0.0.1",
					SrcPort:  localPort,
					DestHost: "localhost",
					DestPort: remotePort,
				},
			}
			term := NewTerminal(250)
			cl.Stdout = term
			cl.Stdin = term
			cl.Labels = tt.labels

			sshSessionCtx, sshSessionCancel := context.WithCancel(context.Background())
			go cl.SSH(sshSessionCtx, []string{}, false)
			defer sshSessionCancel()

			timeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err = waitForSessionToBeEstablished(timeout, apidefaults.Namespace, site)
			require.NoError(t, err)

			// When everything is *finally* set up, and I attempt to use the
			// forwarded connection
			localURL := fmt.Sprintf("http://%s:%d/", "localhost", localPort)
			r, err := http.Get(localURL)

			if r != nil {
				r.Body.Close()
			}

			if tt.expectSuccess {
				require.NoError(t, err)
				require.NotNil(t, r)
			} else {
				require.Error(t, err)
			}
		})
	}
}
