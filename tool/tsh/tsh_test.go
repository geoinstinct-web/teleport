/*
Copyright 2015-2017 Gravitational, Inc.

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

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"
	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/kube/kubeconfig"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/srv"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
)

const (
	staticToken = "test-static-token"
	// tshBinMainTestEnv allows to execute tsh main function from test binary.
	tshBinMainTestEnv = "TSH_BIN_MAIN_TEST"
)

var ports utils.PortList

func init() {
	// Allows test to refer to tsh binary in tests.
	// Needed for tests that generate OpenSSH config by tsh config command where
	// tsh proxy ssh command is used as ProxyCommand.
	if os.Getenv(tshBinMainTestEnv) != "" {
		main()
		return
	}

	// If the test is re-executing itself, execute the command that comes over
	// the pipe. Used to test tsh ssh command.
	if len(os.Args) == 2 && (os.Args[1] == teleport.ExecSubCommand || os.Args[1] == teleport.ForwardSubCommand) {
		srv.RunAndExit(os.Args[1])
		return
	}

	var err error
	ports, err = utils.GetFreeTCPPorts(5000, utils.PortStartingNumber)
	if err != nil {
		panic(fmt.Sprintf("failed to allocate tcp ports for tests: %v", err))
	}
}

func TestMain(m *testing.M) {
	utils.InitLoggerForTests()
	os.Exit(m.Run())
}

type cliModules struct{}

// BuildType returns build type (OSS or Enterprise)
func (p *cliModules) BuildType() string {
	return "CLI"
}

// PrintVersion prints the Teleport version.
func (p *cliModules) PrintVersion() {
	fmt.Printf("Teleport CLI\n")
}

// Features returns supported features
func (p *cliModules) Features() modules.Features {
	return modules.Features{
		Kubernetes:              true,
		DB:                      true,
		App:                     true,
		AdvancedAccessWorkflows: true,
		AccessControls:          true,
	}
}

// IsBoringBinary checks if the binary was compiled with BoringCrypto.
func (p *cliModules) IsBoringBinary() bool {
	return false
}

func TestFailedLogin(t *testing.T) {
	tmpHomePath := t.TempDir()

	connector := mockConnector(t)

	_, proxyProcess := makeTestServers(t, withBootstrap(connector))

	proxyAddr, err := proxyProcess.ProxyWebAddr()
	require.NoError(t, err)

	// build a mock SSO login function to patch into tsh
	loginFailed := trace.AccessDenied("login failed")
	ssoLogin := func(ctx context.Context, connectorID string, pub []byte, protocol string) (*auth.SSHLoginResponse, error) {
		return nil, loginFailed
	}

	err = Run([]string{
		"login",
		"--insecure",
		"--debug",
		"--auth", connector.GetName(),
		"--proxy", proxyAddr.String(),
	}, setHomePath(tmpHomePath), cliOption(func(cf *CLIConf) error {
		cf.mockSSOLogin = client.SSOLoginFunc(ssoLogin)
		return nil
	}))
	require.ErrorIs(t, err, loginFailed)
}

func TestOIDCLogin(t *testing.T) {
	tmpHomePath := t.TempDir()

	modules.SetModules(&cliModules{})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// set up an initial role with `request_access: always` in order to
	// trigger automatic post-login escalation.
	populist, err := types.NewRole("populist", types.RoleSpecV4{
		Allow: types.RoleConditions{
			Request: &types.AccessRequestConditions{
				Roles: []string{"dictator"},
			},
		},
		Options: types.RoleOptions{
			RequestAccess: types.RequestStrategyAlways,
		},
	})
	require.NoError(t, err)

	// empty role which serves as our escalation target
	dictator, err := types.NewRole("dictator", types.RoleSpecV4{})
	require.NoError(t, err)

	alice, err := types.NewUser("alice@example.com")
	require.NoError(t, err)
	alice.SetRoles([]string{"populist"})

	connector := mockConnector(t)

	authProcess, proxyProcess := makeTestServers(t, withBootstrap(populist, dictator, connector, alice))

	authServer := authProcess.GetAuthServer()
	require.NotNil(t, authServer)

	proxyAddr, err := proxyProcess.ProxyWebAddr()
	require.NoError(t, err)

	didAutoRequest := atomic.NewBool(false)

	go func() {
		watcher, err := authServer.NewWatcher(ctx, types.Watch{
			Kinds: []types.WatchKind{
				{Kind: types.KindAccessRequest},
			},
		})
		require.NoError(t, err)
		for {
			select {
			case event := <-watcher.Events():
				if event.Type != types.OpPut {
					continue
				}
				err = authServer.SetAccessRequestState(ctx, types.AccessRequestUpdate{
					RequestID: event.Resource.(types.AccessRequest).GetName(),
					State:     types.RequestState_APPROVED,
				})
				require.NoError(t, err)
				didAutoRequest.Store(true)
				return
			case <-watcher.Done():
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	err = Run([]string{
		"login",
		"--insecure",
		"--debug",
		"--auth", connector.GetName(),
		"--proxy", proxyAddr.String(),
		"--user", "alice", // explicitly use wrong name
	}, setHomePath(tmpHomePath), cliOption(func(cf *CLIConf) error {
		cf.mockSSOLogin = mockSSOLogin(t, authServer, alice)
		cf.SiteName = "localhost"
		return nil
	}))

	require.NoError(t, err)

	// verify that auto-request happened
	require.True(t, didAutoRequest.Load())

	// if we got this far, then tsh successfully registered name change from `alice` to
	// `alice@example.com`, since the correct name needed to be used for the access
	// request to be generated.
}

// TestLoginIdentityOut makes sure that "tsh login --out <ident>" command
// writes identity credentials to the specified path.
func TestLoginIdentityOut(t *testing.T) {
	tmpHomePath := t.TempDir()

	connector := mockConnector(t)

	alice, err := types.NewUser("alice@example.com")
	require.NoError(t, err)
	alice.SetRoles([]string{"access"})

	authProcess, proxyProcess := makeTestServers(t, withBootstrap(connector, alice))

	authServer := authProcess.GetAuthServer()
	require.NotNil(t, authServer)

	proxyAddr, err := proxyProcess.ProxyWebAddr()
	require.NoError(t, err)

	identPath := filepath.Join(t.TempDir(), "ident")

	err = Run([]string{
		"login",
		"--insecure",
		"--debug",
		"--auth", connector.GetName(),
		"--proxy", proxyAddr.String(),
		"--out", identPath,
	}, setHomePath(tmpHomePath), cliOption(func(cf *CLIConf) error {
		cf.mockSSOLogin = mockSSOLogin(t, authServer, alice)
		return nil
	}))
	require.NoError(t, err)

	_, err = client.KeyFromIdentityFile(identPath)
	require.NoError(t, err)
}

func TestRelogin(t *testing.T) {
	tmpHomePath := t.TempDir()

	connector := mockConnector(t)

	alice, err := types.NewUser("alice@example.com")
	require.NoError(t, err)
	alice.SetRoles([]string{"access"})

	authProcess, proxyProcess := makeTestServers(t, withBootstrap(connector, alice))

	authServer := authProcess.GetAuthServer()
	require.NotNil(t, authServer)

	proxyAddr, err := proxyProcess.ProxyWebAddr()
	require.NoError(t, err)

	err = Run([]string{
		"login",
		"--insecure",
		"--debug",
		"--auth", connector.GetName(),
		"--proxy", proxyAddr.String(),
	}, setHomePath(tmpHomePath), cliOption(func(cf *CLIConf) error {
		cf.mockSSOLogin = mockSSOLogin(t, authServer, alice)
		return nil
	}))
	require.NoError(t, err)

	err = Run([]string{
		"login",
		"--insecure",
		"--debug",
		"--proxy", proxyAddr.String(),
		"localhost",
	}, setHomePath(tmpHomePath))
	require.NoError(t, err)

	err = Run([]string{"logout"}, setHomePath(tmpHomePath))
	require.NoError(t, err)

	err = Run([]string{
		"login",
		"--insecure",
		"--debug",
		"--auth", connector.GetName(),
		"--proxy", proxyAddr.String(),
		"localhost",
	}, setHomePath(tmpHomePath), cliOption(func(cf *CLIConf) error {
		cf.mockSSOLogin = mockSSOLogin(t, authServer, alice)
		return nil
	}))
	require.NoError(t, err)
}

func TestMakeClient(t *testing.T) {
	var conf CLIConf
	conf.HomePath = t.TempDir()

	// empty config won't work:
	tc, err := makeClient(&conf, true)
	require.Nil(t, tc)
	require.Error(t, err)

	// minimal configuration (with defaults)
	conf.Proxy = "proxy"
	conf.UserHost = "localhost"
	tc, err = makeClient(&conf, true)
	require.NoError(t, err)
	require.NotNil(t, tc)
	require.Equal(t, "proxy:3023", tc.Config.SSHProxyAddr)
	require.Equal(t, "proxy:3080", tc.Config.WebProxyAddr)

	localUser, err := client.Username()
	require.NoError(t, err)

	require.Equal(t, localUser, tc.Config.HostLogin)
	require.Equal(t, apidefaults.CertDuration, tc.Config.KeyTTL)

	// specific configuration
	conf.MinsToLive = 5
	conf.UserHost = "root@localhost"
	conf.NodePort = 46528
	conf.LocalForwardPorts = []string{"80:remote:180"}
	conf.DynamicForwardedPorts = []string{":8080"}
	tc, err = makeClient(&conf, true)
	require.NoError(t, err)
	require.Equal(t, time.Minute*time.Duration(conf.MinsToLive), tc.Config.KeyTTL)
	require.Equal(t, "root", tc.Config.HostLogin)
	require.Equal(t, client.ForwardedPorts{
		{
			SrcIP:    "127.0.0.1",
			SrcPort:  80,
			DestHost: "remote",
			DestPort: 180,
		},
	}, tc.Config.LocalForwardPorts)
	require.Equal(t, client.DynamicForwardedPorts{
		{
			SrcIP:   "127.0.0.1",
			SrcPort: 8080,
		},
	}, tc.Config.DynamicForwardedPorts)

	// specific configuration with email like user
	conf.MinsToLive = 5
	conf.UserHost = "root@example.com@localhost"
	conf.NodePort = 46528
	conf.LocalForwardPorts = []string{"80:remote:180"}
	conf.DynamicForwardedPorts = []string{":8080"}
	tc, err = makeClient(&conf, true)
	require.NoError(t, err)
	require.Equal(t, time.Minute*time.Duration(conf.MinsToLive), tc.Config.KeyTTL)
	require.Equal(t, "root@example.com", tc.Config.HostLogin)
	require.Equal(t, client.ForwardedPorts{
		{
			SrcIP:    "127.0.0.1",
			SrcPort:  80,
			DestHost: "remote",
			DestPort: 180,
		},
	}, tc.Config.LocalForwardPorts)
	require.Equal(t, client.DynamicForwardedPorts{
		{
			SrcIP:   "127.0.0.1",
			SrcPort: 8080,
		},
	}, tc.Config.DynamicForwardedPorts)

	_, proxy := makeTestServers(t)

	proxyWebAddr, err := proxy.ProxyWebAddr()
	require.NoError(t, err)

	proxySSHAddr, err := proxy.ProxySSHAddr()
	require.NoError(t, err)

	// With provided identity file.
	//
	// makeClient should call Ping on the proxy to fetch SSHProxyAddr, which is
	// different from the default.
	conf = CLIConf{
		Proxy:              proxyWebAddr.String(),
		IdentityFileIn:     "../../fixtures/certs/identities/key-cert-ca.pem",
		Context:            context.Background(),
		InsecureSkipVerify: true,
	}
	tc, err = makeClient(&conf, true)
	require.NoError(t, err)
	require.NotNil(t, tc)
	require.Equal(t, proxyWebAddr.String(), tc.Config.WebProxyAddr)
	require.Equal(t, proxySSHAddr.Addr, tc.Config.SSHProxyAddr)
	require.NotNil(t, tc.LocalAgent().Agent)

	// Client should have an in-memory agent with keys loaded, in case agent
	// forwarding is required for proxy recording mode.
	agentKeys, err := tc.LocalAgent().Agent.List()
	require.NoError(t, err)
	require.Greater(t, len(agentKeys), 0)
}

func TestIdentityRead(t *testing.T) {
	// 3 different types of identities
	ids := []string{
		"cert-key.pem", // cert + key concatenated togther, cert first
		"key-cert.pem", // cert + key concatenated togther, key first
		"key",          // two separate files: key and key-cert.pub
	}
	for _, id := range ids {
		// test reading:
		k, err := client.KeyFromIdentityFile(fmt.Sprintf("../../fixtures/certs/identities/%s", id))
		require.NoError(t, err)
		require.NotNil(t, k)

		cb, err := k.HostKeyCallback(false)
		require.NoError(t, err)
		require.Nil(t, cb)

		// test creating an auth method from the key:
		am, err := authFromIdentity(k)
		require.NoError(t, err)
		require.NotNil(t, am)
	}
	k, err := client.KeyFromIdentityFile("../../fixtures/certs/identities/lonekey")
	require.Nil(t, k)
	require.Error(t, err)

	// lets read an indentity which includes a CA cert
	k, err = client.KeyFromIdentityFile("../../fixtures/certs/identities/key-cert-ca.pem")
	require.NoError(t, err)
	require.NotNil(t, k)

	cb, err := k.HostKeyCallback(true)
	require.NoError(t, err)
	require.NotNil(t, cb)

	// prepare the cluster CA separately
	certBytes, err := ioutil.ReadFile("../../fixtures/certs/identities/ca.pem")
	require.NoError(t, err)

	_, hosts, cert, _, _, err := ssh.ParseKnownHosts(certBytes)
	require.NoError(t, err)

	var a net.Addr
	// host auth callback must succeed
	require.NoError(t, cb(hosts[0], a, cert))

	// load an identity which include TLS certificates
	k, err = client.KeyFromIdentityFile("../../fixtures/certs/identities/tls.pem")
	require.NoError(t, err)
	require.NotNil(t, k)
	require.NotNil(t, k.TLSCert)

	// generate a TLS client config
	conf, err := k.TeleportClientTLSConfig(nil)
	require.NoError(t, err)
	require.NotNil(t, conf)

	// ensure that at least root CA was successfully loaded
	require.Greater(t, len(conf.RootCAs.Subjects()), 0)
}

func TestOptions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		desc        string
		inOptions   []string
		assertError require.ErrorAssertionFunc
		outOptions  Options
	}{
		// Generic option-parsing tests
		{
			desc:        "Space Delimited",
			inOptions:   []string{"AddKeysToAgent yes"},
			assertError: require.NoError,
			outOptions: Options{
				AddKeysToAgent:        true,
				ForwardAgent:          client.ForwardAgentNo,
				RequestTTY:            false,
				StrictHostKeyChecking: true,
			},
		},
		{
			desc:        "Equals Sign Delimited",
			inOptions:   []string{"AddKeysToAgent=yes"},
			assertError: require.NoError,
			outOptions: Options{
				AddKeysToAgent:        true,
				ForwardAgent:          client.ForwardAgentNo,
				RequestTTY:            false,
				StrictHostKeyChecking: true,
			},
		},
		{
			desc:        "Invalid key",
			inOptions:   []string{"foo foo"},
			assertError: require.Error,
			outOptions:  Options{},
		},
		{
			desc:        "Incomplete option",
			inOptions:   []string{"AddKeysToAgent"},
			assertError: require.Error,
			outOptions:  Options{},
		},
		// AddKeysToAgent Tests
		{
			desc:        "AddKeysToAgent Invalid Value",
			inOptions:   []string{"AddKeysToAgent foo"},
			assertError: require.Error,
			outOptions:  Options{},
		},
		// ForwardAgent Tests
		{
			desc:        "Forward Agent Yes",
			inOptions:   []string{"ForwardAgent yes"},
			assertError: require.NoError,
			outOptions: Options{
				AddKeysToAgent:        true,
				ForwardAgent:          client.ForwardAgentYes,
				RequestTTY:            false,
				StrictHostKeyChecking: true,
			},
		},
		{
			desc:        "Forward Agent No",
			inOptions:   []string{"ForwardAgent no"},
			assertError: require.NoError,
			outOptions: Options{
				AddKeysToAgent:        true,
				ForwardAgent:          client.ForwardAgentNo,
				RequestTTY:            false,
				StrictHostKeyChecking: true,
			},
		},
		{
			desc:        "Forward Agent Local",
			inOptions:   []string{"ForwardAgent local"},
			assertError: require.NoError,
			outOptions: Options{
				AddKeysToAgent:        true,
				ForwardAgent:          client.ForwardAgentLocal,
				RequestTTY:            false,
				StrictHostKeyChecking: true,
			},
		},
		{
			desc:        "Forward Agent InvalidValue",
			inOptions:   []string{"ForwardAgent potato"},
			assertError: require.Error,
			outOptions:  Options{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			options, err := parseOptions(tt.inOptions)
			tt.assertError(t, err)

			require.Equal(t, tt.outOptions.AddKeysToAgent, options.AddKeysToAgent)
			require.Equal(t, tt.outOptions.ForwardAgent, options.ForwardAgent)
			require.Equal(t, tt.outOptions.RequestTTY, options.RequestTTY)
			require.Equal(t, tt.outOptions.StrictHostKeyChecking, options.StrictHostKeyChecking)
		})
	}
}

func TestFormatConnectCommand(t *testing.T) {
	tests := []struct {
		clusterFlag string
		comment     string
		db          tlsca.RouteToDatabase
		command     string
	}{
		{
			comment: "no default user/database are specified",
			db: tlsca.RouteToDatabase{
				ServiceName: "test",
				Protocol:    defaults.ProtocolPostgres,
			},
			command: `tsh db connect --db-user=<user> --db-name=<name> test`,
		},
		{
			comment: "default user is specified",
			db: tlsca.RouteToDatabase{
				ServiceName: "test",
				Protocol:    defaults.ProtocolPostgres,
				Username:    "postgres",
			},
			command: `tsh db connect --db-name=<name> test`,
		},
		{
			comment: "default database is specified",
			db: tlsca.RouteToDatabase{
				ServiceName: "test",
				Protocol:    defaults.ProtocolPostgres,
				Database:    "postgres",
			},
			command: `tsh db connect --db-user=<user> test`,
		},
		{
			comment: "default user/database are specified",
			db: tlsca.RouteToDatabase{
				ServiceName: "test",
				Protocol:    defaults.ProtocolPostgres,
				Username:    "postgres",
				Database:    "postgres",
			},
			command: `tsh db connect test`,
		},
		{
			comment:     "extra cluster flag",
			clusterFlag: "leaf",
			db: tlsca.RouteToDatabase{
				ServiceName: "test",
				Protocol:    defaults.ProtocolPostgres,
				Database:    "postgres",
			},
			command: `tsh db connect --cluster=leaf --db-user=<user> test`,
		},
	}
	for _, test := range tests {
		t.Run(test.comment, func(t *testing.T) {
			require.Equal(t, test.command, formatConnectCommand(test.clusterFlag, test.db))
		})
	}
}

func TestEnvFlags(t *testing.T) {
	type testCase struct {
		inCLIConf  CLIConf
		envMap     map[string]string
		outCLIConf CLIConf
	}

	testEnvFlag := func(tc testCase) func(t *testing.T) {
		return func(t *testing.T) {
			setEnvFlags(&tc.inCLIConf, func(envName string) string {
				return tc.envMap[envName]
			})
			require.Equal(t, tc.outCLIConf, tc.inCLIConf)
		}
	}

	t.Run("cluster env", func(t *testing.T) {
		t.Run("nothing set", testEnvFlag(testCase{
			outCLIConf: CLIConf{
				SiteName: "",
			},
		}))
		t.Run("CLI flag is set", testEnvFlag(testCase{
			inCLIConf: CLIConf{
				SiteName: "a.example.com",
			},
			outCLIConf: CLIConf{
				SiteName: "a.example.com",
			},
		}))
		t.Run("TELEPORT_SITE set", testEnvFlag(testCase{
			envMap: map[string]string{
				siteEnvVar: "a.example.com",
			},
			outCLIConf: CLIConf{
				SiteName: "a.example.com",
			},
		}))
		t.Run("TELEPORT_CLUSTER set", testEnvFlag(testCase{
			envMap: map[string]string{
				clusterEnvVar: "b.example.com",
			},
			outCLIConf: CLIConf{
				SiteName: "b.example.com",
			},
		}))
		t.Run("TELEPORT_SITE and TELEPORT_CLUSTER set, prefer TELEPORT_CLUSTER", testEnvFlag(testCase{
			envMap: map[string]string{
				clusterEnvVar: "d.example.com",
				siteEnvVar:    "c.example.com",
			},
			outCLIConf: CLIConf{
				SiteName: "d.example.com",
			},
		}))
		t.Run("TELEPORT_SITE and TELEPORT_CLUSTER and CLI flag is set, prefer CLI", testEnvFlag(testCase{
			inCLIConf: CLIConf{
				SiteName: "e.example.com",
			},
			envMap: map[string]string{
				clusterEnvVar: "g.example.com",
				siteEnvVar:    "f.example.com",
			},
			outCLIConf: CLIConf{
				SiteName: "e.example.com",
			},
		}))
	})

	t.Run("kube cluster env", func(t *testing.T) {
		t.Run("nothing set", testEnvFlag(testCase{
			outCLIConf: CLIConf{
				KubernetesCluster: "",
			},
		}))
		t.Run("CLI flag is set", testEnvFlag(testCase{
			inCLIConf: CLIConf{
				KubernetesCluster: "a.example.com",
			},
			outCLIConf: CLIConf{
				KubernetesCluster: "a.example.com",
			},
		}))
		t.Run("TELEPORT_KUBE_CLUSTER set", testEnvFlag(testCase{
			envMap: map[string]string{
				kubeClusterEnvVar: "a.example.com",
			},
			outCLIConf: CLIConf{
				KubernetesCluster: "a.example.com",
			},
		}))
		t.Run("TELEPORT_KUBE_CLUSTER and CLI flag is set, prefer CLI", testEnvFlag(testCase{
			inCLIConf: CLIConf{
				KubernetesCluster: "e.example.com",
			},
			envMap: map[string]string{
				kubeClusterEnvVar: "g.example.com",
			},
			outCLIConf: CLIConf{
				KubernetesCluster: "e.example.com",
			},
		}))
	})

	t.Run("teleport home env", func(t *testing.T) {
		t.Run("nothing set", testEnvFlag(testCase{
			outCLIConf: CLIConf{},
		}))
		t.Run("CLI flag is set", testEnvFlag(testCase{
			inCLIConf: CLIConf{
				HomePath: "teleport-data",
			},
			outCLIConf: CLIConf{
				HomePath: "teleport-data",
			},
		}))
		t.Run("TELEPORT_HOME set", testEnvFlag(testCase{
			envMap: map[string]string{
				homeEnvVar: "teleport-data/",
			},
			outCLIConf: CLIConf{
				HomePath: "teleport-data",
			},
		}))
		t.Run("TELEPORT_HOME and CLI flag is set, prefer env", testEnvFlag(testCase{
			inCLIConf: CLIConf{
				HomePath: "teleport-data",
			},
			envMap: map[string]string{
				homeEnvVar: "teleport-data/",
			},
			outCLIConf: CLIConf{
				HomePath: "teleport-data",
			},
		}))
	})
}

func TestKubeConfigUpdate(t *testing.T) {
	t.Parallel()
	// don't need real creds for this test, just something to compare against
	creds := &client.Key{KeyIndex: client.KeyIndex{ProxyHost: "a.example.com"}}
	tests := []struct {
		desc           string
		cf             *CLIConf
		kubeStatus     *kubernetesStatus
		errorAssertion require.ErrorAssertionFunc
		expectedValues *kubeconfig.Values
	}{
		{
			desc: "selected cluster",
			cf: &CLIConf{
				executablePath:    "/bin/tsh",
				KubernetesCluster: "dev",
			},
			kubeStatus: &kubernetesStatus{
				clusterAddr:         "https://a.example.com:3026",
				teleportClusterName: "a.example.com",
				kubeClusters:        []string{"dev", "prod"},
				credentials:         creds,
			},
			errorAssertion: require.NoError,
			expectedValues: &kubeconfig.Values{
				Credentials:         creds,
				ClusterAddr:         "https://a.example.com:3026",
				TeleportClusterName: "a.example.com",
				Exec: &kubeconfig.ExecValues{
					TshBinaryPath: "/bin/tsh",
					KubeClusters:  []string{"dev", "prod"},
					SelectCluster: "dev",
				},
			},
		},
		{
			desc: "no selected cluster",
			cf: &CLIConf{
				executablePath:    "/bin/tsh",
				KubernetesCluster: "",
			},
			kubeStatus: &kubernetesStatus{
				clusterAddr:         "https://a.example.com:3026",
				teleportClusterName: "a.example.com",
				kubeClusters:        []string{"dev", "prod"},
				credentials:         creds,
			},
			errorAssertion: require.NoError,
			expectedValues: &kubeconfig.Values{
				Credentials:         creds,
				ClusterAddr:         "https://a.example.com:3026",
				TeleportClusterName: "a.example.com",
				Exec: &kubeconfig.ExecValues{
					TshBinaryPath: "/bin/tsh",
					KubeClusters:  []string{"dev", "prod"},
					SelectCluster: "",
				},
			},
		},
		{
			desc: "invalid selected cluster",
			cf: &CLIConf{
				executablePath:    "/bin/tsh",
				KubernetesCluster: "invalid",
			},
			kubeStatus: &kubernetesStatus{
				clusterAddr:         "https://a.example.com:3026",
				teleportClusterName: "a.example.com",
				kubeClusters:        []string{"dev", "prod"},
				credentials:         creds,
			},
			errorAssertion: func(t require.TestingT, err error, _ ...interface{}) {
				require.True(t, trace.IsBadParameter(err))
			},
			expectedValues: nil,
		},
		{
			desc: "no kube clusters",
			cf: &CLIConf{
				executablePath:    "/bin/tsh",
				KubernetesCluster: "",
			},
			kubeStatus: &kubernetesStatus{
				clusterAddr:         "https://a.example.com:3026",
				teleportClusterName: "a.example.com",
				kubeClusters:        []string{},
				credentials:         creds,
			},
			errorAssertion: require.NoError,
			expectedValues: &kubeconfig.Values{
				Credentials:         creds,
				ClusterAddr:         "https://a.example.com:3026",
				TeleportClusterName: "a.example.com",
				Exec:                nil,
			},
		},
		{
			desc: "no tsh path",
			cf: &CLIConf{
				executablePath:    "",
				KubernetesCluster: "dev",
			},
			kubeStatus: &kubernetesStatus{
				clusterAddr:         "https://a.example.com:3026",
				teleportClusterName: "a.example.com",
				kubeClusters:        []string{"dev", "prod"},
				credentials:         creds,
			},
			errorAssertion: require.NoError,
			expectedValues: &kubeconfig.Values{
				Credentials:         creds,
				ClusterAddr:         "https://a.example.com:3026",
				TeleportClusterName: "a.example.com",
				Exec:                nil,
			},
		},
	}
	for _, testcase := range tests {
		t.Run(testcase.desc, func(t *testing.T) {
			values, err := buildKubeConfigUpdate(testcase.cf, testcase.kubeStatus)
			testcase.errorAssertion(t, err)
			require.Equal(t, testcase.expectedValues, values)
		})
	}
}

type testServersOpts struct {
	bootstrap      []types.Resource
	authConfigFunc func(cfg *service.AuthConfig)
}

type testServerOptFunc func(o *testServersOpts)

func withBootstrap(bootstrap ...types.Resource) testServerOptFunc {
	return func(o *testServersOpts) {
		o.bootstrap = bootstrap
	}
}

func withAuthConfig(fn func(cfg *service.AuthConfig)) testServerOptFunc {
	return func(o *testServersOpts) {
		o.authConfigFunc = fn
	}
}

func makeTestServers(t *testing.T, opts ...testServerOptFunc) (auth *service.TeleportProcess, proxy *service.TeleportProcess) {
	var options testServersOpts
	for _, opt := range opts {
		opt(&options)
	}

	var err error
	// Set up a test auth server.
	//
	// We need this to get a random port assigned to it and allow parallel
	// execution of this test.
	cfg := service.MakeDefaultConfig()
	cfg.Hostname = "localhost"
	cfg.DataDir = t.TempDir()

	cfg.AuthServers = []utils.NetAddr{{AddrNetwork: "tcp", Addr: net.JoinHostPort("127.0.0.1", ports.Pop())}}
	cfg.Auth.Resources = options.bootstrap
	cfg.Auth.StorageConfig.Params = backend.Params{defaults.BackendPath: filepath.Join(cfg.DataDir, defaults.BackendDir)}
	cfg.Auth.StaticTokens, err = types.NewStaticTokens(types.StaticTokensSpecV2{
		StaticTokens: []types.ProvisionTokenV1{{
			Roles:   []types.SystemRole{types.RoleProxy, types.RoleDatabase},
			Expires: time.Now().Add(time.Minute),
			Token:   staticToken,
		}},
	})
	require.NoError(t, err)
	cfg.SSH.Enabled = false
	cfg.Auth.Enabled = true
	cfg.Auth.SSHAddr = utils.NetAddr{AddrNetwork: "tcp", Addr: net.JoinHostPort("127.0.0.1", ports.Pop())}
	cfg.Proxy.Enabled = false
	cfg.Log = utils.NewLoggerForTests()

	if options.authConfigFunc != nil {
		options.authConfigFunc(&cfg.Auth)
	}

	auth, err = service.NewTeleport(cfg)
	require.NoError(t, err)
	require.NoError(t, auth.Start())

	t.Cleanup(func() {
		auth.Close()
	})

	// Wait for proxy to become ready.
	eventCh := make(chan service.Event, 1)
	auth.WaitForEvent(auth.ExitContext(), service.AuthTLSReady, eventCh)
	select {
	case <-eventCh:
	case <-time.After(30 * time.Second):
		// in reality, the auth server should start *much* sooner than this.  we use a very large
		// timeout here because this isn't the kind of problem that this test is meant to catch.
		t.Fatal("auth server didn't start after 30s")
	}

	authAddr, err := auth.AuthSSHAddr()
	require.NoError(t, err)

	// Set up a test proxy service.
	cfg = service.MakeDefaultConfig()
	cfg.Hostname = "localhost"
	cfg.DataDir = t.TempDir()

	cfg.AuthServers = []utils.NetAddr{*authAddr}
	cfg.Token = staticToken
	cfg.SSH.Enabled = false
	cfg.Auth.Enabled = false
	cfg.Proxy.Enabled = true
	cfg.Proxy.WebAddr = utils.NetAddr{AddrNetwork: "tcp", Addr: net.JoinHostPort("127.0.0.1", ports.Pop())}
	cfg.Proxy.SSHAddr = utils.NetAddr{AddrNetwork: "tcp", Addr: net.JoinHostPort("127.0.0.1", ports.Pop())}
	cfg.Proxy.ReverseTunnelListenAddr = utils.NetAddr{AddrNetwork: "tcp", Addr: net.JoinHostPort("127.0.0.1", ports.Pop())}
	cfg.Proxy.DisableWebInterface = true
	cfg.Log = utils.NewLoggerForTests()

	proxy, err = service.NewTeleport(cfg)
	require.NoError(t, err)
	require.NoError(t, proxy.Start())

	t.Cleanup(func() {
		proxy.Close()
	})

	// Wait for proxy to become ready.
	proxy.WaitForEvent(proxy.ExitContext(), service.ProxyWebServerReady, eventCh)
	select {
	case <-eventCh:
	case <-time.After(10 * time.Second):
		t.Fatal("proxy web server didn't start after 10s")
	}

	return auth, proxy
}

func mockConnector(t *testing.T) types.OIDCConnector {
	// Connector need not be functional since we are going to mock the actual
	// login operation.
	connector, err := types.NewOIDCConnector("auth.example.com", types.OIDCConnectorSpecV2{
		IssuerURL:   "https://auth.example.com",
		RedirectURL: "https://cluster.example.com",
		ClientID:    "fake-client",
	})
	require.NoError(t, err)
	return connector
}

func mockSSOLogin(t *testing.T, authServer *auth.Server, user types.User) client.SSOLoginFunc {
	return func(ctx context.Context, connectorID string, pub []byte, protocol string) (*auth.SSHLoginResponse, error) {
		// generate certificates for our user
		sshCert, tlsCert, err := authServer.GenerateUserTestCerts(
			pub, user.GetName(), time.Hour,
			constants.CertificateFormatStandard,
			"localhost",
		)
		require.NoError(t, err)

		// load CA cert
		authority, err := authServer.GetCertAuthority(types.CertAuthID{
			Type:       types.HostCA,
			DomainName: "localhost",
		}, false)
		require.NoError(t, err)

		// build login response
		return &auth.SSHLoginResponse{
			Username:    user.GetName(),
			Cert:        sshCert,
			TLSCert:     tlsCert,
			HostSigners: auth.AuthoritiesToTrustedCerts([]types.CertAuthority{authority}),
		}, nil
	}
}

func setHomePath(path string) cliOption {
	return func(cf *CLIConf) error {
		cf.HomePath = path
		return nil
	}
}
