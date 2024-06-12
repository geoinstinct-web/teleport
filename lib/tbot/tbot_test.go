/*
Copyright 2022 Gravitational, Inc.

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

package tbot

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/cloud"
	"github.com/gravitational/teleport/lib/config"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/service/servicecfg"
	"github.com/gravitational/teleport/lib/tbot/testhelpers"
	"github.com/gravitational/teleport/lib/utils"
)

func TestMain(m *testing.M) {
	utils.InitLoggerForTests()
	native.PrecomputeTestKeys(m)
	os.Exit(m.Run())
}

func rotate( //nolint:unused // used in skipped test
	ctx context.Context, t *testing.T, log logrus.FieldLogger, svc *service.TeleportProcess, phase string,
) {
	t.Helper()
	log.Infof("Triggering rotation: %s", phase)
	err := svc.GetAuthServer().RotateCertAuthority(ctx, auth.RotateRequest{
		// only rotate Host CA as to avoid race condition serverside when
		// multiple CAs are rotated at once and the database closes off.
		Type:        types.HostCA,
		Mode:        "manual",
		TargetPhase: phase,
	})
	if err != nil {
		log.WithError(err).Infof("Error occurred during triggering rotation: %s", phase)
	}
	require.NoError(t, err)
	log.Infof("Triggered rotation: %s", phase)
}

func setupServerForCARotationTest(ctx context.Context, log utils.Logger, t *testing.T, wg *sync.WaitGroup, //nolint:unused // used in skipped test
) (*auth.Client, func() *service.TeleportProcess, *config.FileConfig) {
	fc, fds := testhelpers.DefaultConfig(t)

	cfg := servicecfg.MakeDefaultConfig()
	require.NoError(t, config.ApplyFileConfig(fc, cfg))
	cfg.FileDescriptors = fds
	cfg.Log = log
	cfg.CachePolicy.Enabled = false
	cfg.Proxy.DisableWebInterface = true
	cfg.InstanceMetadataClient = cloud.NewDisabledIMDSClient()

	svcC := make(chan *service.TeleportProcess)
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := service.Run(ctx, *cfg, func(cfg *servicecfg.Config) (service.Process, error) {
			svc, err := service.NewTeleport(cfg)
			if err == nil {
				svcC <- svc
			}
			return svc, err
		})
		require.NoError(t, err)
	}()

	var svc *service.TeleportProcess
	select {
	case <-time.After(30 * time.Second):
		// this should really happen quite quickly, but under the load during
		// parallel test run, it can take a while.
		t.Fatal("teleport process did not instantiate in 30 seconds")
	case svc = <-svcC:
	}

	// Ensure the service starts correctly the first time before proceeding
	_, err := svc.WaitForEventTimeout(30*time.Second, service.TeleportReadyEvent)
	// in reality, the auth server should start *much* sooner than this.  we use a very large
	// timeout here because this isn't the kind of problem that this test is meant to catch.
	require.NoError(t, err, "auth server didn't start after 30s")

	// Tracks the latest instance of the Teleport service through reloads
	activeSvc := svc
	activeSvcMu := sync.Mutex{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case svc := <-svcC:
				activeSvcMu.Lock()
				activeSvc = svc
				activeSvcMu.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()

	return testhelpers.MakeDefaultAuthClient(t, log, fc), func() *service.TeleportProcess {
		activeSvcMu.Lock()
		defer activeSvcMu.Unlock()
		return activeSvc
	}, fc
}

// TestCARotation is a heavy integration test that through a rotation, the bot
// receives credentials for a new CA.
func TestBot_Run_CARotation(t *testing.T) {
	// TODO(jakule): Re-enable this test https://github.com/gravitational/teleport/issues/19403
	t.Skip("Temporary disable until it's fixed - flaky")

	t.Parallel()
	if testing.Short() {
		t.Skip("test skipped when -short provided")
	}

	// wg and context manage the cancellation of long running processes e.g
	// teleport and tbot in the test.
	log := utils.NewLoggerForTests()
	wg := &sync.WaitGroup{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		log.Infof("Shutting down long running test processes..")
		cancel()
		wg.Wait()
	})

	client, teleportProcess, fc := setupServerForCARotationTest(ctx, log, t, wg)

	// Make and join a new bot instance.
	botParams := testhelpers.MakeBot(t, client, "test", "access")
	botConfig := testhelpers.MakeMemoryBotConfig(t, fc, botParams)
	b := New(botConfig, log, make(chan struct{}))

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := b.Run(ctx)
		require.NoError(t, err)
	}()
	// Allow time for bot to start running and watching for CA rotations
	// TODO: We should modify the bot to emit events that may be useful...
	time.Sleep(10 * time.Second)

	// fetch initial host cert
	require.Len(t, b.ident().TLSCACertsBytes, 2)
	initialCAs := [][]byte{}
	copy(initialCAs, b.ident().TLSCACertsBytes)

	// Begin rotating through all of the phases, testing the client after
	// each rotation phase has completed.
	rotate(ctx, t, log, teleportProcess(), types.RotationPhaseInit)
	// TODO: These sleeps allow the client time to rotate. They could be
	// replaced if tbot emitted a CA rotation/renewal event.
	time.Sleep(time.Second * 30)
	_, err := b.Client().Ping(ctx)
	require.NoError(t, err)

	rotate(ctx, t, log, teleportProcess(), types.RotationPhaseUpdateClients)
	time.Sleep(time.Second * 30)
	// Ensure both sets of CA certificates are now available locally
	require.Len(t, b.ident().TLSCACertsBytes, 3)
	_, err = b.Client().Ping(ctx)
	require.NoError(t, err)

	rotate(ctx, t, log, teleportProcess(), types.RotationPhaseUpdateServers)
	time.Sleep(time.Second * 30)
	_, err = b.Client().Ping(ctx)
	require.NoError(t, err)

	rotate(ctx, t, log, teleportProcess(), types.RotationStateStandby)
	time.Sleep(time.Second * 30)
	_, err = b.Client().Ping(ctx)
	require.NoError(t, err)

	require.Len(t, b.ident().TLSCACertsBytes, 2)
	finalCAs := b.ident().TLSCACertsBytes
	require.NotEqual(t, initialCAs, finalCAs)
}

func TestChooseOneResource(t *testing.T) {
	t.Parallel()
	t.Run("database", testChooseOneDatabase)
	t.Run("kube cluster", testChooseOneKubeCluster)
}

func testChooseOneDatabase(t *testing.T) {
	t.Parallel()
	fooDB1 := newMockDiscoveredDB(t, "foo-rds-us-west-1-123456789012", "foo")
	fooDB2 := newMockDiscoveredDB(t, "foo-rds-us-west-2-123456789012", "foo")
	barDB := newMockDiscoveredDB(t, "bar-rds-us-west-1-123456789012", "bar")
	tests := []struct {
		desc      string
		databases []types.Database
		dbSvc     string
		wantDB    types.Database
		wantErr   string
	}{
		{
			desc:      "by exact name match",
			databases: []types.Database{fooDB1, fooDB2, barDB},
			dbSvc:     "bar-rds-us-west-1-123456789012",
			wantDB:    barDB,
		},
		{
			desc:      "by unambiguous discovered name match",
			databases: []types.Database{fooDB1, fooDB2, barDB},
			dbSvc:     "bar",
			wantDB:    barDB,
		},
		{
			desc:      "ambiguous discovered name matches is an error",
			databases: []types.Database{fooDB1, fooDB2, barDB},
			dbSvc:     "foo",
			wantErr:   `"foo" matches multiple auto-discovered databases`,
		},
		{
			desc:      "no match is an error",
			databases: []types.Database{fooDB1, fooDB2, barDB},
			dbSvc:     "xxx",
			wantErr:   `database "xxx" not found`,
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			gotDB, err := chooseOneDatabase(test.databases, test.dbSvc)
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.wantDB, gotDB)
		})
	}
}

func testChooseOneKubeCluster(t *testing.T) {
	t.Parallel()
	fooKube1 := newMockDiscoveredKubeCluster(t, "foo-eks-us-west-1-123456789012", "foo")
	fooKube2 := newMockDiscoveredKubeCluster(t, "foo-eks-us-west-2-123456789012", "foo")
	barKube := newMockDiscoveredKubeCluster(t, "bar-eks-us-west-1-123456789012", "bar")
	tests := []struct {
		desc            string
		clusters        []types.KubeCluster
		kubeSvc         string
		wantKubeCluster types.KubeCluster
		wantErr         string
	}{
		{
			desc:            "by exact name match",
			clusters:        []types.KubeCluster{fooKube1, fooKube2, barKube},
			kubeSvc:         "bar-eks-us-west-1-123456789012",
			wantKubeCluster: barKube,
		},
		{
			desc:            "by unambiguous discovered name match",
			clusters:        []types.KubeCluster{fooKube1, fooKube2, barKube},
			kubeSvc:         "bar",
			wantKubeCluster: barKube,
		},
		{
			desc:     "ambiguous discovered name matches is an error",
			clusters: []types.KubeCluster{fooKube1, fooKube2, barKube},
			kubeSvc:  "foo",
			wantErr:  `"foo" matches multiple auto-discovered kubernetes clusters`,
		},
		{
			desc:     "no match is an error",
			clusters: []types.KubeCluster{fooKube1, fooKube2, barKube},
			kubeSvc:  "xxx",
			wantErr:  `kubernetes cluster "xxx" not found`,
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			gotKube, err := chooseOneKubeCluster(test.clusters, test.kubeSvc)
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.wantKubeCluster, gotKube)
		})
	}
}

func newMockDiscoveredDB(t *testing.T, name, discoveredName string) *types.DatabaseV3 {
	t.Helper()
	db, err := types.NewDatabaseV3(types.Metadata{
		Name: name,
		Labels: map[string]string{
			types.OriginLabel:         types.OriginCloud,
			types.DiscoveredNameLabel: discoveredName,
		},
	}, types.DatabaseSpecV3{
		Protocol: "mysql",
		URI:      "example.com:1234",
	})
	require.NoError(t, err)
	return db
}

func newMockDiscoveredKubeCluster(t *testing.T, name, discoveredName string) *types.KubernetesClusterV3 {
	t.Helper()
	kubeCluster, err := types.NewKubernetesClusterV3(
		types.Metadata{
			Name: name,
			Labels: map[string]string{
				types.OriginLabel:         types.OriginCloud,
				types.DiscoveredNameLabel: discoveredName,
			},
		},
		types.KubernetesClusterSpecV3{},
	)
	require.NoError(t, err)
	return kubeCluster
}
