// Copyright 2023 Gravitational, Inc
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

package connectmycomputer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/teleterm/api/uri"
	"github.com/gravitational/teleport/lib/teleterm/clusters"
	"github.com/gravitational/teleport/lib/utils"
)

func TestRoleSetupRun_WithNonLocalUser(t *testing.T) {
	roleSetup, err := NewRoleSetup(&RoleSetupConfig{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	oidcUser, err := types.NewUser("alice")
	require.NoError(t, err)
	oidcUser.SetCreatedBy(types.CreatedBy{
		Connector: &types.ConnectorRef{Type: "oidc", ID: "google"},
	})
	accessAndIdentity := &mockAccessAndIdentity{
		user:       oidcUser,
		callCounts: make(map[string]int),
		events:     &mockEvents{},
	}
	certManager := &mockCertManager{}

	_, err = roleSetup.Run(ctx, accessAndIdentity, certManager, &clusters.Cluster{URI: uri.NewClusterURI("foo")})
	require.Error(t, err)
	require.True(t, trace.IsBadParameter(err), "expected the error to be BadParameter")
}

// During development, I already managed to introduce a bug in a conditional which resulted in a
// resource being updated on every run of RoleSetup.
// The integration tests won't catch that since they worry about the end result only.
func TestRoleSetupRun_Idempotency(t *testing.T) {
	roleSetup, err := NewRoleSetup(&RoleSetupConfig{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	user, err := types.NewUser("alice")
	require.NoError(t, err)
	events := &mockEvents{}
	accessAndIdentity := &mockAccessAndIdentity{
		user:       user,
		callCounts: make(map[string]int),
		events:     events,
	}
	certManager := &mockCertManager{}

	_, err = roleSetup.Run(ctx, accessAndIdentity, certManager, &clusters.Cluster{URI: uri.NewClusterURI("foo")})
	require.NoError(t, err)

	_, err = roleSetup.Run(ctx, accessAndIdentity, certManager, &clusters.Cluster{URI: uri.NewClusterURI("foo")})
	require.NoError(t, err)

	require.Equal(t, 1, accessAndIdentity.callCounts["UpsertRole"], "expected two runs to update the role only once")
	require.Equal(t, 1, accessAndIdentity.callCounts["UpdateUser"], "expected two runs to update the user only once")
}

func TestRoleSetupRun_RoleErrors(t *testing.T) {
	existingRole, err := types.NewRole("connect-my-computer-alice", types.RoleSpecV6{})
	require.NoError(t, err)

	tests := []struct {
		name          string
		upsertRoleErr error
		existingRole  types.Role
	}{
		{
			name:          "creating role fails",
			upsertRoleErr: errors.New("something went wrong"),
		},
		{
			name:          "updating role fails",
			upsertRoleErr: errors.New("something went wrong"),
			existingRole:  existingRole,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			user, err := types.NewUser("alice")
			require.NoError(t, err)

			events := &mockEvents{}
			certManager := &mockCertManager{}
			accessAndIdentity := &mockAccessAndIdentity{
				user:          user,
				callCounts:    make(map[string]int),
				events:        events,
				upsertRoleErr: tt.upsertRoleErr,
				role:          tt.existingRole,
			}

			roleSetup, err := NewRoleSetup(&RoleSetupConfig{})
			require.NoError(t, err)

			_, err = roleSetup.Run(ctx, accessAndIdentity, certManager, &clusters.Cluster{URI: uri.NewClusterURI("foo")})
			require.Error(t, err)
			require.ErrorIs(t, err, tt.upsertRoleErr)
		})
	}
}

const nodejoinWaitTestTimeout = 10 * time.Second

func TestNodeJoinWaitRun_WaitsForHostUUIDFileToBeCreatedAndFetchesNodeFromCluster(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), nodejoinWaitTestTimeout)
	t.Cleanup(cancel)

	cluster := &clusters.Cluster{URI: uri.NewClusterURI("foo"), ProfileName: "foo"}
	events := &mockEvents{}
	node, err := types.NewServer("1234", types.KindNode, types.ServerSpecV2{
		CmdLabels: types.LabelsToV2(map[string]types.CommandLabel{
			defaults.HostnameLabel: &types.CommandLabelV2{Result: ""},
		}),
	})
	require.NoError(t, err)
	accessAndIdentity := &mockAccessAndIdentity{
		callCounts: make(map[string]int),
		events:     events,
		node:       node,
	}

	nodeJoinWait, err := NewNodeJoinWait(&NodeJoinWaitConfig{AgentsDir: t.TempDir()})
	require.NoError(t, err)

	runErr := make(chan error)
	serverC := make(chan clusters.Server)

	go func() {
		server, err := nodeJoinWait.Run(ctx, accessAndIdentity, cluster)
		runErr <- err
		serverC <- server
	}()

	// Make sure NodeJoinWait.Run doesn't see the file on the first tick.
	time.Sleep(10 * time.Millisecond)

	// Create the UUID file while NodeJoinWait.Run is executed in a separate goroutine to verify that
	// it continuously attempts to read the host UUID file, rather than reading it only once.
	mustMakeHostUUIDFile(t, nodeJoinWait.cfg.AgentsDir, cluster.ProfileName)

	// Verify that NodeJoinWait.Run used GetNode and not a watcher to fetch the node.
	require.NoError(t, <-runErr)
	server := <-serverC
	require.Equal(t, node.GetName(), server.GetName())

	// Verify that the empty hostname label gets filled out.
	hostname, err := os.Hostname()
	require.NoError(t, err)
	require.Contains(t, server.GetCmdLabels(), defaults.HostnameLabel)
	require.Equal(t, hostname, server.GetCmdLabels()[defaults.HostnameLabel].GetResult())
}

func TestNodeJoinWaitRun_WatchesForOpPutIfNodeWasNotFound(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), nodejoinWaitTestTimeout)
	t.Cleanup(cancel)

	cluster := &clusters.Cluster{URI: uri.NewClusterURI("foo"), ProfileName: "foo"}
	events := &mockEvents{}
	accessAndIdentity := &mockAccessAndIdentity{
		callCounts: make(map[string]int),
		events:     events,
		// Setting to true because we manually fire OpPut from test body.
		requireManualOpInitFire: true,
	}

	nodeJoinWait, err := NewNodeJoinWait(&NodeJoinWaitConfig{AgentsDir: t.TempDir()})
	require.NoError(t, err)

	hostUUID := mustMakeHostUUIDFile(t, nodeJoinWait.cfg.AgentsDir, cluster.ProfileName)
	eventServer, err := types.NewServer(hostUUID, types.KindNode, types.ServerSpecV2{
		CmdLabels: types.LabelsToV2(map[string]types.CommandLabel{
			defaults.HostnameLabel: &types.CommandLabelV2{Result: ""},
		}),
	})
	require.NoError(t, err)
	bogusEventServer, err := types.NewServer("1234", types.KindNode, types.ServerSpecV2{})
	require.NoError(t, err)

	runErr := make(chan error)
	serverC := make(chan clusters.Server)

	go func() {
		server, err := nodeJoinWait.Run(ctx, accessAndIdentity, cluster)
		runErr <- err
		serverC <- server
	}()

	err = accessAndIdentity.events.WaitSomeWatchers(ctx)
	require.NoError(t, err)
	accessAndIdentity.events.Fire(types.Event{Type: types.OpInit})

	// Fire an event with another node first to verify that NodeJoinWait does the comparison correctly.
	accessAndIdentity.events.Fire(types.Event{
		Type:     types.OpPut,
		Resource: bogusEventServer,
	})
	accessAndIdentity.events.Fire(types.Event{
		Type:     types.OpPut,
		Resource: eventServer,
	})

	// Verify that NodeJoinWait.Run returns as soon as it receives an event with a matching server.
	require.NoError(t, <-runErr)
	server := <-serverC
	require.Equal(t, eventServer.GetName(), server.GetName())

	// Verify that the empty hostname label gets filled out.
	hostname, err := os.Hostname()
	require.NoError(t, err)
	require.Contains(t, server.GetCmdLabels(), defaults.HostnameLabel)
	require.Equal(t, hostname, server.GetCmdLabels()[defaults.HostnameLabel].GetResult())
}

func TestNodeJoinWaitRun_ReturnsEarlyIfGetNodeReturnsErrorOtherThanNotFound(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), nodejoinWaitTestTimeout)
	t.Cleanup(cancel)

	cluster := &clusters.Cluster{URI: uri.NewClusterURI("foo"), ProfileName: "foo"}
	events := &mockEvents{}
	nodeErr := trace.Errorf("something went wrong")
	accessAndIdentity := &mockAccessAndIdentity{
		callCounts: make(map[string]int),
		events:     events,
		nodeErr:    nodeErr,
	}

	nodeJoinWait, err := NewNodeJoinWait(&NodeJoinWaitConfig{AgentsDir: t.TempDir()})
	require.NoError(t, err)

	mustMakeHostUUIDFile(t, nodeJoinWait.cfg.AgentsDir, cluster.ProfileName)

	_, err = nodeJoinWait.Run(ctx, accessAndIdentity, cluster)
	require.Equal(t, nodeErr, err)
}

type mockAccessAndIdentity struct {
	user       types.User
	role       types.Role
	callCounts map[string]int
	events     *mockEvents
	// requireManualOpInitFire makes mockAccessAndIdentity.NewWatcher skip firing OpInit.
	//
	// In regular tests where this field is false, the code under tests calls
	// mockAccessAndIdentity.NewWatcher (which fires OpInit), waits for OpInit, and then calls another
	// method on mockAccessAndIdentity which fires an event.
	//
	// In tests where events such as OpPut are triggered directly from the test body and not as a
	// result of the code under tests calling methods on mockAccessAndIdentity, setting it to true
	// allows manually firing OpInit first before firing other events. This ensures that the first
	// event that watchers observe is OpInit.
	//
	requireManualOpInitFire bool
	node                    types.Server
	nodeErr                 error
	upsertRoleErr           error
}

func (m *mockAccessAndIdentity) GetUser(name string, withSecrets bool) (types.User, error) {
	return m.user, nil
}

func (m *mockAccessAndIdentity) GetRole(ctx context.Context, name string) (types.Role, error) {
	if m.role != nil {
		return m.role, nil
	}
	return nil, trace.NotFound("role not found")
}

func (m *mockAccessAndIdentity) UpsertRole(ctx context.Context, role types.Role) error {
	m.callCounts["UpsertRole"]++

	if m.upsertRoleErr != nil {
		return m.upsertRoleErr
	}

	m.role = role
	m.events.Fire(types.Event{
		Type:     types.OpPut,
		Resource: role,
	})
	return nil
}

func (m *mockAccessAndIdentity) NewWatcher(ctx context.Context, watch types.Watch) (types.Watcher, error) {
	watcher, err := m.events.NewWatcher(ctx, watch)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if !m.requireManualOpInitFire {
		m.events.Fire(types.Event{Type: types.OpInit})
	}

	return watcher, nil
}

func (m *mockAccessAndIdentity) UpdateUser(ctx context.Context, user types.User) error {
	m.callCounts["UpdateUser"]++
	m.user = user
	m.events.Fire(types.Event{
		Type:     types.OpPut,
		Resource: user,
	})
	return nil
}

func (m *mockAccessAndIdentity) GetNode(ctx context.Context, namespace, name string) (types.Server, error) {
	if m.nodeErr != nil {
		return nil, m.nodeErr
	}

	if m.node != nil {
		return m.node, nil
	}
	return nil, trace.NotFound("node not found")
}

type mockCertManager struct{}

func (m *mockCertManager) ReissueUserCerts(context.Context, client.CertCachePolicy, client.ReissueParams) error {
	return nil
}

// mockEvents enables sending out events to watchers from within a test or other mocks.
// The implementation is copied from integrations/lib/watcherjob/helpers_test.go.
type mockEvents struct {
	sync.Mutex
	channels []chan<- types.Event
}

// NewWatcher creates a new watcher.
func (e *mockEvents) NewWatcher(ctx context.Context, watch types.Watch) (types.Watcher, error) {
	events := make(chan types.Event, 1000)
	e.Lock()
	e.channels = append(e.channels, events)
	e.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	return mockWatcher{events: events, ctx: ctx, cancel: cancel}, ctx.Err()
}

// Fire emits a watcher events for all the subscribers to consume.
func (e *mockEvents) Fire(event types.Event) {
	e.Lock()
	channels := e.channels
	e.Unlock()
	for _, events := range channels {
		events <- event
	}
}

// WaitSomeWatchers blocks until either some watcher is subscribed or context is done.
func (e *mockEvents) WaitSomeWatchers(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			e.Lock()
			n := len(e.channels)
			e.Unlock()
			if n > 0 {
				return nil
			}
		case <-ctx.Done():
			return trace.Wrap(ctx.Err())
		}
	}
}

// mockWatcher is copied from integrations/lib/watcherjob/helpers_test.go.
type mockWatcher struct {
	events <-chan types.Event
	ctx    context.Context
	cancel context.CancelFunc
}

// Events returns a stream of events.
func (w mockWatcher) Events() <-chan types.Event {
	return w.events
}

// Done returns a completion channel.
func (w mockWatcher) Done() <-chan struct{} {
	return w.ctx.Done()
}

// Close sends a termination signal to watcher.
func (w mockWatcher) Close() error {
	w.cancel()
	return nil
}

// Error returns a watcher error.
func (w mockWatcher) Error() error {
	return trace.Wrap(w.ctx.Err())
}

func mustMakeHostUUIDFile(t *testing.T, agentsDir string, profileName string) string {
	dataDir := filepath.Join(agentsDir, profileName, "data")

	agentsDirStat, err := os.Stat(agentsDir)
	require.NoError(t, err)

	err = os.MkdirAll(dataDir, agentsDirStat.Mode())
	require.NoError(t, err)

	hostUUID, err := utils.ReadOrMakeHostUUID(dataDir)
	require.NoError(t, err)

	return hostUUID
}

func TestNodeNameGet(t *testing.T) {
	t.Parallel()

	cluster := &clusters.Cluster{URI: uri.NewClusterURI("foo"), ProfileName: "foo"}
	nodeName, err := NewNodeName(&NodeNameConfig{AgentsDir: t.TempDir()})
	require.NoError(t, err)
	hostUUID := mustMakeHostUUIDFile(t, nodeName.cfg.AgentsDir, cluster.ProfileName)

	readUUID, err := nodeName.Get(cluster)

	require.NoError(t, err)
	require.Equal(t, readUUID, hostUUID)
}
