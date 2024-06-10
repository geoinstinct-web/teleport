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

package integration

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/gravitational/teleport/api/types"
	api "github.com/gravitational/teleport/gen/proto/go/teleport/lib/teleterm/v1"
	dbhelpers "github.com/gravitational/teleport/integration/db"
	"github.com/gravitational/teleport/integration/helpers"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/service/servicecfg"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/teleterm/api/uri"
	"github.com/gravitational/teleport/lib/teleterm/apiserver/handler"
	"github.com/gravitational/teleport/lib/teleterm/clusters"
	"github.com/gravitational/teleport/lib/teleterm/daemon"
	"github.com/gravitational/teleport/lib/tlsca"
)

func TestTeleterm(t *testing.T) {
	pack := dbhelpers.SetupDatabaseTest(t,
		dbhelpers.WithListenerSetupDatabaseTest(helpers.SingleProxyPortSetup),
		dbhelpers.WithLeafConfig(func(config *servicecfg.Config) {
			config.Auth.NetworkingConfig.SetProxyListenerMode(types.ProxyListenerMode_Multiplex)
		}),
		dbhelpers.WithRootConfig(func(config *servicecfg.Config) {
			config.Auth.NetworkingConfig.SetProxyListenerMode(types.ProxyListenerMode_Multiplex)
		}),
	)
	pack.WaitForLeaf(t)

	creds, err := helpers.GenerateUserCreds(helpers.UserCredsRequest{
		Process:  pack.Root.Cluster.Process,
		Username: pack.Root.User.GetName(),
	})
	require.NoError(t, err)

	t.Run("adding root cluster", func(t *testing.T) {
		t.Parallel()

		testAddingRootCluster(t, pack, creds)
	})

	t.Run("ListRootClusters returns logged in user", func(t *testing.T) {
		t.Parallel()

		testListRootClustersReturnsLoggedInUser(t, pack, creds)
	})
	t.Run("GetCluster returns properties from auth server", func(t *testing.T) {
		t.Parallel()

		testGetClusterReturnsPropertiesFromAuthServer(t, pack)
	})

	t.Run("Test headless watcher", func(t *testing.T) {
		t.Parallel()

		testHeadlessWatcher(t, pack, creds)
	})

	t.Run("ListDatabaseUsers", func(t *testing.T) {
		// ListDatabaseUsers cannot be run in parallel as it modifies the default roles of users set up
		// through the test pack.
		// TODO(ravicious): After some optimizations, those tests could run in parallel. Instead of
		// modifying existing roles, they could create new users with new roles and then update the role
		// mapping between the root the leaf cluster through authServer.UpdateUserCARoleMap.
		testListDatabaseUsers(t, pack)
	})
}

func testAddingRootCluster(t *testing.T, pack *dbhelpers.DatabasePack, creds *helpers.UserCreds) {
	storage, err := clusters.NewStorage(clusters.Config{
		Dir:                t.TempDir(),
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)

	daemonService, err := daemon.New(daemon.Config{
		Storage: storage,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		daemonService.Stop()
	})

	addedCluster, err := daemonService.AddCluster(context.Background(), pack.Root.Cluster.Web)
	require.NoError(t, err)

	clusters, err := daemonService.ListRootClusters(context.Background())
	require.NoError(t, err)

	clusterURIs := make([]uri.ResourceURI, 0, len(clusters))
	for _, cluster := range clusters {
		clusterURIs = append(clusterURIs, cluster.URI)
	}
	require.ElementsMatch(t, clusterURIs, []uri.ResourceURI{addedCluster.URI})
}

func testListRootClustersReturnsLoggedInUser(t *testing.T, pack *dbhelpers.DatabasePack, creds *helpers.UserCreds) {
	tc := mustLogin(t, pack.Root.User.GetName(), pack, creds)

	storage, err := clusters.NewStorage(clusters.Config{
		Dir:                tc.KeysDir,
		InsecureSkipVerify: tc.InsecureSkipVerify,
	})
	require.NoError(t, err)

	daemonService, err := daemon.New(daemon.Config{
		Storage: storage,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		daemonService.Stop()
	})

	handler, err := handler.New(
		handler.Config{
			DaemonService: daemonService,
		},
	)
	require.NoError(t, err)

	response, err := handler.ListRootClusters(context.Background(), &api.ListClustersRequest{})
	require.NoError(t, err)

	require.Equal(t, 1, len(response.Clusters))
	require.Equal(t, pack.Root.User.GetName(), response.Clusters[0].LoggedInUser.Name)
}

func testGetClusterReturnsPropertiesFromAuthServer(t *testing.T, pack *dbhelpers.DatabasePack) {
	authServer := pack.Root.Cluster.Process.GetAuthServer()

	// Use random names to not collide with other tests.
	uuid := uuid.NewString()
	suggestedReviewer := "suggested-reviewer"
	requestableRoleName := fmt.Sprintf("%s-%s", "requested-role", uuid)
	userName := fmt.Sprintf("%s-%s", "user", uuid)
	roleName := fmt.Sprintf("%s-%s", "get-cluster-role", uuid)

	requestableRole, err := types.NewRole(requestableRoleName, types.RoleSpecV6{})
	require.NoError(t, err)

	// Create user role with ability to request role
	userRole, err := types.NewRole(roleName, types.RoleSpecV6{
		Options: types.RoleOptions{},
		Allow: types.RoleConditions{
			Logins: []string{
				userName,
			},
			NodeLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
			Request: &types.AccessRequestConditions{
				Roles:              []string{requestableRoleName},
				SuggestedReviewers: []string{suggestedReviewer},
			},
		},
	})
	require.NoError(t, err)

	// add role that user can request
	err = authServer.UpsertRole(context.Background(), requestableRole)
	require.NoError(t, err)

	// add role that allows to request "requestableRole"
	err = authServer.UpsertRole(context.Background(), userRole)
	require.NoError(t, err)

	user, err := types.NewUser(userName)
	user.AddRole(userRole.GetName())
	require.NoError(t, err)

	err = authServer.UpsertUser(user)
	require.NoError(t, err)

	creds, err := helpers.GenerateUserCreds(helpers.UserCredsRequest{
		Process:  pack.Root.Cluster.Process,
		Username: userName,
	})
	require.NoError(t, err)

	tc := mustLogin(t, userName, pack, creds)

	storage, err := clusters.NewStorage(clusters.Config{
		Dir:                tc.KeysDir,
		InsecureSkipVerify: tc.InsecureSkipVerify,
	})
	require.NoError(t, err)

	daemonService, err := daemon.New(daemon.Config{
		Storage: storage,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		daemonService.Stop()
	})

	handler, err := handler.New(
		handler.Config{
			DaemonService: daemonService,
		},
	)
	require.NoError(t, err)

	rootClusterName, _, err := net.SplitHostPort(pack.Root.Cluster.Web)
	require.NoError(t, err)

	response, err := handler.GetCluster(context.Background(), &api.GetClusterRequest{
		ClusterUri: uri.NewClusterURI(rootClusterName).String(),
	})
	require.NoError(t, err)

	require.Equal(t, userName, response.LoggedInUser.Name)
	require.ElementsMatch(t, []string{requestableRoleName}, response.LoggedInUser.RequestableRoles)
	require.ElementsMatch(t, []string{suggestedReviewer}, response.LoggedInUser.SuggestedReviewers)
}

func testHeadlessWatcher(t *testing.T, pack *dbhelpers.DatabasePack, creds *helpers.UserCreds) {
	t.Helper()
	ctx := context.Background()

	tc := mustLogin(t, pack.Root.User.GetName(), pack, creds)

	storage, err := clusters.NewStorage(clusters.Config{
		Dir:                tc.KeysDir,
		InsecureSkipVerify: tc.InsecureSkipVerify,
	})
	require.NoError(t, err)

	cluster, err := storage.Add(ctx, tc.WebProxyAddr)
	require.NoError(t, err)

	daemonService, err := daemon.New(daemon.Config{
		Storage: storage,
		CreateTshdEventsClientCredsFunc: func() (grpc.DialOption, error) {
			return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		daemonService.Stop()
	})

	expires := pack.Root.Cluster.Config.Clock.Now().Add(time.Minute)
	ha, err := types.NewHeadlessAuthentication(pack.Root.User.GetName(), "uuid", expires)
	require.NoError(t, err)
	ha.State = types.HeadlessAuthenticationState_HEADLESS_AUTHENTICATION_STATE_PENDING

	// Start the tshd event service and connect the daemon to it.

	tshdEventsService, addr := newMockTSHDEventsServiceServer(t)
	err = daemonService.UpdateAndDialTshdEventsServerAddress(addr)
	require.NoError(t, err)

	// Stop and restart the watcher twice to simulate logout + login + relogin. Ensure the watcher catches events.

	err = daemonService.StopHeadlessWatcher(cluster.URI.String())
	require.NoError(t, err)
	err = daemonService.StartHeadlessWatcher(cluster.URI.String(), false /* waitInit */)
	require.NoError(t, err)
	err = daemonService.StartHeadlessWatcher(cluster.URI.String(), true /* waitInit */)
	require.NoError(t, err)

	// Ensure the watcher catches events and sends them to the Electron App.

	err = pack.Root.Cluster.Process.GetAuthServer().UpsertHeadlessAuthentication(ctx, ha)
	assert.NoError(t, err)

	assert.Eventually(t,
		func() bool {
			return tshdEventsService.sendPendingHeadlessAuthenticationCount.Load() == 1
		},
		10*time.Second,
		500*time.Millisecond,
		"Expected tshdEventService to receive 1 SendPendingHeadlessAuthentication message but got %v",
		tshdEventsService.sendPendingHeadlessAuthenticationCount.Load(),
	)
}

// testListDatabaseUsers adds a unique string under spec.allow.db_users of the role automatically
// given to a user by [dbhelpers.DatabasePack] and then checks if that string is returned when
// calling [handler.Handler.ListDatabaseUsers].
func testListDatabaseUsers(t *testing.T, pack *dbhelpers.DatabasePack) {
	ctx := context.Background()

	mustAddDBUserToUserRole := func(ctx context.Context, t *testing.T, cluster *helpers.TeleInstance, user, dbUser string) {
		t.Helper()
		authServer := cluster.Process.GetAuthServer()
		roleName := services.RoleNameForUser(user)
		role, err := authServer.GetRole(ctx, roleName)
		require.NoError(t, err)

		dbUsers := role.GetDatabaseUsers(types.Allow)
		dbUsers = append(dbUsers, dbUser)
		role.SetDatabaseUsers(types.Allow, dbUsers)
		err = authServer.UpsertRole(ctx, role)
		require.NoError(t, err)

		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			role, err := authServer.GetRole(ctx, roleName)
			if assert.NoError(collect, err) {
				assert.Equal(collect, dbUsers, role.GetDatabaseUsers(types.Allow))
			}
		}, 10*time.Second, 100*time.Millisecond)
	}

	mustUpdateUserRoles := func(ctx context.Context, t *testing.T, cluster *helpers.TeleInstance, userName string, roles []string) {
		t.Helper()
		authServer := cluster.Process.GetAuthServer()
		user, err := authServer.GetUser(userName, false /* withSecrets */)
		require.NoError(t, err)

		user.SetRoles(roles)
		err = authServer.UpdateUser(ctx, user)
		require.NoError(t, err)

		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			user, err := authServer.GetUser(userName, false /* withSecrets */)
			if assert.NoError(collect, err) {
				assert.Equal(collect, roles, user.GetRoles())
			}
		}, 10*time.Second, 100*time.Millisecond)
	}

	// Allow resource access requests to be created.
	currentModules := modules.GetModules()
	t.Cleanup(func() { modules.SetModules(currentModules) })
	modules.SetModules(&modules.TestModules{TestBuildType: modules.BuildEnterprise})

	rootClusterName, _, err := net.SplitHostPort(pack.Root.Cluster.Web)
	require.NoError(t, err)
	rootDatabaseURI := uri.NewClusterURI(rootClusterName).AppendDB(pack.Root.PostgresService.Name)
	leafDatabaseURI := uri.NewClusterURI(rootClusterName).AppendLeafCluster(pack.Leaf.Cluster.Secrets.SiteName).AppendDB(pack.Leaf.PostgresService.Name)

	rootDBUser := fmt.Sprintf("root-db-user-%s", uuid.NewString())
	leafDBUser := fmt.Sprintf("leaf-db-user-%s", uuid.NewString())
	leafDBUserWithAccessRequest := fmt.Sprintf("leaf-db-user-with-access-request-%s", uuid.NewString())

	rootUserName := pack.Root.User.GetName()
	leafUserName := pack.Leaf.User.GetName()
	rootRoleName := services.RoleNameForUser(rootUserName)

	tests := []struct {
		name                string
		dbURI               uri.ResourceURI
		wantDBUser          string
		prepareRole         func(ctx context.Context, t *testing.T)
		createAccessRequest func(ctx context.Context, t *testing.T) string
	}{
		{
			name:       "root cluster",
			dbURI:      rootDatabaseURI,
			wantDBUser: rootDBUser,
			prepareRole: func(ctx context.Context, t *testing.T) {
				mustAddDBUserToUserRole(ctx, t, pack.Root.Cluster, rootUserName, rootDBUser)
			},
		},
		{
			name:       "leaf cluster",
			dbURI:      leafDatabaseURI,
			wantDBUser: leafDBUser,
			prepareRole: func(ctx context.Context, t *testing.T) {
				mustAddDBUserToUserRole(ctx, t, pack.Leaf.Cluster, leafUserName, leafDBUser)
			},
		},
		{
			name:       "leaf cluster with resource access request",
			dbURI:      leafDatabaseURI,
			wantDBUser: leafDBUserWithAccessRequest,
			// Remove role from root-user and move it to search_as_roles.
			//
			// root-user has access to leafDatabaseURI through the user:root-user role which gets mapped
			// to a corresponding leaf cluster role.
			// We want to create a resource access request for that database. To do this, we need to
			// create a new role which lets root-user request the database.
			prepareRole: func(ctx context.Context, t *testing.T) {
				mustAddDBUserToUserRole(ctx, t, pack.Leaf.Cluster, leafUserName, leafDBUserWithAccessRequest)

				authServer := pack.Root.Cluster.Process.GetAuthServer()

				// Create new role that lets root-user request the database.
				requesterRole, err := types.NewRole(fmt.Sprintf("requester-%s", uuid.NewString()), types.RoleSpecV6{
					Allow: types.RoleConditions{
						Request: &types.AccessRequestConditions{
							SearchAsRoles: []string{rootRoleName},
						},
					},
				})
				require.NoError(t, err)
				err = authServer.CreateRole(ctx, requesterRole)
				require.NoError(t, err)

				user, err := authServer.GetUser(rootUserName, false /* withSecrets */)
				require.NoError(t, err)

				// Delete rootRoleName from roles, add requester role. Restore original role set after test
				// is done.
				currentRoles := user.GetRoles()
				t.Cleanup(func() { mustUpdateUserRoles(ctx, t, pack.Root.Cluster, rootUserName, currentRoles) })
				mustUpdateUserRoles(ctx, t, pack.Root.Cluster, rootUserName, []string{requesterRole.GetName()})
			},
			createAccessRequest: func(ctx context.Context, t *testing.T) string {
				req, err := services.NewAccessRequestWithResources(rootUserName, []string{rootRoleName}, []types.ResourceID{
					types.ResourceID{
						ClusterName: pack.Leaf.Cluster.Secrets.SiteName,
						Kind:        types.KindDatabase,
						Name:        pack.Leaf.PostgresService.Name,
					},
				})
				require.NoError(t, err)

				authServer := pack.Root.Cluster.Process.GetAuthServer()
				req, err = authServer.CreateAccessRequestV2(ctx, req, tlsca.Identity{})
				require.NoError(t, err)

				err = authServer.SetAccessRequestState(ctx, types.AccessRequestUpdate{
					RequestID: req.GetName(),
					State:     types.RequestState_APPROVED,
				})
				require.NoError(t, err)

				return req.GetName()
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.prepareRole(ctx, t)
			var accessRequestID string
			if test.createAccessRequest != nil {
				accessRequestID = test.createAccessRequest(ctx, t)

				if accessRequestID == "" {
					require.FailNow(t, "createAccessRequest returned empty access request ID")
				}
			}

			creds, err := helpers.GenerateUserCreds(helpers.UserCredsRequest{
				Process:  pack.Root.Cluster.Process,
				Username: rootUserName,
			})
			require.NoError(t, err)

			tc := mustLogin(t, rootUserName, pack, creds)

			storage, err := clusters.NewStorage(clusters.Config{
				Dir:                tc.KeysDir,
				InsecureSkipVerify: tc.InsecureSkipVerify,
			})
			require.NoError(t, err)

			daemonService, err := daemon.New(daemon.Config{
				Storage: storage,
			})
			require.NoError(t, err)
			t.Cleanup(func() {
				daemonService.Stop()
			})

			handler, err := handler.New(
				handler.Config{
					DaemonService: daemonService,
				},
			)
			require.NoError(t, err)

			if accessRequestID != "" {
				_, err := handler.AssumeRole(ctx, &api.AssumeRoleRequest{
					RootClusterUri:   test.dbURI.GetRootClusterURI().String(),
					AccessRequestIds: []string{accessRequestID},
				})
				require.NoError(t, err)
			}

			res, err := handler.ListDatabaseUsers(ctx, &api.ListDatabaseUsersRequest{
				DbUri: test.dbURI.String(),
			})
			require.NoError(t, err)
			require.Contains(t, res.Users, test.wantDBUser)
		})
	}

}

// mustLogin logs in as the given user by completely skipping the actual login flow and saving valid
// certs to disk. clusters.Storage can then be pointed to tc.KeysDir and daemon.Service can act as
// if the user was successfully logged in.
//
// This is faster than going through the actual process, but keep in mind that it might skip some
// vital steps. It should be used only for tests which don't depend on complex user setup and do not
// reissue certs or modify them in some other way.
func mustLogin(t *testing.T, userName string, pack *dbhelpers.DatabasePack, creds *helpers.UserCreds) *client.TeleportClient {
	tc, err := pack.Root.Cluster.NewClientWithCreds(helpers.ClientConfig{
		Login:   userName,
		Cluster: pack.Root.Cluster.Secrets.SiteName,
	}, *creds)
	require.NoError(t, err)
	// Save the profile yaml file to disk as NewClientWithCreds doesn't do that by itself.
	tc.SaveProfile(false /* makeCurrent */)
	return tc
}

type mockTSHDEventsService struct {
	*api.UnimplementedTshdEventsServiceServer
	sendPendingHeadlessAuthenticationCount atomic.Uint32
}

func newMockTSHDEventsServiceServer(t *testing.T) (service *mockTSHDEventsService, addr string) {
	tshdEventsService := &mockTSHDEventsService{}

	ls, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer()
	api.RegisterTshdEventsServiceServer(grpcServer, tshdEventsService)

	serveErr := make(chan error)
	go func() {
		serveErr <- grpcServer.Serve(ls)
	}()

	t.Cleanup(func() {
		grpcServer.GracefulStop()

		// For test cases that did not send any grpc calls, test may finish
		// before grpcServer.Serve is called and grpcServer.Serve will return
		// grpc.ErrServerStopped.
		err := <-serveErr
		if err != grpc.ErrServerStopped {
			assert.NoError(t, err)
		}
	})

	return tshdEventsService, ls.Addr().String()
}

func (c *mockTSHDEventsService) SendPendingHeadlessAuthentication(context.Context, *api.SendPendingHeadlessAuthenticationRequest) (*api.SendPendingHeadlessAuthenticationResponse, error) {
	c.sendPendingHeadlessAuthenticationCount.Add(1)
	return &api.SendPendingHeadlessAuthenticationResponse{}, nil
}
