/**
 * Copyright 2021 Gravitational, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package web

import (
	"context"
	"fmt"
	"testing"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/web/ui"

	"github.com/gravitational/trace"

	"github.com/stretchr/testify/require"
)

func TestExtractResourceAndValidate(t *testing.T) {
	goodContent := `kind: role
metadata:
  name: test
spec:
  allow:
    logins:
    - testing
version: v3`
	extractedResource, err := ExtractResourceAndValidate(goodContent)
	require.Nil(t, err)
	require.NotNil(t, extractedResource)

	// Test missing name.
	badContent := `kind: role
metadata:
  name:`
	extractedResource, err = ExtractResourceAndValidate(badContent)
	require.Nil(t, extractedResource)
	require.True(t, trace.IsBadParameter(err))
	require.Contains(t, err.Error(), "Name")
}

func TestCheckResourceUpsertableByError(t *testing.T) {
	err := CheckResourceUpsertableByError(trace.BadParameter(""), "POST", "")
	require.True(t, trace.IsBadParameter(err))

	err = CheckResourceUpsertableByError(nil, "POST", "")
	require.True(t, trace.IsAlreadyExists(err))

	err = CheckResourceUpsertableByError(trace.NotFound(""), "POST", "")
	require.Nil(t, err)

	err = CheckResourceUpsertableByError(nil, "PUT", "")
	require.Nil(t, err)

	err = CheckResourceUpsertableByError(trace.NotFound(""), "PUT", "")
	require.True(t, trace.IsNotFound(err))
}

func TestNewResourceItem(t *testing.T) {
	// Test github resource.
	githubConn := types.NewGithubConnector("githubName", types.GithubConnectorSpecV3{})
	item, err := ui.NewResourceItem(githubConn)
	require.Nil(t, err)
	require.Equal(t, item.ID, fmt.Sprintf("%s:%s", types.KindGithubConnector, "githubName"))
	require.Equal(t, item.Kind, types.KindGithubConnector)
	require.Equal(t, item.Name, "githubName")
	require.Contains(t, item.Content, types.KindGithubConnector)

	// Test role resource.
	role, err := types.NewRole("roleName", types.RoleSpecV3{
		Allow: types.RoleConditions{
			Logins: []string{"test"},
		},
	})
	require.Nil(t, err)

	item, err = ui.NewResourceItem(role)
	require.Nil(t, err)
	require.Equal(t, item.ID, fmt.Sprintf("%s:%s", types.KindRole, "roleName"))
	require.Equal(t, item.Kind, types.KindRole)
	require.Equal(t, item.Name, "roleName")
	require.Contains(t, item.Content, types.KindRole)

	// Test trusted cluster resource.
	cluster, err := types.NewTrustedCluster("tcName", types.TrustedClusterSpecV2{})
	require.Nil(t, err)

	item, err = ui.NewResourceItem(cluster)
	require.Nil(t, err)
	require.Equal(t, item.ID, fmt.Sprintf("%s:%s", types.KindTrustedCluster, "tcName"))
	require.Equal(t, item.Kind, types.KindTrustedCluster)
	require.Equal(t, item.Name, "tcName")
	require.Contains(t, item.Content, types.KindTrustedCluster)
}

func TestGetRoles(t *testing.T) {
	m := &mockedResourceAPIGetter{}

	m.mockGetRoles = func() ([]types.Role, error) {
		role, err := types.NewRole("test", types.RoleSpecV3{
			Allow: types.RoleConditions{
				Logins: []string{"test"},
			},
		})
		require.Nil(t, err)

		return []types.Role{role}, nil
	}

	// Test response is converted to ui objects.
	roles, err := getRoles(m)
	require.Nil(t, err)
	require.Len(t, roles, 1)
	require.Contains(t, roles[0].Content, "name: test")
}

func TestUpsertRole(t *testing.T) {
	m := &mockedResourceAPIGetter{}

	m.mockUpsertRole = func(ctx context.Context, role types.Role) error {
		return nil
	}
	m.mockGetRole = func(name string) (types.Role, error) {
		return nil, trace.NotFound("")
	}

	// Test bad request kind.
	badKind := `kind: bad-kind
metadata:
  name: test`
	role, err := upsertRole(context.Background(), m, badKind, "")
	require.Nil(t, role)
	require.True(t, trace.IsBadParameter(err))
	require.Contains(t, err.Error(), "kind")

	goodContent := `kind: role
metadata:
  name: test
spec:
  allow:
    logins:
    - testing
version: v3`

	// Test POST (create) role.
	role, err = upsertRole(context.Background(), m, goodContent, "POST")
	require.Nil(t, err)
	require.Contains(t, role.Content, "name: test")

	// Test error with PUT (update) with non existing role.
	role, err = upsertRole(context.Background(), m, goodContent, "PUT")
	require.Nil(t, role)
	require.True(t, trace.IsNotFound(err))
}

func TestGetGithubConnectors(t *testing.T) {
	m := &mockedResourceAPIGetter{}

	m.mockGetGithubConnectors = func(withSecrets bool) ([]types.GithubConnector, error) {
		connector := types.NewGithubConnector("test", types.GithubConnectorSpecV3{})

		return []types.GithubConnector{connector}, nil
	}

	// Test response is converted to ui objects.
	connectors, err := getGithubConnectors(m)
	require.Nil(t, err)
	require.Len(t, connectors, 1)
	require.Contains(t, connectors[0].Content, "name: test")
}

func TestUpsertGithubConnector(t *testing.T) {
	m := &mockedResourceAPIGetter{}
	m.mockUpsertGithubConnector = func(ctx context.Context, connector types.GithubConnector) error {
		return nil
	}
	m.mockGetGithubConnector = func(id string, withSecrets bool) (types.GithubConnector, error) {
		return nil, trace.NotFound("")
	}

	// Test bad request kind.
	badKind := `kind: bad-kind
metadata:
  name: test`
	conn, err := upsertGithubConnector(context.Background(), m, badKind, "")
	require.Nil(t, conn)
	require.True(t, trace.IsBadParameter(err))
	require.Contains(t, err.Error(), "kind")

	goodContent := `kind: github
metadata:
  name: test
spec:
  client_id: <client-id>
  client_secret: <client-secret>
  display: Github
  redirect_url: https://<cluster-url>/v1/webapi/github/callback
  teams_to_logins:
  - logins:
    - admins
    organization: <github-org>
    team: admins
version: v3`

	// Test POST (create) connector.
	connector, err := upsertGithubConnector(context.Background(), m, goodContent, "POST")
	require.Nil(t, err)
	require.Contains(t, connector.Content, "name: test")
}

func TestGetTrustedClusters(t *testing.T) {
	m := &mockedResourceAPIGetter{}

	m.mockGetTrustedClusters = func() ([]types.TrustedCluster, error) {
		cluster, err := types.NewTrustedCluster("test", types.TrustedClusterSpecV2{})
		require.Nil(t, err)

		return []types.TrustedCluster{cluster}, nil
	}

	// Test response is converted to ui objects.
	tcs, err := getTrustedClusters(m)
	require.Nil(t, err)
	require.Len(t, tcs, 1)
	require.Contains(t, tcs[0].Content, "name: test")
}

func TestUpsertTrustedCluster(t *testing.T) {
	m := &mockedResourceAPIGetter{}
	m.mockUpsertTrustedCluster = func(ctx context.Context, tc types.TrustedCluster) (types.TrustedCluster, error) {
		return nil, nil
	}
	m.mockGetTrustedCluster = func(name string) (types.TrustedCluster, error) {
		return nil, trace.NotFound("")
	}

	// Test bad request kind.
	badKind := `kind: bad-kind
metadata:
  name: test`
	conn, err := upsertTrustedCluster(context.Background(), m, badKind, "")
	require.Nil(t, conn)
	require.True(t, trace.IsBadParameter(err))
	require.Contains(t, err.Error(), "kind")

	// Test create (POST).
	goodContent := `kind: trusted_cluster
metadata:
  name: test
spec:
  role_map:
  - local:
    - admin
    remote: admin
version: v2`
	tc, err := upsertTrustedCluster(context.Background(), m, goodContent, "POST")
	require.Nil(t, err)
	require.Contains(t, tc.Content, "name: test")
}

type mockedResourceAPIGetter struct {
	mockGetRole               func(name string) (types.Role, error)
	mockGetRoles              func() ([]types.Role, error)
	mockUpsertRole            func(ctx context.Context, role types.Role) error
	mockUpsertGithubConnector func(ctx context.Context, connector types.GithubConnector) error
	mockGetGithubConnectors   func(withSecrets bool) ([]types.GithubConnector, error)
	mockGetGithubConnector    func(id string, withSecrets bool) (types.GithubConnector, error)
	mockDeleteGithubConnector func(ctx context.Context, id string) error
	mockUpsertTrustedCluster  func(ctx context.Context, tc types.TrustedCluster) (types.TrustedCluster, error)
	mockGetTrustedCluster     func(string) (types.TrustedCluster, error)
	mockGetTrustedClusters    func() ([]types.TrustedCluster, error)
	mockDeleteTrustedCluster  func(ctx context.Context, name string) error
}

func (m *mockedResourceAPIGetter) GetRole(name string) (types.Role, error) {
	if m.mockGetRole != nil {
		return m.mockGetRole(name)
	}
	return nil, trace.NotImplemented("mockGetRole not implemented")
}

func (m *mockedResourceAPIGetter) GetRoles() ([]types.Role, error) {
	if m.mockGetRoles != nil {
		return m.mockGetRoles()
	}
	return nil, trace.NotImplemented("mockGetRoles not implemented")
}

func (m *mockedResourceAPIGetter) UpsertRole(ctx context.Context, role types.Role) error {
	if m.mockUpsertRole != nil {
		return m.mockUpsertRole(ctx, role)
	}

	return trace.NotImplemented("mockUpsertRole not implemented")
}

func (m *mockedResourceAPIGetter) UpsertGithubConnector(ctx context.Context, connector types.GithubConnector) error {
	if m.mockUpsertGithubConnector != nil {
		return m.mockUpsertGithubConnector(ctx, connector)
	}

	return trace.NotImplemented("mockUpsertGithubConnector not implemented")
}

func (m *mockedResourceAPIGetter) GetGithubConnectors(withSecrets bool) ([]types.GithubConnector, error) {
	if m.mockGetGithubConnectors != nil {
		return m.mockGetGithubConnectors(false)
	}

	return nil, trace.NotImplemented("mockGetGithubConnectors not implemented")
}

func (m *mockedResourceAPIGetter) GetGithubConnector(id string, withSecrets bool) (types.GithubConnector, error) {
	if m.mockGetGithubConnector != nil {
		return m.mockGetGithubConnector(id, false)
	}

	return nil, trace.NotImplemented("mockGetGithubConnector not implemented")
}

func (m *mockedResourceAPIGetter) DeleteGithubConnector(ctx context.Context, id string) error {
	if m.mockDeleteGithubConnector != nil {
		return m.mockDeleteGithubConnector(ctx, id)
	}

	return trace.NotImplemented("mockDeleteGithubConnector not implemented")
}

func (m *mockedResourceAPIGetter) UpsertTrustedCluster(ctx context.Context, tc types.TrustedCluster) (types.TrustedCluster, error) {
	if m.mockUpsertTrustedCluster != nil {
		return m.mockUpsertTrustedCluster(ctx, tc)
	}

	return nil, trace.NotImplemented("mockUpsertTrustedCluster not implemented")
}

func (m *mockedResourceAPIGetter) GetTrustedCluster(name string) (types.TrustedCluster, error) {
	if m.mockGetTrustedCluster != nil {
		return m.mockGetTrustedCluster(name)
	}

	return nil, trace.NotImplemented("mockGetTrustedCluster not implemented")
}

func (m *mockedResourceAPIGetter) GetTrustedClusters() ([]types.TrustedCluster, error) {
	if m.mockGetTrustedClusters != nil {
		return m.mockGetTrustedClusters()
	}

	return nil, trace.NotImplemented("mockGetTrustedClusters not implemented")
}

func (m *mockedResourceAPIGetter) DeleteTrustedCluster(ctx context.Context, name string) error {
	if m.mockDeleteTrustedCluster != nil {
		return m.mockDeleteTrustedCluster(ctx, name)
	}

	return trace.NotImplemented("mockDeleteTrustedCluster not implemented")
}
