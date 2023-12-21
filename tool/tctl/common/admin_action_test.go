/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package common_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	machineidv1pb "github.com/gravitational/teleport/api/gen/proto/go/teleport/machineid/v1"
	"github.com/gravitational/teleport/api/mfa"
	"github.com/gravitational/teleport/api/types"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/auth/mocku2f"
	wancli "github.com/gravitational/teleport/lib/auth/webauthncli"
	wantypes "github.com/gravitational/teleport/lib/auth/webauthntypes"
	libclient "github.com/gravitational/teleport/lib/client"
	libmfa "github.com/gravitational/teleport/lib/client/mfa"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/service/servicecfg"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
	tctl "github.com/gravitational/teleport/tool/tctl/common"
	testserver "github.com/gravitational/teleport/tool/teleport/testenv"
	tsh "github.com/gravitational/teleport/tool/tsh/common"
)

func TestAdminActionMFA(t *testing.T) {
	s := newAdminActionTestSuite(t)

	t.Run("Users", s.testUsers)
	t.Run("Bots", s.testBots)
	t.Run("AuthSign", s.testAuthSign)
	t.Run("Roles", s.testRoles)
	t.Run("AccessRequests", s.testAccessRequests)
	t.Run("Tokens", s.testTokens)
	t.Run("UserGroups", s.testUserGroups)
	t.Run("OIDCConnector", s.testOIDCConnector)
	t.Run("SAMLConnector", s.testSAMLConnector)
	t.Run("GithubConnector", s.testGithubConnector)
	t.Run("SAMLIdpServiceProvider", s.testSAMLIdpServiceProvider)
}

func (s *adminActionTestSuite) testUsers(t *testing.T) {
	ctx := context.Background()

	user, err := types.NewUser("teleuser")
	require.NoError(t, err)

	createUser := func() error {
		_, err := s.authServer.CreateUser(ctx, user)
		return trace.Wrap(err)
	}

	deleteUser := func() error {
		return s.authServer.DeleteUser(ctx, "teleuser")
	}

	for name, tc := range map[string]adminActionTestCase{
		"tctl users add": {
			command:    "users add teleuser --roles=access",
			cliCommand: &tctl.UserCommand{},
			cleanup:    deleteUser,
		},
		"tctl users update": {
			command:    "users update teleuser --set-roles=access,auditor",
			cliCommand: &tctl.UserCommand{},
			setup:      createUser,
			cleanup:    deleteUser,
		},
		"tctl users rm": {
			command:    "users rm teleuser",
			cliCommand: &tctl.UserCommand{},
			setup:      createUser,
			cleanup:    deleteUser,
		},
		"tctl users reset": {
			command:    "users reset teleuser",
			cliCommand: &tctl.UserCommand{},
			setup:      createUser,
			cleanup:    deleteUser,
		},
	} {
		t.Run(name, func(t *testing.T) {
			s.testCommand(t, ctx, tc)
		})
	}

	s.testResourceCommand(t, ctx, resourceCommandTestCase{
		resource:       user,
		resourceCreate: createUser,
		resourceDelete: deleteUser,
	})
}

func (s *adminActionTestSuite) testBots(t *testing.T) {
	ctx := context.Background()

	botName := "bot"
	botReq := &machineidv1pb.CreateBotRequest{
		Bot: &machineidv1pb.Bot{
			Metadata: &headerv1.Metadata{
				Name: botName,
			},
			Spec: &machineidv1pb.BotSpec{
				Roles: []string{teleport.PresetAccessRoleName},
			},
		},
	}

	createBot := func() error {
		_, err := s.localAdminClient.BotServiceClient().CreateBot(ctx, botReq)
		return trace.Wrap(err)
	}

	deleteBot := func() error {
		_, err := s.localAdminClient.BotServiceClient().DeleteBot(ctx, &machineidv1pb.DeleteBotRequest{
			BotName: botName,
		})
		return trace.Wrap(err)
	}

	t.Run("BotCommands", func(t *testing.T) {
		for name, tc := range map[string]adminActionTestCase{
			"tctl bots add": {
				command:    fmt.Sprintf("bots add --roles=%v %v", teleport.PresetAccessRoleName, botName),
				cliCommand: &tctl.BotsCommand{},
				cleanup:    deleteBot,
			},
			"tctl bots rm": {
				command:    fmt.Sprintf("bots rm %v", botName),
				cliCommand: &tctl.BotsCommand{},
				setup:      createBot,
				cleanup:    deleteBot,
			},
		} {
			t.Run(name, func(t *testing.T) {
				s.testCommand(t, ctx, tc)
			})
		}
	})
}

func (s *adminActionTestSuite) testAuthSign(t *testing.T) {
	ctx := context.Background()

	user, err := types.NewUser("teleuser")
	require.NoError(t, err)
	_, err = s.authServer.CreateUser(ctx, user)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, s.authServer.DeleteUser(ctx, user.GetName()))
	})

	identityFilePath := filepath.Join(t.TempDir(), "identity")

	t.Run("AuthCommands", func(t *testing.T) {
		t.Run("Impersonation", func(t *testing.T) {
			s.testCommand(t, ctx, adminActionTestCase{
				command:    fmt.Sprintf("auth sign --out=%v --user=%v --overwrite", identityFilePath, user.GetName()),
				cliCommand: &tctl.AuthCommand{},
			})
		})

		// Renewing certs for yourself should not require admin MFA.
		t.Run("RenewCerts", func(t *testing.T) {
			err := runTestCase(t, ctx, s.userClientNoMFA, adminActionTestCase{
				command:    fmt.Sprintf("auth sign --out=%v --user=admin --overwrite", identityFilePath),
				cliCommand: &tctl.AuthCommand{},
			})
			require.NoError(t, err)
		})
	})
}

func (s *adminActionTestSuite) testRoles(t *testing.T) {
	ctx := context.Background()

	role, err := types.NewRole("telerole", types.RoleSpecV6{})
	require.NoError(t, err)

	createRole := func() error {
		_, err := s.authServer.CreateRole(ctx, role)
		return trace.Wrap(err)
	}

	getRole := func() (types.Resource, error) {
		return s.authServer.GetRole(ctx, role.GetName())
	}

	deleteRole := func() error {
		return s.authServer.DeleteRole(ctx, role.GetName())
	}

	s.testResourceCommand(t, ctx, resourceCommandTestCase{
		resource:       role,
		resourceCreate: createRole,
		resourceDelete: deleteRole,
	})

	s.testEditCommand(t, ctx, editCommandTestCase{
		resourceRef:    getResourceRef(role),
		resourceCreate: createRole,
		resourceGet:    getRole,
		resourceDelete: deleteRole,
	})
}

func (s *adminActionTestSuite) testAccessRequests(t *testing.T) {
	ctx := context.Background()

	role, err := types.NewRole("telerole", types.RoleSpecV6{
		Allow: types.RoleConditions{
			Request: &types.AccessRequestConditions{
				Roles: []string{teleport.PresetAccessRoleName},
			},
		},
	})
	require.NoError(t, err)
	_, err = s.authServer.CreateRole(ctx, role)
	require.NoError(t, err)

	user, err := types.NewUser("teleuser")
	require.NoError(t, err)
	user.SetRoles([]string{role.GetName()})
	_, err = s.authServer.CreateUser(ctx, user)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, s.authServer.DeleteUser(ctx, user.GetName()))
		require.NoError(t, s.authServer.DeleteRole(ctx, role.GetName()))
	})

	accessRequest, err := services.NewAccessRequest(user.GetName(), teleport.PresetAccessRoleName)
	require.NoError(t, err)
	accessRequest.SetThresholds([]types.AccessReviewThreshold{{
		Name:    "one",
		Approve: 1,
		Deny:    1,
	}})

	createAccessRequest := func() error {
		return s.authServer.CreateAccessRequest(ctx, accessRequest)
	}

	deleteAllAccessRequests := func() error {
		return s.authServer.DeleteAllAccessRequests(ctx)
	}

	t.Run("AccessRequestCommands", func(t *testing.T) {
		for _, tc := range map[string]adminActionTestCase{
			"tctl requests create": {
				// creating an access request on behalf of another user requires admin MFA.
				command:    fmt.Sprintf("requests create --roles=%v %v", teleport.PresetAccessRoleName, user.GetName()),
				cliCommand: &tctl.AccessRequestCommand{},
				cleanup:    deleteAllAccessRequests,
			},
			"tctl requests approve": {
				command:    fmt.Sprintf("requests approve %v", accessRequest.GetName()),
				cliCommand: &tctl.AccessRequestCommand{},
				setup:      createAccessRequest,
				cleanup:    deleteAllAccessRequests,
			},
			"tctl requests deny": {
				command:    fmt.Sprintf("requests deny %v", accessRequest.GetName()),
				cliCommand: &tctl.AccessRequestCommand{},
				setup:      createAccessRequest,
				cleanup:    deleteAllAccessRequests,
			},
			"tctl requests review --approve": {
				command:    fmt.Sprintf("requests review %v --author=admin --approve", accessRequest.GetName()),
				cliCommand: &tctl.AccessRequestCommand{},
				setup:      createAccessRequest,
				cleanup:    deleteAllAccessRequests,
			},
			"tctl requests review --deny": {
				command:    fmt.Sprintf("requests review %v --author=admin --deny", accessRequest.GetName()),
				cliCommand: &tctl.AccessRequestCommand{},
				setup:      createAccessRequest,
				cleanup:    deleteAllAccessRequests,
			},
			"tctl requests rm": {
				command:    fmt.Sprintf("requests rm %v", accessRequest.GetName()),
				cliCommand: &tctl.AccessRequestCommand{},
				setup:      createAccessRequest,
				cleanup:    deleteAllAccessRequests,
			},
		} {
			t.Run(tc.command, func(t *testing.T) {
				s.testCommand(t, ctx, tc)
			})
		}

		// Creating an access request for yourself should not require admin MFA.
		t.Run("OK owner creating access request without MFA", func(t *testing.T) {
			err := runTestCase(t, ctx, s.userClientNoMFA, adminActionTestCase{
				command:    fmt.Sprintf("requests create --roles=%v %v", teleport.PresetAccessRoleName, "admin"),
				cliCommand: &tctl.AccessRequestCommand{},
				setup:      createAccessRequest,
				cleanup:    deleteAllAccessRequests,
			})
			require.NoError(t, err)
		})
	})
}

func (s *adminActionTestSuite) testTokens(t *testing.T) {
	ctx := context.Background()

	token, err := types.NewProvisionToken("teletoken", []types.SystemRole{types.RoleNode}, time.Time{})
	require.NoError(t, err)

	createToken := func() error {
		return s.authServer.CreateToken(ctx, token)
	}

	getToken := func() (types.Resource, error) {
		return s.authServer.GetToken(ctx, token.GetName())
	}

	deleteToken := func() error {
		return s.authServer.DeleteToken(ctx, token.GetName())
	}

	t.Run("TokensCommands", func(t *testing.T) {
		for _, tc := range []adminActionTestCase{
			{
				command:    fmt.Sprintf("tokens add --type=%v --value=%v", types.RoleNode, token.GetName()),
				cliCommand: &tctl.TokensCommand{},
				cleanup:    deleteToken,
			}, {
				command:    fmt.Sprintf("tokens rm %v", token.GetName()),
				cliCommand: &tctl.TokensCommand{},
				setup:      createToken,
				cleanup:    deleteToken,
			},
		} {
			t.Run(tc.command, func(t *testing.T) {
				s.testCommand(t, ctx, tc)
			})
		}
	})

	t.Run("ResourceCommands", func(t *testing.T) {
		s.testResourceCommand(t, ctx, resourceCommandTestCase{
			resource:       token,
			resourceCreate: createToken,
			resourceDelete: deleteToken,
		})
	})

	t.Run("EditCommand", func(t *testing.T) {
		s.testEditCommand(t, ctx, editCommandTestCase{
			resourceRef:    getResourceRef(token),
			resourceCreate: createToken,
			resourceGet:    getToken,
			resourceDelete: deleteToken,
		})
	})
}

func (s *adminActionTestSuite) testUserGroups(t *testing.T) {
	ctx := context.Background()

	userGroup, err := types.NewUserGroup(types.Metadata{
		Name:   "teleusergroup",
		Labels: map[string]string{"label": "value"},
	}, types.UserGroupSpecV1{})
	require.NoError(t, err)

	// Only deletion is permitted through tctl.
	t.Run("tctl rm", func(t *testing.T) {
		s.testCommand(t, ctx, adminActionTestCase{
			command:    fmt.Sprintf("rm %v", getResourceRef(userGroup)),
			cliCommand: &tctl.ResourceCommand{},
			setup: func() error {
				return s.authServer.CreateUserGroup(ctx, userGroup)
			},
			cleanup: func() error {
				return s.authServer.DeleteUserGroup(ctx, userGroup.GetName())
			},
		})
	})
}

func (s *adminActionTestSuite) testOIDCConnector(t *testing.T) {
	ctx := context.Background()

	connector, err := types.NewOIDCConnector("oidc", types.OIDCConnectorSpecV3{
		ClientID:     "12345",
		ClientSecret: "678910",
		RedirectURLs: []string{"https://proxy.example.com/v1/webapi/oidc/callback"},
		Display:      "OIDC",
		ClaimsToRoles: []types.ClaimMapping{
			{
				Claim: "test",
				Value: "test",
				Roles: []string{"access", "editor", "auditor"},
			},
		},
	})
	require.NoError(t, err)

	createOIDCConnector := func() error {
		_, err := s.authServer.CreateOIDCConnector(ctx, connector)
		return trace.Wrap(err)
	}

	getOIDCConnector := func() (types.Resource, error) {
		return s.authServer.GetOIDCConnector(ctx, connector.GetName(), true)
	}

	deleteOIDCConnector := func() error {
		return s.authServer.DeleteOIDCConnector(ctx, connector.GetName())
	}

	t.Run("ResourceCommands", func(t *testing.T) {
		s.testResourceCommand(t, ctx, resourceCommandTestCase{
			resource:       connector,
			resourceCreate: createOIDCConnector,
			resourceDelete: deleteOIDCConnector,
		})
	})

	t.Run("EditCommand", func(t *testing.T) {
		s.testEditCommand(t, ctx, editCommandTestCase{
			resourceRef:    getResourceRef(connector),
			resourceCreate: createOIDCConnector,
			resourceGet:    getOIDCConnector,
			resourceDelete: deleteOIDCConnector,
		})
	})
}

func (s *adminActionTestSuite) testSAMLConnector(t *testing.T) {
	ctx := context.Background()

	connector, err := types.NewSAMLConnector("saml", types.SAMLConnectorSpecV2{
		AssertionConsumerService: "http://localhost:65535/acs", // not called
		Issuer:                   "test",
		SSO:                      "https://localhost:65535/sso", // not called
		AttributesToRoles: []types.AttributeMapping{
			// not used. can be any name, value but role must exist
			{Name: "groups", Value: "admin", Roles: []string{"access"}},
		},
	})
	require.NoError(t, err)

	createSAMLConnector := func() error {
		_, err := s.authServer.CreateSAMLConnector(ctx, connector)
		return trace.Wrap(err)
	}

	getSAMLConnector := func() (types.Resource, error) {
		return s.authServer.GetSAMLConnector(ctx, connector.GetName(), true)
	}

	deleteSAMLConnector := func() error {
		return s.authServer.DeleteSAMLConnector(ctx, connector.GetName())
	}

	t.Run("ResourceCommands", func(t *testing.T) {
		s.testResourceCommand(t, ctx, resourceCommandTestCase{
			resource:       connector,
			resourceCreate: createSAMLConnector,
			resourceDelete: deleteSAMLConnector,
		})
	})

	t.Run("EditCommand", func(t *testing.T) {
		s.testEditCommand(t, ctx, editCommandTestCase{
			resourceRef:    getResourceRef(connector),
			resourceCreate: createSAMLConnector,
			resourceGet:    getSAMLConnector,
			resourceDelete: deleteSAMLConnector,
		})
	})
}

func (s *adminActionTestSuite) testGithubConnector(t *testing.T) {
	ctx := context.Background()

	connector, err := types.NewGithubConnector("github", types.GithubConnectorSpecV3{
		ClientID:     "12345",
		ClientSecret: "678910",
		RedirectURL:  "https://proxy.example.com/v1/webapi/github/callback",
		Display:      "Github",
		TeamsToRoles: []types.TeamRolesMapping{
			{
				Organization: "acme",
				Team:         "users",
				Roles:        []string{"access", "editor", "auditor"},
			},
		},
	})
	require.NoError(t, err)

	createGithubConnector := func() error {
		_, err := s.authServer.CreateGithubConnector(ctx, connector)
		return trace.Wrap(err)
	}

	getGithubConnector := func() (types.Resource, error) {
		return s.authServer.GetGithubConnector(ctx, connector.GetName(), true)
	}

	deleteGithubConnector := func() error {
		return s.authServer.DeleteGithubConnector(ctx, connector.GetName())
	}

	t.Run("ResourceCommands", func(t *testing.T) {
		s.testResourceCommand(t, ctx, resourceCommandTestCase{
			resource:       connector,
			resourceCreate: createGithubConnector,
			resourceDelete: deleteGithubConnector,
		})
	})

	t.Run("EditCommand", func(t *testing.T) {
		s.testEditCommand(t, ctx, editCommandTestCase{
			resourceRef:    getResourceRef(connector),
			resourceCreate: createGithubConnector,
			resourceGet:    getGithubConnector,
			resourceDelete: deleteGithubConnector,
		})
	})
}

func (s *adminActionTestSuite) testSAMLIdpServiceProvider(t *testing.T) {
	ctx := context.Background()

	sp, err := types.NewSAMLIdPServiceProvider(types.Metadata{
		Name: "test-saml-app",
	}, types.SAMLIdPServiceProviderSpecV1{
		// A test entity descriptor from https://sptest.iamshowcase.com/testsp_metadata.xml.
		EntityDescriptor: `<?xml version="1.0" encoding="UTF-8"?>
		<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="test-saml-app" validUntil="2025-12-09T09:13:31.006Z">
			 <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
					<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
					<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
					<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sptest.iamshowcase.com/acs" index="0" isDefault="true"/>
			 </md:SPSSODescriptor>
		</md:EntityDescriptor>`,
		EntityID: "test-saml-app",
	})
	require.NoError(t, err)

	CreateSAMLIdPServiceProvider := func() error {
		return s.authServer.CreateSAMLIdPServiceProvider(ctx, sp)
	}

	getSAMLIdPServiceProvider := func() (types.Resource, error) {
		return s.authServer.GetSAMLIdPServiceProvider(ctx, sp.GetName())
	}

	deleteSAMLIdPServiceProvider := func() error {
		return s.authServer.DeleteSAMLIdPServiceProvider(ctx, sp.GetName())
	}

	t.Run("ResourceCommands", func(t *testing.T) {
		s.testResourceCommand(t, ctx, resourceCommandTestCase{
			resource:       sp,
			resourceCreate: CreateSAMLIdPServiceProvider,
			resourceDelete: deleteSAMLIdPServiceProvider,
		})
	})

	t.Run("EditCommand", func(t *testing.T) {
		s.testEditCommand(t, ctx, editCommandTestCase{
			resourceRef:    getResourceRef(sp),
			resourceCreate: CreateSAMLIdPServiceProvider,
			resourceGet:    getSAMLIdPServiceProvider,
			resourceDelete: deleteSAMLIdPServiceProvider,
		})
	})
}

type resourceCommandTestCase struct {
	resource       types.Resource
	resourceCreate func() error
	resourceDelete func() error
}

func (s *adminActionTestSuite) testResourceCommand(t *testing.T, ctx context.Context, tc resourceCommandTestCase) {
	t.Helper()

	f, err := os.CreateTemp(t.TempDir(), "resource-*.yaml")
	require.NoError(t, err)
	require.NoError(t, utils.WriteYAML(f, tc.resource))

	t.Run("tctl create", func(t *testing.T) {
		s.testCommand(t, ctx, adminActionTestCase{
			command:    fmt.Sprintf("create %v", f.Name()),
			cliCommand: &tctl.ResourceCommand{},
			cleanup:    tc.resourceDelete,
		})
	})

	t.Run("tctl create -f", func(t *testing.T) {
		s.testCommand(t, ctx, adminActionTestCase{
			command:    fmt.Sprintf("create -f %v", f.Name()),
			cliCommand: &tctl.ResourceCommand{},
			setup:      tc.resourceCreate,
			cleanup:    tc.resourceDelete,
		})
	})

	t.Run("tctl rm", func(t *testing.T) {
		s.testCommand(t, ctx, adminActionTestCase{
			command:    fmt.Sprintf("rm %v", getResourceRef(tc.resource)),
			cliCommand: &tctl.ResourceCommand{},
			setup:      tc.resourceCreate,
			cleanup:    tc.resourceDelete,
		})
	})
}

type editCommandTestCase struct {
	resourceRef    string
	resourceCreate func() error
	resourceGet    func() (types.Resource, error)
	resourceDelete func() error
}

func (s *adminActionTestSuite) testEditCommand(t *testing.T, ctx context.Context, tc editCommandTestCase) {
	t.Run("tctl edit", func(t *testing.T) {
		s.testCommand(t, ctx, adminActionTestCase{
			command: fmt.Sprintf("edit %v", tc.resourceRef),
			setup:   tc.resourceCreate,
			cliCommand: &tctl.EditCommand{
				Editor: func(filename string) error {
					// Get the latest version of the resource with the correct revision ID.
					resource, err := tc.resourceGet()
					require.NoError(t, err)

					// Update the expiry so that the edit goes through.
					resource.SetExpiry(time.Now())

					f, err := os.Create(filename)
					require.NoError(t, err)
					require.NoError(t, utils.WriteYAML(f, resource))
					return nil
				},
			},
			cleanup: tc.resourceDelete,
		})
	})
}

type adminActionTestSuite struct {
	authServer *auth.Server
	// userClientWithMFA supports MFA prompt for admin actions.
	userClientWithMFA auth.ClientI
	// userClientWithMFA does not support MFA prompt for admin actions.
	userClientNoMFA  auth.ClientI
	localAdminClient *auth.Client
}

func newAdminActionTestSuite(t *testing.T) *adminActionTestSuite {
	t.Helper()
	ctx := context.Background()
	modules.SetTestModules(t, &modules.TestModules{
		TestBuildType: modules.BuildEnterprise,
		TestFeatures: modules.Features{
			OIDC: true,
			SAML: true,
		},
	})

	authPref, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
		Type:         constants.Local,
		SecondFactor: constants.SecondFactorOptional,
		Webauthn: &types.Webauthn{
			RPID: "localhost",
		},
	})
	require.NoError(t, err)
	authPref.SetOrigin(types.OriginDefaults)

	var proxyPublicAddr utils.NetAddr
	process := testserver.MakeTestServer(t,
		testserver.WithAuthPreference(authPref),
		testserver.WithConfig(func(cfg *servicecfg.Config) {
			proxyPublicAddr = cfg.Proxy.WebAddr
			proxyPublicAddr.Addr = fmt.Sprintf("localhost:%v", proxyPublicAddr.Port(0))
			cfg.Proxy.PublicAddrs = []utils.NetAddr{proxyPublicAddr}
		}),
	)
	authAddr, err := process.AuthAddr()
	require.NoError(t, err)
	authServer := process.GetAuthServer()

	// create admin role and user.
	username := "admin"
	adminRole, err := types.NewRole(username, types.RoleSpecV6{
		Allow: types.RoleConditions{
			GroupLabels: types.Labels{types.Wildcard: apiutils.Strings{types.Wildcard}},
			Impersonate: &types.ImpersonateConditions{
				Users: []string{types.Wildcard},
				Roles: []string{types.Wildcard},
			},
			Rules: []types.Rule{
				{
					Resources: []string{types.Wildcard},
					Verbs:     []string{types.Wildcard},
				},
			},
			ReviewRequests: &types.AccessReviewConditions{
				Roles: []string{types.Wildcard},
			},
			Request: &types.AccessRequestConditions{
				Roles: []string{types.Wildcard},
			},
		},
	})
	require.NoError(t, err)
	adminRole, err = authServer.CreateRole(ctx, adminRole)
	require.NoError(t, err)

	user, err := types.NewUser(username)
	user.SetRoles([]string{adminRole.GetName()})
	require.NoError(t, err)
	_, err = authServer.CreateUser(ctx, user)
	require.NoError(t, err)

	mockWebauthnLogin := setupWebAuthn(t, authServer, username)
	mockMFAPromptConstructor := func(opts ...mfa.PromptOpt) mfa.Prompt {
		promptCfg := libmfa.NewPromptConfig(proxyPublicAddr.String(), opts...)
		promptCfg.WebauthnLoginFunc = mockWebauthnLogin
		return libmfa.NewCLIPrompt(promptCfg, os.Stderr)
	}

	// Login as the admin user.
	tshHome := t.TempDir()
	err = tsh.Run(context.Background(), []string{
		"login",
		"--insecure",
		"--debug",
		"--user", username,
		"--proxy", proxyPublicAddr.String(),
		"--auth", constants.PasswordlessConnector,
	},
		setHomePath(tshHome),
		setKubeConfigPath(filepath.Join(t.TempDir(), teleport.KubeConfigFile)),
		func(c *tsh.CLIConf) error {
			c.WebauthnLogin = mockWebauthnLogin
			return nil
		},
	)
	require.NoError(t, err)

	userClientNoMFA, err := auth.NewClient(client.Config{
		Addrs: []string{authAddr.String()},
		Credentials: []client.Credentials{
			client.LoadProfile(tshHome, ""),
		},
	})
	require.NoError(t, err)

	userClientWithMFA, err := auth.NewClient(client.Config{
		Addrs: []string{authAddr.String()},
		Credentials: []client.Credentials{
			client.LoadProfile(tshHome, ""),
		},
		MFAPromptConstructor: mockMFAPromptConstructor,
	})
	require.NoError(t, err)

	hostUUID, err := utils.ReadHostUUID(process.Config.DataDir)
	require.NoError(t, err)
	localAdmin, err := auth.ReadLocalIdentity(
		filepath.Join(process.Config.DataDir, teleport.ComponentProcess),
		auth.IdentityID{Role: types.RoleAdmin, HostUUID: hostUUID},
	)
	require.NoError(t, err)
	localAdminTLS, err := localAdmin.TLSConfig(nil)
	require.NoError(t, err)
	localAdminClient, err := authclient.Connect(ctx, &authclient.Config{
		TLS:         localAdminTLS,
		AuthServers: []utils.NetAddr{*authAddr},
		Log:         utils.NewLoggerForTests(),
	})
	require.NoError(t, err)

	return &adminActionTestSuite{
		authServer:        authServer,
		userClientNoMFA:   userClientNoMFA,
		userClientWithMFA: userClientWithMFA,
		localAdminClient:  localAdminClient,
	}
}

type adminActionTestCase struct {
	command    string
	cliCommand tctl.CLICommand
	setup      func() error
	cleanup    func() error
}

func (s *adminActionTestSuite) testCommand(t *testing.T, ctx context.Context, tc adminActionTestCase) {
	t.Helper()

	t.Run("OK with MFA", func(t *testing.T) {
		err := runTestCase(t, ctx, s.userClientWithMFA, tc)
		require.NoError(t, err)
	})

	t.Run("NOK without MFA", func(t *testing.T) {
		err := runTestCase(t, ctx, s.userClientNoMFA, tc)
		require.ErrorIs(t, err, &mfa.ErrAdminActionMFARequired)
	})

	t.Run("OK mfa off", func(t *testing.T) {
		// turn MFA off, admin actions should not require MFA now.
		authPref := types.DefaultAuthPreference()
		authPref.SetSecondFactor(constants.SecondFactorOff)
		originalAuthPref, err := s.authServer.GetAuthPreference(ctx)
		require.NoError(t, err)

		require.NoError(t, s.authServer.SetAuthPreference(ctx, authPref))
		t.Cleanup(func() {
			require.NoError(t, s.authServer.SetAuthPreference(ctx, originalAuthPref))
		})

		err = runTestCase(t, ctx, s.userClientNoMFA, tc)
		require.NoError(t, err)
	})
}

func runTestCase(t *testing.T, ctx context.Context, client auth.ClientI, tc adminActionTestCase) error {
	t.Helper()

	if tc.setup != nil {
		require.NoError(t, tc.setup(), "unexpected error during setup")
	}
	if tc.cleanup != nil {
		t.Cleanup(func() {
			if err := tc.cleanup(); err != nil && !trace.IsNotFound(err) {
				t.Errorf("unexpected error during cleanup: %v", err)
			}
		})
	}

	app := utils.InitCLIParser("tctl", tctl.GlobalHelpString)
	cfg := servicecfg.MakeDefaultConfig()
	tc.cliCommand.Initialize(app, cfg)

	args := strings.Split(tc.command, " ")
	commandName, err := app.Parse(args)
	require.NoError(t, err)

	match, err := tc.cliCommand.TryRun(ctx, commandName, client)
	require.True(t, match)
	return err
}

func getResourceRef(r types.Resource) string {
	switch kind := r.GetKind(); kind {
	case types.KindClusterAuthPreference:
		// single resources are referred to by kind alone.
		return kind
	default:
		return fmt.Sprintf("%v/%v", r.GetKind(), r.GetName())
	}
}

func setupWebAuthn(t *testing.T, authServer *auth.Server, username string) libclient.WebauthnLoginFunc {
	t.Helper()
	ctx := context.Background()

	const origin = "https://localhost"
	device, err := mocku2f.Create()
	require.NoError(t, err)
	device.SetPasswordless()

	token, err := authServer.CreateResetPasswordToken(ctx, auth.CreateUserTokenRequest{
		Name: username,
	})
	require.NoError(t, err)

	tokenID := token.GetName()
	res, err := authServer.CreateRegisterChallenge(ctx, &proto.CreateRegisterChallengeRequest{
		TokenID:     tokenID,
		DeviceType:  proto.DeviceType_DEVICE_TYPE_WEBAUTHN,
		DeviceUsage: proto.DeviceUsage_DEVICE_USAGE_PASSWORDLESS,
	})
	require.NoError(t, err)
	cc := wantypes.CredentialCreationFromProto(res.GetWebauthn())

	userWebID := res.GetWebauthn().PublicKey.User.Id

	ccr, err := device.SignCredentialCreation(origin, cc)
	require.NoError(t, err)
	_, err = authServer.ChangeUserAuthentication(ctx, &proto.ChangeUserAuthenticationRequest{
		TokenID: tokenID,
		NewMFARegisterResponse: &proto.MFARegisterResponse{
			Response: &proto.MFARegisterResponse_Webauthn{
				Webauthn: wantypes.CredentialCreationResponseToProto(ccr),
			},
		},
	})
	require.NoError(t, err)

	return func(ctx context.Context, origin string, assertion *wantypes.CredentialAssertion, prompt wancli.LoginPrompt, opts *wancli.LoginOpts) (*proto.MFAAuthenticateResponse, string, error) {
		car, err := device.SignAssertion(origin, assertion)
		if err != nil {
			return nil, "", err
		}
		car.AssertionResponse.UserHandle = userWebID

		return &proto.MFAAuthenticateResponse{
			Response: &proto.MFAAuthenticateResponse_Webauthn{
				Webauthn: wantypes.CredentialAssertionResponseToProto(car),
			},
		}, "", nil
	}
}

func setHomePath(path string) tsh.CliOption {
	return func(cf *tsh.CLIConf) error {
		cf.HomePath = path
		return nil
	}
}

func setKubeConfigPath(path string) tsh.CliOption {
	return func(cf *tsh.CLIConf) error {
		cf.KubeConfigPath = path
		return nil
	}
}
