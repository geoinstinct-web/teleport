package auth

import (
	"context"
	"errors"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/utils/githubactions"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

type mockIDTokenValidator struct {
	tokens map[string]githubactions.IDTokenClaims
}

var mockInvalidTokenErr = errors.New("invalid token")

func (m *mockIDTokenValidator) Validate(_ context.Context, token string) (*githubactions.IDTokenClaims, error) {
	claims, ok := m.tokens[token]
	if !ok {
		return nil, mockInvalidTokenErr
	}

	return &claims, nil
}

func TestAuth_RegisterUsingToken_GHA(t *testing.T) {
	validIDToken := "test.fake.jwt"
	idTokenValidator := &mockIDTokenValidator{
		tokens: map[string]githubactions.IDTokenClaims{
			validIDToken: {
				Sub:             "repo:octo-org/octo-repo:environment:prod",
				Repository:      "octo-org/octo-repo",
				RepositoryOwner: "octo-org",
				Workflow:        "example-workflow",
				Environment:     "prod",
				Actor:           "octocat",
				Ref:             "refs/heads/main",
				RefType:         "branch",
			},
		},
	}
	var withTokenValidator ServerOption = func(server *Server) error {
		server.ghaIDTokenValidator = idTokenValidator
		return nil
	}
	ctx := context.Background()
	p, err := newTestPack(ctx, t.TempDir(), withTokenValidator)
	require.NoError(t, err)
	auth := p.a

	sshPrivateKey, sshPublicKey, err := testauthority.New().GenerateKeyPair()
	require.NoError(t, err)

	tlsPublicKey, err := PrivateKeyToPublicKeyTLS(sshPrivateKey)
	require.NoError(t, err)

	allowRule := func(modifier func(*types.ProvisionTokenSpecV3GitHub_Rule)) *types.ProvisionTokenSpecV3GitHub_Rule {
		rule := &types.ProvisionTokenSpecV3GitHub_Rule{
			Sub:             "repo:octo-org/octo-repo:environment:prod",
			Repository:      "octo-org/octo-repo",
			RepositoryOwner: "octo-org",
			Workflow:        "example-workflow",
			Environment:     "prod",
			Actor:           "octocat",
			Ref:             "refs/heads/main",
			RefType:         "branch",
		}
		if modifier != nil {
			modifier(rule)
		}
		return rule
	}

	allowRulesNotMatched := assert.ErrorAssertionFunc(func(t assert.TestingT, err error, i ...interface{}) bool {
		messageMatch := assert.ErrorContains(t, err, "id token claims did not match any allow rules")
		typeMatch := assert.True(t, trace.IsAccessDenied(err))
		return messageMatch && typeMatch
	})
	tests := []struct {
		name           string
		request        *types.RegisterUsingTokenRequest
		tokenSpec      types.ProvisionTokenSpecV3
		errorAssertion assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			tokenSpec: types.ProvisionTokenSpecV3{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV3GitHub{
					Allow: []*types.ProvisionTokenSpecV3GitHub_Rule{
						allowRule(nil),
					},
				},
			},
			request: &types.RegisterUsingTokenRequest{
				HostID:  "host-id",
				Role:    types.RoleNode,
				IDToken: validIDToken,
			},
			errorAssertion: assert.NoError,
		},
		{
			name: "incorrect sub",
			tokenSpec: types.ProvisionTokenSpecV3{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV3GitHub{
					Allow: []*types.ProvisionTokenSpecV3GitHub_Rule{
						allowRule(func(rule *types.ProvisionTokenSpecV3GitHub_Rule) {
							rule.Sub = "not matching"
						}),
					},
				},
			},
			request: &types.RegisterUsingTokenRequest{
				HostID:  "host-id",
				Role:    types.RoleNode,
				IDToken: validIDToken,
			},
			errorAssertion: allowRulesNotMatched,
		},
		{
			name: "incorrect repository",
			tokenSpec: types.ProvisionTokenSpecV3{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV3GitHub{
					Allow: []*types.ProvisionTokenSpecV3GitHub_Rule{
						allowRule(func(rule *types.ProvisionTokenSpecV3GitHub_Rule) {
							rule.Repository = "not matching"
						}),
					},
				},
			},
			request: &types.RegisterUsingTokenRequest{
				HostID:  "host-id",
				Role:    types.RoleNode,
				IDToken: validIDToken,
			},
			errorAssertion: allowRulesNotMatched,
		},
		{
			name: "incorrect repository owner",
			tokenSpec: types.ProvisionTokenSpecV3{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV3GitHub{
					Allow: []*types.ProvisionTokenSpecV3GitHub_Rule{
						allowRule(func(rule *types.ProvisionTokenSpecV3GitHub_Rule) {
							rule.RepositoryOwner = "not matching"
						}),
					},
				},
			},
			request: &types.RegisterUsingTokenRequest{
				HostID:  "host-id",
				Role:    types.RoleNode,
				IDToken: validIDToken,
			},
			errorAssertion: allowRulesNotMatched,
		},
		{
			name: "incorrect workflow",
			tokenSpec: types.ProvisionTokenSpecV3{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV3GitHub{
					Allow: []*types.ProvisionTokenSpecV3GitHub_Rule{
						allowRule(func(rule *types.ProvisionTokenSpecV3GitHub_Rule) {
							rule.Workflow = "not matching"
						}),
					},
				},
			},
			request: &types.RegisterUsingTokenRequest{
				HostID:  "host-id",
				Role:    types.RoleNode,
				IDToken: validIDToken,
			},
			errorAssertion: allowRulesNotMatched,
		},
		{
			name: "incorrect environment",
			tokenSpec: types.ProvisionTokenSpecV3{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV3GitHub{
					Allow: []*types.ProvisionTokenSpecV3GitHub_Rule{
						allowRule(func(rule *types.ProvisionTokenSpecV3GitHub_Rule) {
							rule.Environment = "not matching"
						}),
					},
				},
			},
			request: &types.RegisterUsingTokenRequest{
				HostID:  "host-id",
				Role:    types.RoleNode,
				IDToken: validIDToken,
			},
			errorAssertion: allowRulesNotMatched,
		},
		{
			name: "incorrect actor",
			tokenSpec: types.ProvisionTokenSpecV3{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV3GitHub{
					Allow: []*types.ProvisionTokenSpecV3GitHub_Rule{
						allowRule(func(rule *types.ProvisionTokenSpecV3GitHub_Rule) {
							rule.Actor = "not matching"
						}),
					},
				},
			},
			request: &types.RegisterUsingTokenRequest{
				HostID:  "host-id",
				Role:    types.RoleNode,
				IDToken: validIDToken,
			},
			errorAssertion: allowRulesNotMatched,
		},
		{
			name: "incorrect ref",
			tokenSpec: types.ProvisionTokenSpecV3{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV3GitHub{
					Allow: []*types.ProvisionTokenSpecV3GitHub_Rule{
						allowRule(func(rule *types.ProvisionTokenSpecV3GitHub_Rule) {
							rule.Ref = "not matching"
						}),
					},
				},
			},
			request: &types.RegisterUsingTokenRequest{
				HostID:  "host-id",
				Role:    types.RoleNode,
				IDToken: validIDToken,
			},
			errorAssertion: allowRulesNotMatched,
		},
		{
			name: "incorrect ref type",
			tokenSpec: types.ProvisionTokenSpecV3{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV3GitHub{
					Allow: []*types.ProvisionTokenSpecV3GitHub_Rule{
						allowRule(func(rule *types.ProvisionTokenSpecV3GitHub_Rule) {
							rule.RefType = "not matching"
						}),
					},
				},
			},
			request: &types.RegisterUsingTokenRequest{
				HostID:  "host-id",
				Role:    types.RoleNode,
				IDToken: validIDToken,
			},
			errorAssertion: allowRulesNotMatched,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := types.NewProvisionTokenFromSpec(
				tt.name, time.Now().Add(time.Minute), tt.tokenSpec,
			)
			require.NoError(t, err)
			require.NoError(t, auth.CreateToken(ctx, token))

			// Set common request fields
			tt.request.Token = tt.name
			tt.request.PublicSSHKey = sshPublicKey
			tt.request.PublicTLSKey = tlsPublicKey

			_, err = auth.RegisterUsingToken(ctx, tt.request)
			tt.errorAssertion(t, err)
		})
	}
}
