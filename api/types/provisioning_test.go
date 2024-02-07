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

package types

import (
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/defaults"
)

func TestProvisionTokenV2_CheckAndSetDefaults(t *testing.T) {
	testcases := []struct {
		desc     string
		token    *ProvisionTokenV2
		expected *ProvisionTokenV2
		wantErr  bool
	}{
		{
			desc:    "empty",
			token:   &ProvisionTokenV2{},
			wantErr: true,
		},
		{
			desc: "missing roles",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
			},
			wantErr: true,
		},
		{
			desc: "invalid role",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles: []SystemRole{RoleNode, "not a role"},
				},
			},
			wantErr: true,
		},
		{
			desc: "simple token",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles: []SystemRole{RoleNode},
				},
			},
			expected: &ProvisionTokenV2{
				Kind:    "token",
				Version: "v2",
				Metadata: Metadata{
					Name:      "test",
					Namespace: "default",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: "token",
				},
			},
		},
		{
			desc: "implicit ec2 method",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles: []SystemRole{RoleNode},
					Allow: []*TokenRule{
						{
							AWSAccount: "1234",
							AWSRole:    "1234/role",
							AWSRegions: []string{"us-west-2"},
						},
					},
				},
			},
			expected: &ProvisionTokenV2{
				Kind:    "token",
				Version: "v2",
				Metadata: Metadata{
					Name:      "test",
					Namespace: "default",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: "ec2",
					Allow: []*TokenRule{
						{
							AWSAccount: "1234",
							AWSRole:    "1234/role",
							AWSRegions: []string{"us-west-2"},
						},
					},
					AWSIIDTTL: Duration(5 * time.Minute),
				},
			},
		},
		{
			desc: "explicit ec2 method",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: "ec2",
					Allow:      []*TokenRule{{AWSAccount: "1234"}},
				},
			},
			expected: &ProvisionTokenV2{
				Kind:    "token",
				Version: "v2",
				Metadata: Metadata{
					Name:      "test",
					Namespace: "default",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: "ec2",
					Allow:      []*TokenRule{{AWSAccount: "1234"}},
					AWSIIDTTL:  Duration(5 * time.Minute),
				},
			},
		},
		{
			desc: "ec2 method no allow rules",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: "ec2",
				},
			},
			wantErr: true,
		},
		{
			desc: "ec2 method with aws_arn",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: "ec2",
					Allow: []*TokenRule{
						{
							AWSAccount: "1234",
							AWSARN:     "1234",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "ec2 method empty rule",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: "ec2",
					Allow:      []*TokenRule{{}},
				},
			},
			wantErr: true,
		},
		{
			desc: "iam method",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: "ec2",
					Allow:      []*TokenRule{{AWSAccount: "1234"}},
				},
			},
			expected: &ProvisionTokenV2{
				Kind:    "token",
				Version: "v2",
				Metadata: Metadata{
					Name:      "test",
					Namespace: "default",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: "ec2",
					Allow:      []*TokenRule{{AWSAccount: "1234"}},
					AWSIIDTTL:  Duration(5 * time.Minute),
				},
			},
		},
		{
			desc: "iam method with aws_role",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: "iam",
					Allow: []*TokenRule{
						{
							AWSAccount: "1234",
							AWSRole:    "1234/role",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "iam method with aws_regions",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: "iam",
					Allow: []*TokenRule{
						{
							AWSAccount: "1234",
							AWSRegions: []string{"us-west-2"},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "github valid",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodGitHub,
					GitHub: &ProvisionTokenSpecV2GitHub{
						Allow: []*ProvisionTokenSpecV2GitHub_Rule{
							{
								Sub: "foo",
							},
						},
					},
				},
			},
		},
		{
			desc: "github ghes valid",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodGitHub,
					GitHub: &ProvisionTokenSpecV2GitHub{
						EnterpriseServerHost: "example.com",
						Allow: []*ProvisionTokenSpecV2GitHub_Rule{
							{
								Sub: "foo",
							},
						},
					},
				},
			},
		},
		{
			desc: "github ghes invalid",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodGitHub,
					GitHub: &ProvisionTokenSpecV2GitHub{
						EnterpriseServerHost: "https://example.com",
						Allow: []*ProvisionTokenSpecV2GitHub_Rule{
							{
								Sub: "foo",
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "circleci valid",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodCircleCI,
					CircleCI: &ProvisionTokenSpecV2CircleCI{
						OrganizationID: "foo",
						Allow: []*ProvisionTokenSpecV2CircleCI_Rule{
							{
								ProjectID: "foo",
								ContextID: "bar",
							},
						},
					},
				},
			},
		},
		{
			desc: "circleci and no allow",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodCircleCI,
					CircleCI: &ProvisionTokenSpecV2CircleCI{
						OrganizationID: "foo",
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "circleci and no org id",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodCircleCI,
					CircleCI: &ProvisionTokenSpecV2CircleCI{
						Allow: []*ProvisionTokenSpecV2CircleCI_Rule{
							{
								ProjectID: "foo",
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "circleci allow rule blank",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodCircleCI,
					CircleCI: &ProvisionTokenSpecV2CircleCI{
						Allow: []*ProvisionTokenSpecV2CircleCI_Rule{
							{},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "kubernetes: in_cluster defaults",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodKubernetes,
					Kubernetes: &ProvisionTokenSpecV2Kubernetes{
						Allow: []*ProvisionTokenSpecV2Kubernetes_Rule{
							{
								ServiceAccount: "namespace:my-service-account",
							},
						},
					},
				},
			},
			expected: &ProvisionTokenV2{
				Kind:    "token",
				Version: "v2",
				Metadata: Metadata{
					Name:      "test",
					Namespace: "default",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodKubernetes,
					Kubernetes: &ProvisionTokenSpecV2Kubernetes{
						Type: KubernetesJoinTypeInCluster,
						Allow: []*ProvisionTokenSpecV2Kubernetes_Rule{
							{
								ServiceAccount: "namespace:my-service-account",
							},
						},
					},
				},
			},
		},
		{
			desc: "kubernetes: valid in_cluster",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodKubernetes,
					Kubernetes: &ProvisionTokenSpecV2Kubernetes{
						Type: KubernetesJoinTypeInCluster,
						Allow: []*ProvisionTokenSpecV2Kubernetes_Rule{
							{
								ServiceAccount: "namespace:my-service-account",
							},
						},
					},
				},
			},
		},
		{
			desc: "kubernetes: valid static_jwks",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodKubernetes,
					Kubernetes: &ProvisionTokenSpecV2Kubernetes{
						Type: KubernetesJoinTypeStaticJWKS,
						Allow: []*ProvisionTokenSpecV2Kubernetes_Rule{
							{
								ServiceAccount: "namespace:my-service-account",
							},
						},
						StaticJWKS: &ProvisionTokenSpecV2Kubernetes_StaticJWKSConfig{
							JWKS: `{"keys":[{"use":"sig","kty":"RSA","kid":"-snip-","alg":"RS256","n":"-snip-","e":"-snip-"}]}`,
						},
					},
				},
			},
		},
		{
			desc: "kubernetes: missing static_jwks",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodKubernetes,
					Kubernetes: &ProvisionTokenSpecV2Kubernetes{
						Type: KubernetesJoinTypeStaticJWKS,
						Allow: []*ProvisionTokenSpecV2Kubernetes_Rule{
							{
								ServiceAccount: "namespace:my-service-account",
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "kubernetes: missing static_jwks.jwks",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodKubernetes,
					Kubernetes: &ProvisionTokenSpecV2Kubernetes{
						Type: KubernetesJoinTypeStaticJWKS,
						Allow: []*ProvisionTokenSpecV2Kubernetes_Rule{
							{
								ServiceAccount: "namespace:my-service-account",
							},
						},
						StaticJWKS: &ProvisionTokenSpecV2Kubernetes_StaticJWKSConfig{},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "kubernetes: wrong service account name",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodKubernetes,
					Kubernetes: &ProvisionTokenSpecV2Kubernetes{
						Allow: []*ProvisionTokenSpecV2Kubernetes_Rule{
							{
								ServiceAccount: "my-service-account",
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "kubernetes: allow rule blank",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodKubernetes,
					Kubernetes: &ProvisionTokenSpecV2Kubernetes{
						Allow: []*ProvisionTokenSpecV2Kubernetes_Rule{
							{},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "gitlab empty allow rules",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodGitLab,
					GitLab: &ProvisionTokenSpecV2GitLab{
						Allow: []*ProvisionTokenSpecV2GitLab_Rule{},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "gitlab missing config",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodGitLab,
					GitLab:     nil,
				},
			},
			wantErr: true,
		},
		{
			desc: "gitlab empty allow rule",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodGitLab,
					GitLab: &ProvisionTokenSpecV2GitLab{
						Allow: []*ProvisionTokenSpecV2GitLab_Rule{
							{},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "gitlab defaults",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodGitLab,
					GitLab: &ProvisionTokenSpecV2GitLab{
						Allow: []*ProvisionTokenSpecV2GitLab_Rule{
							{
								Sub: "asub",
							},
						},
					},
				},
			},
			expected: &ProvisionTokenV2{
				Kind:    KindToken,
				Version: V2,
				Metadata: Metadata{
					Name:      "test",
					Namespace: defaults.Namespace,
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodGitLab,
					GitLab: &ProvisionTokenSpecV2GitLab{
						Allow: []*ProvisionTokenSpecV2GitLab_Rule{
							{
								Sub: "asub",
							},
						},
						Domain: defaultGitLabDomain,
					},
				},
			},
		},
		{
			desc: "overridden domain",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodGitLab,
					GitLab: &ProvisionTokenSpecV2GitLab{
						Allow: []*ProvisionTokenSpecV2GitLab_Rule{
							{
								Sub: "asub",
							},
						},
						Domain: "gitlab.example.com",
					},
				},
			},
			expected: &ProvisionTokenV2{
				Kind:    KindToken,
				Version: V2,
				Metadata: Metadata{
					Name:      "test",
					Namespace: defaults.Namespace,
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodGitLab,
					GitLab: &ProvisionTokenSpecV2GitLab{
						Allow: []*ProvisionTokenSpecV2GitLab_Rule{
							{
								Sub: "asub",
							},
						},
						Domain: "gitlab.example.com",
					},
				},
			},
		},
		{
			desc: "invalid overridden domain",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodGitLab,
					GitLab: &ProvisionTokenSpecV2GitLab{
						Allow: []*ProvisionTokenSpecV2GitLab_Rule{
							{
								Sub: "asub",
							},
						},
						Domain: "http://gitlab.example.com",
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "spacelift",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodSpacelift,
					Spacelift: &ProvisionTokenSpecV2Spacelift{
						Hostname: "example.app.spacelift.io",
						Allow: []*ProvisionTokenSpecV2Spacelift_Rule{
							{
								SpaceID: "foo",
							},
						},
					},
				},
			},
			expected: &ProvisionTokenV2{
				Kind:    "token",
				Version: "v2",
				Metadata: Metadata{
					Name:      "test",
					Namespace: "default",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodSpacelift,
					Spacelift: &ProvisionTokenSpecV2Spacelift{
						Hostname: "example.app.spacelift.io",
						Allow: []*ProvisionTokenSpecV2Spacelift_Rule{
							{
								SpaceID: "foo",
							},
						},
					},
				},
			},
		},
		{
			desc: "spacelift empty allow rules",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodSpacelift,
					Spacelift: &ProvisionTokenSpecV2Spacelift{
						Hostname: "example.app.spacelift.io",
						Allow:    []*ProvisionTokenSpecV2Spacelift_Rule{},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "spacelift rule missing fields",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodSpacelift,
					Spacelift: &ProvisionTokenSpecV2Spacelift{
						Hostname: "example.app.spacelift.io",
						Allow:    []*ProvisionTokenSpecV2Spacelift_Rule{{}},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "spacelift missing hostname",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodSpacelift,
					Spacelift: &ProvisionTokenSpecV2Spacelift{
						Allow: []*ProvisionTokenSpecV2Spacelift_Rule{
							{
								SpaceID: "foo",
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "spacelift incorrect hostname",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: JoinMethodSpacelift,
					Spacelift: &ProvisionTokenSpecV2Spacelift{
						Hostname: "https://example.app.spacelift.io",
						Allow: []*ProvisionTokenSpecV2Spacelift_Rule{
							{
								SpaceID: "foo",
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "gcp method",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: "gcp",
					GCP: &ProvisionTokenSpecV2GCP{
						Allow: []*ProvisionTokenSpecV2GCP_Rule{
							{
								ProjectIDs: []string{"p1"},
								Locations:  []string{"us-west1-b"},
							},
						},
					},
				},
			},
			expected: &ProvisionTokenV2{
				Kind:    "token",
				Version: "v2",
				Metadata: Metadata{
					Name:      "test",
					Namespace: "default",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: "gcp",
					GCP: &ProvisionTokenSpecV2GCP{
						Allow: []*ProvisionTokenSpecV2GCP_Rule{
							{
								ProjectIDs: []string{"p1"},
								Locations:  []string{"us-west1-b"},
							},
						},
					},
				},
			},
		},
		{
			desc: "gcp method no project ids",
			token: &ProvisionTokenV2{
				Metadata: Metadata{
					Name: "test",
				},
				Spec: ProvisionTokenSpecV2{
					Roles:      []SystemRole{RoleNode},
					JoinMethod: "gcp",
					GCP: &ProvisionTokenSpecV2GCP{
						Allow: []*ProvisionTokenSpecV2GCP_Rule{
							{
								Locations: []string{"us-west1-b"},
							},
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			err := tc.token.CheckAndSetDefaults()
			if tc.wantErr {
				require.Error(t, err)
				require.True(t,
					trace.IsBadParameter(err),
					"want BadParameter, got %v (%T)", err, trace.Unwrap(err))
				return
			}
			require.NoError(t, err)

			if tc.expected != nil {
				require.Equal(t, tc.expected, tc.token)
			}
		})
	}
}

func TestProvisionTokenV2_GetSafeName(t *testing.T) {
	t.Run("token join method (short)", func(t *testing.T) {
		tok, err := NewProvisionToken("1234", []SystemRole{RoleNode}, time.Now())
		require.NoError(t, err)
		got := tok.GetSafeName()
		require.Equal(t, "****", got)
	})
	t.Run("token join method (long)", func(t *testing.T) {
		tok, err := NewProvisionToken("0123456789abcdef", []SystemRole{RoleNode}, time.Now())
		require.NoError(t, err)
		got := tok.GetSafeName()
		require.Equal(t, "************cdef", got)
	})
	t.Run("non-token join method", func(t *testing.T) {
		tok, err := NewProvisionTokenFromSpec("12345678", time.Now(), ProvisionTokenSpecV2{
			Roles:      []SystemRole{RoleNode},
			JoinMethod: JoinMethodKubernetes,
			Kubernetes: &ProvisionTokenSpecV2Kubernetes{
				Allow: []*ProvisionTokenSpecV2Kubernetes_Rule{
					{
						ServiceAccount: "namespace:my-service-account",
					},
				},
			},
		})
		require.NoError(t, err)
		got := tok.GetSafeName()
		require.Equal(t, "12345678", got)
	})
}
