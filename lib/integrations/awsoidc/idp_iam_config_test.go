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

package awsoidc

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/lib"
)

func TestIdPIAMConfigReqDefaults(t *testing.T) {
	base64EncodedString := base64.StdEncoding.EncodeToString([]byte(`jwks`))

	baseIdPIAMConfigReqWithS3Bucket := func() IdPIAMConfigureRequest {
		return IdPIAMConfigureRequest{
			Cluster:           "mycluster",
			IntegrationName:   "myintegration",
			IntegrationRole:   "integrationrole",
			S3BucketLocation:  "s3://bucket-1/prefix-2",
			S3JWKSContentsB64: base64EncodedString,
		}
	}

	baseIdPIAMConfigReqWithProxy := func() IdPIAMConfigureRequest {
		return IdPIAMConfigureRequest{
			Cluster:            "mycluster",
			IntegrationName:    "myintegration",
			IntegrationRole:    "integrationrole",
			ProxyPublicAddress: "https://proxy.example.com",
		}
	}

	for _, tt := range []struct {
		name     string
		req      func() IdPIAMConfigureRequest
		errCheck require.ErrorAssertionFunc
		expected IdPIAMConfigureRequest
	}{
		{
			name:     "proxy mode: set defaults",
			req:      baseIdPIAMConfigReqWithProxy,
			errCheck: require.NoError,
			expected: IdPIAMConfigureRequest{
				Cluster:            "mycluster",
				IntegrationName:    "myintegration",
				IntegrationRole:    "integrationrole",
				ProxyPublicAddress: "https://proxy.example.com",
				issuer:             "proxy.example.com",
				issuerURL:          "https://proxy.example.com",
				ownershipTags: AWSTags{
					"teleport.dev/cluster":     "mycluster",
					"teleport.dev/integration": "myintegration",
					"teleport.dev/origin":      "integration_awsoidc",
				},
			},
		},
		{
			name: "proxy mode: missing proxy public address",
			req: func() IdPIAMConfigureRequest {
				req := baseIdPIAMConfigReqWithProxy()
				req.ProxyPublicAddress = ""
				return req
			},
			errCheck: badParameterCheck,
		},
		{
			name:     "s3 bucket mode: set defaults",
			req:      baseIdPIAMConfigReqWithS3Bucket,
			errCheck: require.NoError,
			expected: IdPIAMConfigureRequest{
				Cluster:           "mycluster",
				IntegrationName:   "myintegration",
				IntegrationRole:   "integrationrole",
				S3BucketLocation:  "s3://bucket-1/prefix-2",
				s3Bucket:          "bucket-1",
				s3BucketPrefix:    "prefix-2",
				jwksFileContents:  []byte(`jwks`),
				S3JWKSContentsB64: base64EncodedString,
				issuer:            "bucket-1.s3.amazonaws.com/prefix-2",
				issuerURL:         "https://bucket-1.s3.amazonaws.com/prefix-2",
				ownershipTags: AWSTags{
					"teleport.dev/cluster":     "mycluster",
					"teleport.dev/integration": "myintegration",
					"teleport.dev/origin":      "integration_awsoidc",
				},
			},
		},
		{
			name: "s3 bucket mode: missing jwks content",
			req: func() IdPIAMConfigureRequest {
				req := baseIdPIAMConfigReqWithS3Bucket()
				req.S3JWKSContentsB64 = ""
				return req
			},
			errCheck: badParameterCheck,
		},
		{
			name: "s3 bucket mode: invalid jwks content",
			req: func() IdPIAMConfigureRequest {
				req := baseIdPIAMConfigReqWithS3Bucket()
				req.S3JWKSContentsB64 = "x"
				return req
			},
			errCheck: badParameterCheck,
		},
		{
			name: "s3 bucket mode: invalid url for s3 location",
			req: func() IdPIAMConfigureRequest {
				req := baseIdPIAMConfigReqWithS3Bucket()
				req.S3BucketLocation = "invalid-url"
				return req
			},
			errCheck: badParameterCheck,
		},
		{
			name: "s3 bucket mode: invalid schema for s3 location",
			req: func() IdPIAMConfigureRequest {
				req := baseIdPIAMConfigReqWithS3Bucket()
				req.S3BucketLocation = "https://proxy.example.com"
				return req
			},
			errCheck: badParameterCheck,
		},
		{
			name: "proxy and s3 bucket defined",
			req: func() IdPIAMConfigureRequest {
				req := baseIdPIAMConfigReqWithProxy()
				req.S3BucketLocation = "s3://bucket/prefix"
				return req
			},
			errCheck: badParameterCheck,
		},
		{
			name: "missing cluster",
			req: func() IdPIAMConfigureRequest {
				req := baseIdPIAMConfigReqWithProxy()
				req.Cluster = ""
				return req
			},
			errCheck: badParameterCheck,
		},
		{
			name: "missing integration name",
			req: func() IdPIAMConfigureRequest {
				req := baseIdPIAMConfigReqWithProxy()
				req.IntegrationName = ""
				return req
			},
			errCheck: badParameterCheck,
		},
		{
			name: "missing integration role",
			req: func() IdPIAMConfigureRequest {
				req := baseIdPIAMConfigReqWithProxy()
				req.IntegrationRole = ""
				return req
			},
			errCheck: badParameterCheck,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.req()
			err := req.CheckAndSetDefaults()
			tt.errCheck(t, err)
			if err != nil {
				return
			}

			require.Equal(t, tt.expected, req)
		})
	}
}

func policyDocWithStatementsJSON(statement ...string) *string {
	statements := strings.Join(statement, ",")
	ret := fmt.Sprintf(`{
        "Version": "2012-10-17",
        "Statement": [
            %s
        ]
    }`, statements)
	return &ret
}

func assumeRoleStatementJSON(issuer string) string {
	return fmt.Sprintf(`{
    "Effect": "Allow",
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/%s"
    },
    "Condition": {
        "StringEquals": {
            "%s:aud": "discover.teleport"
        }
    }
}`, issuer, issuer)
}

func policyStatementS3PublicAccessJSON(bucket, prefix string) string {
	return fmt.Sprintf(`{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::%s/%s/*"
}`, bucket, prefix)
}

func TestConfigureIdPIAMUsingProxyURL(t *testing.T) {
	ctx := context.Background()

	t.Run("using proxy url", func(t *testing.T) {
		tlsServer := httptest.NewTLSServer(nil)
		tlsServerURL, err := url.Parse(tlsServer.URL)
		require.NoError(t, err)

		tlsServerIssuer := tlsServerURL.Host
		// TLS Server starts with self-signed certificates.

		lib.SetInsecureDevMode(true)
		defer lib.SetInsecureDevMode(false)

		baseIdPIAMConfigReqWithTLServer := func() IdPIAMConfigureRequest {
			return IdPIAMConfigureRequest{
				Cluster:            "mycluster",
				IntegrationName:    "myintegration",
				IntegrationRole:    "integrationrole",
				ProxyPublicAddress: tlsServer.URL,
			}
		}

		for _, tt := range []struct {
			name               string
			mockAccountID      string
			mockExistingRoles  map[string]mockRole
			mockExistingIdPUrl []string
			req                func() IdPIAMConfigureRequest
			errCheck           require.ErrorAssertionFunc
			externalStateCheck func(*testing.T, mockIdPIAMConfigClient)
		}{
			{
				name:               "valid",
				mockAccountID:      "123456789012",
				req:                baseIdPIAMConfigReqWithTLServer,
				mockExistingIdPUrl: []string{},
				mockExistingRoles:  map[string]mockRole{},
				errCheck:           require.NoError,
			},
			{
				name:               "idp url already exists",
				mockAccountID:      "123456789012",
				mockExistingIdPUrl: []string{tlsServer.URL},
				mockExistingRoles:  map[string]mockRole{},
				req:                baseIdPIAMConfigReqWithTLServer,
				errCheck:           require.NoError,
			},
			{
				name:               "role exists, no ownership tags",
				mockAccountID:      "123456789012",
				mockExistingIdPUrl: []string{},
				mockExistingRoles:  map[string]mockRole{"integrationrole": {}},
				req:                baseIdPIAMConfigReqWithTLServer,
				errCheck:           badParameterCheck,
			},
			{
				name:               "role exists, ownership tags, no assume role",
				mockAccountID:      "123456789012",
				mockExistingIdPUrl: []string{},
				mockExistingRoles: map[string]mockRole{"integrationrole": {
					tags: []iamTypes.Tag{
						{Key: aws.String("teleport.dev/origin"), Value: aws.String("integration_awsoidc")},
						{Key: aws.String("teleport.dev/cluster"), Value: aws.String("mycluster")},
						{Key: aws.String("teleport.dev/integration"), Value: aws.String("myintegration")},
					},
					assumeRolePolicyDoc: aws.String(`{"Version":"2012-10-17", "Statements":[]}`),
				}},
				req:      baseIdPIAMConfigReqWithTLServer,
				errCheck: require.NoError,
				externalStateCheck: func(t *testing.T, mipc mockIdPIAMConfigClient) {
					role := mipc.existingRoles["integrationrole"]
					expectedAssumeRolePolicyDoc := policyDocWithStatementsJSON(
						assumeRoleStatementJSON(tlsServerIssuer),
					)
					require.JSONEq(t, *expectedAssumeRolePolicyDoc, aws.ToString(role.assumeRolePolicyDoc))
				},
			},
			{
				name:               "role exists, ownership tags, with existing assume role",
				mockAccountID:      "123456789012",
				mockExistingIdPUrl: []string{},
				mockExistingRoles: map[string]mockRole{"integrationrole": {
					tags: []iamTypes.Tag{
						{Key: aws.String("teleport.dev/origin"), Value: aws.String("integration_awsoidc")},
						{Key: aws.String("teleport.dev/cluster"), Value: aws.String("mycluster")},
						{Key: aws.String("teleport.dev/integration"), Value: aws.String("myintegration")},
					},
					assumeRolePolicyDoc: policyDocWithStatementsJSON(
						assumeRoleStatementJSON("some-other-issuer"),
					),
				}},
				req:      baseIdPIAMConfigReqWithTLServer,
				errCheck: require.NoError,
				externalStateCheck: func(t *testing.T, mipc mockIdPIAMConfigClient) {
					role := mipc.existingRoles["integrationrole"]
					expectedAssumeRolePolicyDoc := policyDocWithStatementsJSON(
						assumeRoleStatementJSON("some-other-issuer"),
						assumeRoleStatementJSON(tlsServerIssuer),
					)
					require.JSONEq(t, *expectedAssumeRolePolicyDoc, aws.ToString(role.assumeRolePolicyDoc))
				},
			},
			{
				name:               "role exists, ownership tags, assume role already exists",
				mockAccountID:      "123456789012",
				mockExistingIdPUrl: []string{},
				mockExistingRoles: map[string]mockRole{"integrationrole": {
					tags: []iamTypes.Tag{
						{Key: aws.String("teleport.dev/origin"), Value: aws.String("integration_awsoidc")},
						{Key: aws.String("teleport.dev/cluster"), Value: aws.String("mycluster")},
						{Key: aws.String("teleport.dev/integration"), Value: aws.String("myintegration")},
					},
					assumeRolePolicyDoc: policyDocWithStatementsJSON(
						assumeRoleStatementJSON(tlsServerIssuer),
					),
				}},
				req:      baseIdPIAMConfigReqWithTLServer,
				errCheck: require.NoError,
				externalStateCheck: func(t *testing.T, mipc mockIdPIAMConfigClient) {
					role := mipc.existingRoles["integrationrole"]
					expectedAssumeRolePolicyDoc := policyDocWithStatementsJSON(
						assumeRoleStatementJSON(tlsServerIssuer),
					)
					require.JSONEq(t, *expectedAssumeRolePolicyDoc, aws.ToString(role.assumeRolePolicyDoc))
				},
			},
		} {
			t.Run(tt.name, func(t *testing.T) {
				clt := mockIdPIAMConfigClient{
					accountID:      tt.mockAccountID,
					existingRoles:  tt.mockExistingRoles,
					existingIDPUrl: tt.mockExistingIdPUrl,
				}

				err := ConfigureIdPIAM(ctx, &clt, tt.req())
				tt.errCheck(t, err)

				if tt.externalStateCheck != nil {
					tt.externalStateCheck(t, clt)
				}
			})
		}
	})

	t.Run("using s3 bucket", func(t *testing.T) {
		base64EncodedString := base64.StdEncoding.EncodeToString([]byte(`jwks`))

		baseIdPIAMConfigReqWithS3Bucket := func() IdPIAMConfigureRequest {
			return IdPIAMConfigureRequest{
				Cluster:           "mycluster",
				IntegrationName:   "myintegration",
				IntegrationRole:   "integrationrole",
				S3BucketLocation:  "s3://bucket-1/prefix-2",
				S3JWKSContentsB64: base64EncodedString,
			}
		}
		expectedIssuer := "bucket-1.s3.amazonaws.com/prefix-2"
		expectedIssuerURL := "https://" + expectedIssuer

		for _, tt := range []struct {
			name                string
			mockAccountID       string
			mockExistingIdPUrl  []string
			mockExistingRoles   map[string]mockRole
			mockClientRegion    string
			mockExistingBuckets map[string]mockBucket
			req                 func() IdPIAMConfigureRequest
			errCheck            require.ErrorAssertionFunc
			externalStateCheck  func(*testing.T, mockIdPIAMConfigClient)
		}{
			{
				name:                "valid without any existing resources",
				mockAccountID:       "123456789012",
				req:                 baseIdPIAMConfigReqWithS3Bucket,
				mockExistingIdPUrl:  []string{},
				mockExistingRoles:   map[string]mockRole{},
				mockExistingBuckets: map[string]mockBucket{},
				mockClientRegion:    "my-region",
				errCheck:            require.NoError,
				externalStateCheck: func(t *testing.T, mipc mockIdPIAMConfigClient) {
					// Check IdP creation
					require.Contains(t, mipc.existingIDPUrl, expectedIssuerURL)

					// Check Role creation
					role := mipc.existingRoles["integrationrole"]
					expectedAssumeRolePolicyDoc := policyDocWithStatementsJSON(
						assumeRoleStatementJSON(expectedIssuer),
					)
					require.JSONEq(t, *expectedAssumeRolePolicyDoc, aws.ToString(role.assumeRolePolicyDoc))

					// Check Bucket creation
					require.Contains(t, mipc.existingBuckets, "bucket-1")
					bucket := mipc.existingBuckets["bucket-1"]
					require.Equal(t, "my-region", bucket.region)
					require.False(t, bucket.publicAccessIsBlocked)
					expectedBucketPolicyDoc := policyDocWithStatementsJSON(
						policyStatementS3PublicAccessJSON("bucket-1", "prefix-2"),
					)
					require.JSONEq(t, *expectedBucketPolicyDoc, *bucket.policyDoc)

				},
			},
			{
				name:               "valid with an existing IdP set up using Proxy URL",
				mockAccountID:      "123456789012",
				req:                baseIdPIAMConfigReqWithS3Bucket,
				mockExistingIdPUrl: []string{"https://proxy.example.com"},
				mockExistingRoles: map[string]mockRole{
					"integrationrole": {
						tags: []iamTypes.Tag{
							{Key: aws.String("teleport.dev/origin"), Value: aws.String("integration_awsoidc")},
							{Key: aws.String("teleport.dev/cluster"), Value: aws.String("mycluster")},
							{Key: aws.String("teleport.dev/integration"), Value: aws.String("myintegration")},
						},
						assumeRolePolicyDoc: policyDocWithStatementsJSON(
							assumeRoleStatementJSON("proxy.example.com"),
						),
					},
				},
				mockExistingBuckets: map[string]mockBucket{},
				mockClientRegion:    "my-region",
				errCheck:            require.NoError,
				externalStateCheck: func(t *testing.T, mipc mockIdPIAMConfigClient) {
					// IdP should be created and the existing one must not be deleted.
					require.Contains(t, mipc.existingIDPUrl, expectedIssuerURL)
					require.Contains(t, mipc.existingIDPUrl, "https://proxy.example.com")

					// The role must include the new statement and must not delete the previous one
					role := mipc.existingRoles["integrationrole"]
					expectedAssumeRolePolicyDoc := policyDocWithStatementsJSON(
						assumeRoleStatementJSON("proxy.example.com"),
						assumeRoleStatementJSON(expectedIssuer),
					)
					require.JSONEq(t, *expectedAssumeRolePolicyDoc, aws.ToString(role.assumeRolePolicyDoc))

					// Check Bucket creation
					require.Contains(t, mipc.existingBuckets, "bucket-1")
					bucket := mipc.existingBuckets["bucket-1"]
					require.Equal(t, "my-region", bucket.region)
					require.False(t, bucket.publicAccessIsBlocked)
					expectedBucketPolicyDoc := policyDocWithStatementsJSON(
						policyStatementS3PublicAccessJSON("bucket-1", "prefix-2"),
					)
					require.JSONEq(t, *expectedBucketPolicyDoc, *bucket.policyDoc)
				},
			},
			{
				name:               "bucket already exists but is on another region",
				mockAccountID:      "123456789012",
				req:                baseIdPIAMConfigReqWithS3Bucket,
				mockExistingIdPUrl: []string{},
				mockExistingRoles:  map[string]mockRole{},
				mockExistingBuckets: map[string]mockBucket{
					"bucket-1": {
						region:                "another-region",
						publicAccessIsBlocked: true,
					},
				},
				mockClientRegion: "my-region",
				errCheck:         require.NoError,
				externalStateCheck: func(t *testing.T, mipc mockIdPIAMConfigClient) {
					// Check IdP creation
					require.Contains(t, mipc.existingIDPUrl, expectedIssuerURL)

					// Check Role creation
					role := mipc.existingRoles["integrationrole"]
					expectedAssumeRolePolicyDoc := policyDocWithStatementsJSON(
						assumeRoleStatementJSON(expectedIssuer),
					)
					require.JSONEq(t, *expectedAssumeRolePolicyDoc, aws.ToString(role.assumeRolePolicyDoc))

					// Check Bucket creation
					require.Contains(t, mipc.existingBuckets, "bucket-1")
					bucket := mipc.existingBuckets["bucket-1"]
					require.False(t, bucket.publicAccessIsBlocked)
					expectedBucketPolicyDoc := policyDocWithStatementsJSON(
						policyStatementS3PublicAccessJSON("bucket-1", "prefix-2"),
					)
					require.JSONEq(t, *expectedBucketPolicyDoc, *bucket.policyDoc)

					// The last configured region must be the existing bucket's region.
					require.Equal(t, "another-region", mipc.clientRegion)
				},
			},
			{
				name:               "bucket already exists and already has a policy",
				mockAccountID:      "123456789012",
				req:                baseIdPIAMConfigReqWithS3Bucket,
				mockExistingIdPUrl: []string{},
				mockExistingRoles:  map[string]mockRole{},
				mockExistingBuckets: map[string]mockBucket{
					"bucket-1": {
						region:                "my-region",
						publicAccessIsBlocked: true,
						policyDoc: policyDocWithStatementsJSON(
							policyStatementS3PublicAccessJSON("bucket-2", "prefix-2"),
						),
					},
				},
				mockClientRegion: "my-region",
				errCheck:         require.NoError,
				externalStateCheck: func(t *testing.T, mipc mockIdPIAMConfigClient) {
					// Check IdP creation
					require.Contains(t, mipc.existingIDPUrl, expectedIssuerURL)

					// Check Role creation
					role := mipc.existingRoles["integrationrole"]
					expectedAssumeRolePolicyDoc := policyDocWithStatementsJSON(
						assumeRoleStatementJSON(expectedIssuer),
					)
					require.JSONEq(t, *expectedAssumeRolePolicyDoc, aws.ToString(role.assumeRolePolicyDoc))

					// Check Bucket creation
					require.Contains(t, mipc.existingBuckets, "bucket-1")
					bucket := mipc.existingBuckets["bucket-1"]
					require.False(t, bucket.publicAccessIsBlocked)
					expectedBucketPolicyDoc := policyDocWithStatementsJSON(
						policyStatementS3PublicAccessJSON("bucket-2", "prefix-2"),
						policyStatementS3PublicAccessJSON("bucket-1", "prefix-2"),
					)
					require.JSONEq(t, *expectedBucketPolicyDoc, *bucket.policyDoc)
				},
			},
			{
				name:               "everything already exists",
				mockAccountID:      "123456789012",
				req:                baseIdPIAMConfigReqWithS3Bucket,
				mockExistingIdPUrl: []string{"https://bucket-1.s3.amazonaws.com/prefix-2"},
				mockExistingRoles: map[string]mockRole{
					"integrationrole": {
						tags: []iamTypes.Tag{
							{Key: aws.String("teleport.dev/origin"), Value: aws.String("integration_awsoidc")},
							{Key: aws.String("teleport.dev/cluster"), Value: aws.String("mycluster")},
							{Key: aws.String("teleport.dev/integration"), Value: aws.String("myintegration")},
						},
						assumeRolePolicyDoc: policyDocWithStatementsJSON(
							assumeRoleStatementJSON("bucket-1.s3.amazonaws.com/prefix-2"),
						),
					},
				},
				mockExistingBuckets: map[string]mockBucket{
					"bucket-1": {
						region:                "my-region",
						publicAccessIsBlocked: true,
						policyDoc: policyDocWithStatementsJSON(
							policyStatementS3PublicAccessJSON("bucket-1", "prefix-2"),
						),
					},
				},
				mockClientRegion: "my-region",
				errCheck:         require.NoError,
				externalStateCheck: func(t *testing.T, mipc mockIdPIAMConfigClient) {
					// Check IdP exists
					require.Contains(t, mipc.existingIDPUrl, expectedIssuerURL)

					// Check Role exists
					role := mipc.existingRoles["integrationrole"]
					expectedAssumeRolePolicyDoc := policyDocWithStatementsJSON(
						assumeRoleStatementJSON(expectedIssuer),
					)
					require.JSONEq(t, *expectedAssumeRolePolicyDoc, aws.ToString(role.assumeRolePolicyDoc))

					// Check Bucket exists
					require.Contains(t, mipc.existingBuckets, "bucket-1")
					bucket := mipc.existingBuckets["bucket-1"]
					require.False(t, bucket.publicAccessIsBlocked)
					expectedBucketPolicyDoc := policyDocWithStatementsJSON(
						policyStatementS3PublicAccessJSON("bucket-1", "prefix-2"),
					)
					require.JSONEq(t, *expectedBucketPolicyDoc, *bucket.policyDoc)
				},
			},
		} {
			t.Run(tt.name, func(t *testing.T) {
				clt := mockIdPIAMConfigClient{
					accountID:       tt.mockAccountID,
					existingRoles:   tt.mockExistingRoles,
					existingIDPUrl:  tt.mockExistingIdPUrl,
					existingBuckets: tt.mockExistingBuckets,
					clientRegion:    tt.mockClientRegion,
				}

				err := ConfigureIdPIAM(ctx, &clt, tt.req())
				tt.errCheck(t, err)

				if tt.externalStateCheck != nil {
					tt.externalStateCheck(t, clt)
				}
			})
		}
	})
}

type mockBucket struct {
	region                string
	publicAccessIsBlocked bool
	policyDoc             *string
}

type mockRole struct {
	assumeRolePolicyDoc *string
	tags                []iamTypes.Tag
}
type mockIdPIAMConfigClient struct {
	clientRegion    string
	accountID       string
	existingIDPUrl  []string
	existingRoles   map[string]mockRole
	existingBuckets map[string]mockBucket
}

// GetCallerIdentity returns information about the caller identity.
func (m *mockIdPIAMConfigClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{
		Account: &m.accountID,
	}, nil
}

// CreateRole creates a new IAM Role.
func (m *mockIdPIAMConfigClient) CreateRole(ctx context.Context, params *iam.CreateRoleInput, optFns ...func(*iam.Options)) (*iam.CreateRoleOutput, error) {
	alreadyExistsMessage := fmt.Sprintf("Role %q already exists.", *params.RoleName)
	_, found := m.existingRoles[aws.ToString(params.RoleName)]
	if found {
		return nil, &iamTypes.EntityAlreadyExistsException{
			Message: &alreadyExistsMessage,
		}
	}
	m.existingRoles[*params.RoleName] = mockRole{
		tags:                params.Tags,
		assumeRolePolicyDoc: params.AssumeRolePolicyDocument,
	}

	return &iam.CreateRoleOutput{
		Role: &iamTypes.Role{
			Arn: aws.String("arn:something"),
		},
	}, nil
}

// CreateOpenIDConnectProvider creates an IAM OpenID Connect Provider.
func (m *mockIdPIAMConfigClient) CreateOpenIDConnectProvider(ctx context.Context, params *iam.CreateOpenIDConnectProviderInput, optFns ...func(*iam.Options)) (*iam.CreateOpenIDConnectProviderOutput, error) {
	alreadyExistsMessage := fmt.Sprintf("IdP with URL %q already exists.", *params.Url)
	if slices.Contains(m.existingIDPUrl, *params.Url) {
		return nil, &iamTypes.EntityAlreadyExistsException{
			Message: &alreadyExistsMessage,
		}
	}
	m.existingIDPUrl = append(m.existingIDPUrl, *params.Url)

	return &iam.CreateOpenIDConnectProviderOutput{}, nil
}

// GetRole retrieves information about the specified role, including the role's path,
// GUID, ARN, and the role's trust policy that grants permission to assume the
// role.
func (m *mockIdPIAMConfigClient) GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	role, found := m.existingRoles[aws.ToString(params.RoleName)]
	if !found {
		return nil, trace.NotFound("role not found")
	}
	return &iam.GetRoleOutput{
		Role: &iamTypes.Role{
			Tags:                     role.tags,
			AssumeRolePolicyDocument: role.assumeRolePolicyDoc,
		},
	}, nil
}

// UpdateAssumeRolePolicy updates the policy that grants an IAM entity permission to assume a role.
// This is typically referred to as the "role trust policy".
func (m *mockIdPIAMConfigClient) UpdateAssumeRolePolicy(ctx context.Context, params *iam.UpdateAssumeRolePolicyInput, optFns ...func(*iam.Options)) (*iam.UpdateAssumeRolePolicyOutput, error) {
	role, found := m.existingRoles[aws.ToString(params.RoleName)]
	if !found {
		return nil, trace.NotFound("role not found")
	}

	role.assumeRolePolicyDoc = params.PolicyDocument
	m.existingRoles[aws.ToString(params.RoleName)] = role

	return &iam.UpdateAssumeRolePolicyOutput{}, nil
}

// CreateBucket creates an Amazon S3 bucket.
func (m *mockIdPIAMConfigClient) CreateBucket(ctx context.Context, params *s3.CreateBucketInput, optFns ...func(*s3.Options)) (*s3.CreateBucketOutput, error) {
	m.existingBuckets[*params.Bucket] = mockBucket{
		publicAccessIsBlocked: true,
		region:                m.clientRegion,
	}
	return nil, nil
}

// PutObject adds an object to a bucket.
func (m *mockIdPIAMConfigClient) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return nil, nil
}

// HeadBucket adds an object to a bucket.
func (m *mockIdPIAMConfigClient) HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	bucket, found := m.existingBuckets[*params.Bucket]
	if !found {
		return nil, trace.NotFound("bucket does not exist")
	}

	return &s3.HeadBucketOutput{
		BucketRegion: &bucket.region,
	}, nil
}

// RegionForCreateBucket returns the default aws region to use when creating a bucket.
func (m *mockIdPIAMConfigClient) RegionForCreateBucket() string {
	return m.clientRegion
}

// SetAWSRegion sets the default aws region to use.
func (m *mockIdPIAMConfigClient) SetAWSRegion(awsRegion string) {
	m.clientRegion = awsRegion
}

// PutBucketPolicy applies an Amazon S3 bucket policy to an Amazon S3 bucket.
func (m *mockIdPIAMConfigClient) PutBucketPolicy(ctx context.Context, params *s3.PutBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.PutBucketPolicyOutput, error) {
	bucket, found := m.existingBuckets[*params.Bucket]
	if !found {
		return nil, trace.NotFound("bucket does not exist")
	}

	bucket.policyDoc = params.Policy
	m.existingBuckets[*params.Bucket] = bucket

	return &s3.PutBucketPolicyOutput{}, nil
}

// DeletePublicAccessBlock  removes the PublicAccessBlock configuration for an Amazon S3 bucket.
func (m *mockIdPIAMConfigClient) DeletePublicAccessBlock(ctx context.Context, params *s3.DeletePublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.DeletePublicAccessBlockOutput, error) {
	bucket, found := m.existingBuckets[*params.Bucket]
	if !found {
		return nil, trace.NotFound("bucket does not exist")
	}

	bucket.publicAccessIsBlocked = false
	m.existingBuckets[*params.Bucket] = bucket

	return &s3.DeletePublicAccessBlockOutput{}, nil
}

// GetBucketPolicy returns the policy of a specified bucket
func (m *mockIdPIAMConfigClient) GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	bucket, found := m.existingBuckets[*params.Bucket]
	if !found {
		return nil, trace.NotFound("bucket does not exist")
	}

	if bucket.policyDoc == nil {
		return nil, trace.NotFound("policy not set yet")
	}

	return &s3.GetBucketPolicyOutput{
		Policy: bucket.policyDoc,
	}, nil
}

// HTTPHead does an HEAD HTTP Request to the target URL.
func (m *mockIdPIAMConfigClient) HTTPHead(ctx context.Context, endpoint string) (*http.Response, error) {
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// check if bucket exists
	// expected URL is: https://s3.amazonaws.com/<bucket>/<prefix>
	endpointURLPath := strings.TrimLeft(endpointURL.Path, "/")
	bucketName := strings.Split(endpointURLPath, "/")[0]

	bucket, found := m.existingBuckets[bucketName]
	if !found {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       http.NoBody,
		}, nil
	}

	m.clientRegion = bucket.region

	return &http.Response{
		Header: http.Header{
			"x-amz-bucket-region": []string{bucket.region},
		},
		Body: http.NoBody,
	}, nil
}

func TestNewIdPIAMConfigureClient(t *testing.T) {
	t.Run("no aws_region env var, returns an error", func(t *testing.T) {
		_, err := NewIdPIAMConfigureClient(context.Background())
		require.ErrorContains(t, err, "please set the AWS_REGION environment variable")
	})

	t.Run("aws_region env var was set, success", func(t *testing.T) {
		t.Setenv("AWS_REGION", "some-region")
		idpClient, err := NewIdPIAMConfigureClient(context.Background())
		require.NoError(t, err)
		require.NotNil(t, idpClient)
	})
}
