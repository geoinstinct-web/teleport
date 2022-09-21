/*
Copyright 2021-2022 Gravitational, Inc.

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

package auth

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/trace"

	"github.com/coreos/go-semver/semver"
	"github.com/stretchr/testify/require"
)

func responseFromAWSIdentity(id awsIdentity) string {
	return fmt.Sprintf(`{
		"GetCallerIdentityResponse": {
			"GetCallerIdentityResult": {
				"Account": "%s",
				"Arn": "%s"
			}}}`, id.Account, id.Arn)
}

type mockClient struct {
	respStatusCode int
	respBody       string
}

func (c *mockClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: c.respStatusCode,
		Body:       io.NopCloser(strings.NewReader(c.respBody)),
	}, nil
}

var identityRequestTemplate = template.Must(template.New("sts-request").Parse(`POST / HTTP/1.1
Host: {{.Host}}
User-Agent: aws-sdk-go/1.37.17 (go1.17.1; darwin; amd64)
Content-Length: 43
Accept: application/json
Authorization: AWS4-HMAC-SHA256 Credential=AAAAAAAAAAAAAAAAAAAA/20211102/us-east-1/sts/aws4_request, SignedHeaders=accept;content-length;content-type;host;x-amz-date;x-amz-security-token;{{.SignedHeader}}, Signature=111
Content-Type: application/x-www-form-urlencoded; charset=utf-8
X-Amz-Date: 20211102T204300Z
X-Amz-Security-Token: aaa
X-Teleport-Challenge: {{.Challenge}}

Action=GetCallerIdentity&Version=2011-06-15`))

type identityRequestTemplateInput struct {
	Host         string
	SignedHeader string
	Challenge    string
}

func defaultIdentityRequestTemplateInput(challenge string) identityRequestTemplateInput {
	return identityRequestTemplateInput{
		Host:         "sts.amazonaws.com",
		SignedHeader: "x-teleport-challenge;",
		Challenge:    challenge,
	}
}

type challengeResponseOption func(*identityRequestTemplateInput)

func withHost(host string) challengeResponseOption {
	return func(templateInput *identityRequestTemplateInput) {
		templateInput.Host = host
	}
}

func withSignedHeader(signedHeader string) challengeResponseOption {
	return func(templateInput *identityRequestTemplateInput) {
		templateInput.SignedHeader = signedHeader
	}
}

func withChallenge(challenge string) challengeResponseOption {
	return func(templateInput *identityRequestTemplateInput) {
		templateInput.Challenge = challenge
	}
}

func TestAuth_RegisterUsingIAMMethod(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p, err := newTestPack(ctx, t.TempDir())
	require.NoError(t, err)
	a := p.a

	sshPrivateKey, sshPublicKey, err := native.GenerateKeyPair()
	require.NoError(t, err)

	tlsPublicKey, err := PrivateKeyToPublicKeyTLS(sshPrivateKey)
	require.NoError(t, err)

	isAccessDenied := func(t require.TestingT, err error, _ ...interface{}) {
		require.True(t, trace.IsAccessDenied(err), "expected Access Denied error, actual error: %v", err)
	}
	isBadParameter := func(t require.TestingT, err error, _ ...interface{}) {
		require.True(t, trace.IsBadParameter(err), "expected Bad Parameter error, actual error: %v", err)
	}

	testCases := []struct {
		desc                     string
		tokenName                string
		requestTokenName         string
		tokenSpec                types.ProvisionTokenSpecV2
		stsClient                stsClient
		iamRegisterOptions       []iamRegisterOption
		challengeResponseOptions []challengeResponseOption
		challengeResponseErr     error
		assertError              require.ErrorAssertionFunc
	}{
		{
			desc:             "basic passing case",
			tokenName:        "test-token",
			requestTokenName: "test-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Allow: []*types.TokenRule{
					{
						AWSAccount: "1234",
						AWSARN:     "arn:aws::1111",
					},
				},
				JoinMethod: types.JoinMethodIAM,
			},
			stsClient: &mockClient{
				respStatusCode: http.StatusOK,
				respBody: responseFromAWSIdentity(awsIdentity{
					Account: "1234",
					Arn:     "arn:aws::1111",
				}),
			},
			assertError: require.NoError,
		},
		{
			desc:             "wildcard arn 1",
			tokenName:        "test-token",
			requestTokenName: "test-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Allow: []*types.TokenRule{
					{
						AWSAccount: "1234",
						AWSARN:     "arn:aws::role/admins-*",
					},
				},
				JoinMethod: types.JoinMethodIAM,
			},
			stsClient: &mockClient{
				respStatusCode: http.StatusOK,
				respBody: responseFromAWSIdentity(awsIdentity{
					Account: "1234",
					Arn:     "arn:aws::role/admins-test",
				}),
			},
			assertError: require.NoError,
		},
		{
			desc:             "wildcard arn 2",
			tokenName:        "test-token",
			requestTokenName: "test-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Allow: []*types.TokenRule{
					{
						AWSAccount: "1234",
						AWSARN:     "arn:aws::role/admins-???",
					},
				},
				JoinMethod: types.JoinMethodIAM,
			},
			stsClient: &mockClient{
				respStatusCode: http.StatusOK,
				respBody: responseFromAWSIdentity(awsIdentity{
					Account: "1234",
					Arn:     "arn:aws::role/admins-123",
				}),
			},
			assertError: require.NoError,
		},
		{
			desc:             "wrong token",
			tokenName:        "test-token",
			requestTokenName: "wrong-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Allow: []*types.TokenRule{
					{
						AWSAccount: "1234",
						AWSARN:     "arn:aws::1111",
					},
				},
				JoinMethod: types.JoinMethodIAM,
			},
			stsClient: &mockClient{
				respStatusCode: http.StatusOK,
				respBody: responseFromAWSIdentity(awsIdentity{
					Account: "1234",
					Arn:     "arn:aws::1111",
				}),
			},
			assertError: isAccessDenied,
		},
		{
			desc:             "challenge response error",
			tokenName:        "test-token",
			requestTokenName: "test-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Allow: []*types.TokenRule{
					{
						AWSAccount: "1234",
						AWSARN:     "arn:aws::1111",
					},
				},
				JoinMethod: types.JoinMethodIAM,
			},
			stsClient: &mockClient{
				respStatusCode: http.StatusOK,
				respBody: responseFromAWSIdentity(awsIdentity{
					Account: "1234",
					Arn:     "arn:aws::1111",
				}),
			},
			challengeResponseErr: trace.BadParameter("test error"),
			assertError:          isBadParameter,
		},
		{
			desc:             "wrong arn",
			tokenName:        "test-token",
			requestTokenName: "test-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Allow: []*types.TokenRule{
					{
						AWSAccount: "1234",
						AWSARN:     "arn:aws::role/admins-???",
					},
				},
				JoinMethod: types.JoinMethodIAM,
			},
			stsClient: &mockClient{
				respStatusCode: http.StatusOK,
				respBody: responseFromAWSIdentity(awsIdentity{
					Account: "1234",
					Arn:     "arn:aws::role/admins-1234",
				}),
			},
			assertError: isAccessDenied,
		},
		{
			desc:             "wrong challenge",
			tokenName:        "test-token",
			requestTokenName: "test-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Allow: []*types.TokenRule{
					{
						AWSAccount: "1234",
						AWSARN:     "arn:aws::1111",
					},
				},
				JoinMethod: types.JoinMethodIAM,
			},
			stsClient: &mockClient{
				respStatusCode: http.StatusOK,
				respBody: responseFromAWSIdentity(awsIdentity{
					Account: "1234",
					Arn:     "arn:aws::1111",
				}),
			},
			challengeResponseOptions: []challengeResponseOption{
				withChallenge("wrong-challenge"),
			},
			assertError: isAccessDenied,
		},
		{
			desc:             "wrong account",
			tokenName:        "test-token",
			requestTokenName: "test-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Allow: []*types.TokenRule{
					{
						AWSAccount: "1234",
						AWSARN:     "arn:aws::1111",
					},
				},
				JoinMethod: types.JoinMethodIAM,
			},
			stsClient: &mockClient{
				respStatusCode: http.StatusOK,
				respBody: responseFromAWSIdentity(awsIdentity{
					Account: "5678",
					Arn:     "arn:aws::1111",
				}),
			},
			assertError: isAccessDenied,
		},
		{
			desc:             "sts api error",
			tokenName:        "test-token",
			requestTokenName: "test-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Allow: []*types.TokenRule{
					{
						AWSAccount: "1234",
						AWSARN:     "arn:aws::1111",
					},
				},
				JoinMethod: types.JoinMethodIAM,
			},
			stsClient: &mockClient{
				respStatusCode: http.StatusForbidden,
				respBody:       "access denied",
			},
			assertError: isAccessDenied,
		},
		{
			desc:             "wrong sts host",
			tokenName:        "test-token",
			requestTokenName: "test-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Allow: []*types.TokenRule{
					{
						AWSAccount: "1234",
						AWSARN:     "arn:aws::1111",
					},
				},
				JoinMethod: types.JoinMethodIAM,
			},
			stsClient: &mockClient{
				respStatusCode: http.StatusOK,
				respBody: responseFromAWSIdentity(awsIdentity{
					Account: "1234",
					Arn:     "arn:aws::1111",
				}),
			},
			challengeResponseOptions: []challengeResponseOption{
				withHost("sts.wrong-host.amazonaws.com"),
			},
			assertError: isAccessDenied,
		},
		{
			desc:             "regional sts endpoint",
			tokenName:        "test-token",
			requestTokenName: "test-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Allow: []*types.TokenRule{
					{
						AWSAccount: "1234",
						AWSARN:     "arn:aws::1111",
					},
				},
				JoinMethod: types.JoinMethodIAM,
			},
			stsClient: &mockClient{
				respStatusCode: http.StatusOK,
				respBody: responseFromAWSIdentity(awsIdentity{
					Account: "1234",
					Arn:     "arn:aws::1111",
				}),
			},
			challengeResponseOptions: []challengeResponseOption{
				withHost("sts.us-west-2.amazonaws.com"),
			},
			assertError: require.NoError,
		},
		{
			desc:             "unsigned challenge header",
			tokenName:        "test-token",
			requestTokenName: "test-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Allow: []*types.TokenRule{
					{
						AWSAccount: "1234",
						AWSARN:     "arn:aws::1111",
					},
				},
				JoinMethod: types.JoinMethodIAM,
			},
			stsClient: &mockClient{
				respStatusCode: http.StatusOK,
				respBody: responseFromAWSIdentity(awsIdentity{
					Account: "1234",
					Arn:     "arn:aws::1111",
				}),
			},
			challengeResponseOptions: []challengeResponseOption{
				withSignedHeader(""),
			},
			assertError: isAccessDenied,
		},
		{
			desc:             "fips pass",
			tokenName:        "test-token",
			requestTokenName: "test-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Allow: []*types.TokenRule{
					{
						AWSAccount: "1234",
						AWSARN:     "arn:aws::1111",
					},
				},
				JoinMethod: types.JoinMethodIAM,
			},
			stsClient: &mockClient{
				respStatusCode: http.StatusOK,
				respBody: responseFromAWSIdentity(awsIdentity{
					Account: "1234",
					Arn:     "arn:aws::1111",
				}),
			},
			iamRegisterOptions: []iamRegisterOption{
				withFips(true),
				withAuthVersion(&semver.Version{Major: 12}),
			},
			challengeResponseOptions: []challengeResponseOption{
				withHost("sts-fips.us-east-1.amazonaws.com"),
			},
			assertError: require.NoError,
		},
		{
			desc:             "non-fips client pass v11",
			tokenName:        "test-token",
			requestTokenName: "test-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Allow: []*types.TokenRule{
					{
						AWSAccount: "1234",
						AWSARN:     "arn:aws::1111",
					},
				},
				JoinMethod: types.JoinMethodIAM,
			},
			stsClient: &mockClient{
				respStatusCode: http.StatusOK,
				respBody: responseFromAWSIdentity(awsIdentity{
					Account: "1234",
					Arn:     "arn:aws::1111",
				}),
			},
			iamRegisterOptions: []iamRegisterOption{
				withFips(true),
				withAuthVersion(&semver.Version{Major: 11}),
			},
			challengeResponseOptions: []challengeResponseOption{
				withHost("sts.us-east-1.amazonaws.com"),
			},
			assertError: require.NoError,
		},
		{
			desc:             "non-fips client fail v12",
			tokenName:        "test-token",
			requestTokenName: "test-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Allow: []*types.TokenRule{
					{
						AWSAccount: "1234",
						AWSARN:     "arn:aws::1111",
					},
				},
				JoinMethod: types.JoinMethodIAM,
			},
			stsClient: &mockClient{
				respStatusCode: http.StatusOK,
				respBody: responseFromAWSIdentity(awsIdentity{
					Account: "1234",
					Arn:     "arn:aws::1111",
				}),
			},
			iamRegisterOptions: []iamRegisterOption{
				withFips(true),
				withAuthVersion(&semver.Version{Major: 12}),
			},
			challengeResponseOptions: []challengeResponseOption{
				withHost("sts.us-east-1.amazonaws.com"),
			},
			assertError: isAccessDenied,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			// add token to auth server
			token, err := types.NewProvisionTokenFromSpec(
				tc.tokenName,
				time.Now().Add(time.Minute),
				tc.tokenSpec)
			require.NoError(t, err)
			require.NoError(t, a.UpsertToken(ctx, token))
			defer func() {
				require.NoError(t, a.DeleteToken(ctx, token.GetName()))
			}()

			requestContext := context.Background()
			requestContext = context.WithValue(requestContext, ContextClientAddr, &net.IPAddr{})
			requestContext = context.WithValue(requestContext, stsClientKey{}, tc.stsClient)

			_, err = a.RegisterUsingIAMMethod(requestContext, func(challenge string) (*proto.RegisterUsingIAMMethodRequest, error) {
				templateInput := defaultIdentityRequestTemplateInput(challenge)
				for _, opt := range tc.challengeResponseOptions {
					opt(&templateInput)
				}
				var identityRequest bytes.Buffer
				require.NoError(t, identityRequestTemplate.Execute(&identityRequest, templateInput))

				req := &proto.RegisterUsingIAMMethodRequest{
					RegisterUsingTokenRequest: &types.RegisterUsingTokenRequest{
						Token:        tc.requestTokenName,
						HostID:       "test-node",
						Role:         types.RoleNode,
						PublicSSHKey: sshPublicKey,
						PublicTLSKey: tlsPublicKey,
					},
					StsIdentityRequest: identityRequest.Bytes(),
				}
				return req, tc.challengeResponseErr
			}, tc.iamRegisterOptions...)
			tc.assertError(t, err)
		})
	}
}
