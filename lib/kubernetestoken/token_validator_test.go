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

package kubernetestoken

import (
	"context"
	"testing"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/discovery"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes/fake"
	ctest "k8s.io/client-go/testing"
)

var userGroups = []string{"system:serviceaccounts", "system:serviceaccounts:namespace", "system:authenticated"}

var boundTokenKubernetesVersion = version.Info{
	Major:      "1",
	Minor:      "22",
	GitVersion: "1.22",
}

var legacyTokenKubernetesVersion = version.Info{
	Major:      "1",
	Minor:      "19",
	GitVersion: "1.19",
}

// tokenReviewMock creates a testing.ReactionFunc validating the tokenReview request and answering it
func tokenReviewMock(t *testing.T, reviewResult *v1.TokenReview) func(ctest.Action) (bool, runtime.Object, error) {
	return func(action ctest.Action) (bool, runtime.Object, error) {
		createAction, ok := action.(ctest.CreateAction)
		require.True(t, ok)
		obj := createAction.GetObject()
		reviewRequest, ok := obj.(*v1.TokenReview)
		require.True(t, ok)

		require.Equal(t, reviewResult.Spec.Token, reviewRequest.Spec.Token)
		return true, reviewResult, nil
	}
}

// newFakeClientset builds a fake clientSet reporting a specific Kubernetes version
// This is used to test version-specific behaviours.
func newFakeClientset(version *version.Info) *fakeClientSet {
	cs := fakeClientSet{}
	cs.discovery = fakediscovery.FakeDiscovery{
		Fake:               &cs.Fake,
		FakedServerVersion: version,
	}
	return &cs
}

type fakeClientSet struct {
	fake.Clientset
	discovery fakediscovery.FakeDiscovery
}

// Discovery overrides the default fake.Clientset Discovery method and returns our custom discovery mock instead
func (c fakeClientSet) Discovery() discovery.DiscoveryInterface {
	return &c.discovery
}

func TestIDTokenValidator_Validate(t *testing.T) {
	tests := []struct {
		token         string
		review        *v1.TokenReview
		kubeVersion   *version.Info
		expectedError error
	}{
		{
			token: "valid",
			review: &v1.TokenReview{
				Spec: v1.TokenReviewSpec{
					Token: "valid",
				},
				Status: v1.TokenReviewStatus{
					Authenticated: true,
					User: v1.UserInfo{
						Username: "system:serviceaccount:namespace:my-service-account",
						UID:      "sa-uuid",
						Groups:   userGroups,
						Extra: map[string]v1.ExtraValue{
							"authentication.kubernetes.io/pod-name": {"podA"},
							"authentication.kubernetes.io/pod-uid":  {"podA-uuid"},
						},
					},
				},
			},
			kubeVersion:   &boundTokenKubernetesVersion,
			expectedError: nil,
		},
		{
			token: "valid-not-bound",
			review: &v1.TokenReview{
				Spec: v1.TokenReviewSpec{
					Token: "valid-not-bound",
				},
				Status: v1.TokenReviewStatus{
					Authenticated: true,
					User: v1.UserInfo{
						Username: "system:serviceaccount:namespace:my-service-account",
						UID:      "sa-uuid",
						Groups:   userGroups,
						Extra:    nil,
					},
				},
			},
			kubeVersion:   &legacyTokenKubernetesVersion,
			expectedError: nil,
		},
		{
			token: "valid-not-bound-on-modern-version",
			review: &v1.TokenReview{
				Spec: v1.TokenReviewSpec{
					Token: "valid-not-bound-on-modern-version",
				},
				Status: v1.TokenReviewStatus{
					Authenticated: true,
					User: v1.UserInfo{
						Username: "system:serviceaccount:namespace:my-service-account",
						UID:      "sa-uuid",
						Groups:   userGroups,
						Extra:    nil,
					},
				},
			},
			kubeVersion:   &boundTokenKubernetesVersion,
			expectedError: trace.BadParameter("legacy SA tokens are not accepted as kubernetes version 1.21 supports bound tokens"),
		},
		{
			token: "valid-but-not-serviceaccount",
			review: &v1.TokenReview{
				Spec: v1.TokenReviewSpec{
					Token: "valid-but-not-serviceaccount",
				},
				Status: v1.TokenReviewStatus{
					Authenticated: true,
					User: v1.UserInfo{
						Username: "eve@example.com",
						UID:      "user-uuid",
						Groups:   []string{"system:authenticated", "some-other-group"},
						Extra:    nil,
					},
				},
			},
			kubeVersion:   &boundTokenKubernetesVersion,
			expectedError: trace.BadParameter("token user is not a service account: eve@example.com"),
		},
		{
			token: "valid-but-not-serviceaccount-group",
			review: &v1.TokenReview{
				Spec: v1.TokenReviewSpec{
					Token: "valid-but-not-serviceaccount-group",
				},
				Status: v1.TokenReviewStatus{
					Authenticated: true,
					User: v1.UserInfo{
						Username: "system:serviceaccount:namespace:my-service-account",
						UID:      "user-uuid",
						Groups:   []string{"system:authenticated", "some-other-group"},
						Extra:    nil,
					},
				},
			},
			kubeVersion:   &boundTokenKubernetesVersion,
			expectedError: trace.BadParameter("token user 'system:serviceaccount:namespace:my-service-account' does not belong to the 'system:serviceaccounts' group"),
		},
		{
			token: "invalid-expired",
			review: &v1.TokenReview{
				Spec: v1.TokenReviewSpec{
					Token: "invalid-expired",
				},
				Status: v1.TokenReviewStatus{
					Authenticated: false,
					Error:         "[invalid bearer token, Token has been invalidated, unknown]",
				},
			},
			kubeVersion:   &boundTokenKubernetesVersion,
			expectedError: trace.AccessDenied("kubernetes failed to validate token: [invalid bearer token, Token has been invalidated, unknown]"),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.token, func(t *testing.T) {
			client := newFakeClientset(tt.kubeVersion)
			client.AddReactor("create", "tokenreviews", tokenReviewMock(t, tt.review))
			v := Validator{
				client: client,
			}
			userInfo, err := v.Validate(context.Background(), tt.token)
			if tt.expectedError == nil {
				require.NoError(t, err)
				require.Equal(t, tt.review.Status.User, *userInfo)
			} else {
				require.ErrorIs(t, err, tt.expectedError)
			}
		})
	}
}
