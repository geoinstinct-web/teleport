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
package e2e

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/integration/helpers"
	"github.com/gravitational/teleport/integration/kube"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/service/servicecfg"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
)

var (
	// kubernetes groups and users used for the test.
	// discovery-ci-eks
	// The kubernetes service IAM role can only impersonate the user and group listed below.
	// This is a security measure to prevent the kubernetes service from impersonating any user/group
	// including system:masters.
	// If you need to impersonate a different user/group, you need to update the RBAC
	// permissions for the kubernetes service IAM role.
	kubeGroups = []string{kube.TestImpersonationGroup}
	kubeUsers  = []string{"alice@example.com"}
)

// checkRequiredKubeEnvVars ensures that the required environment variables are set.
func checkRequiredKubeEnvVars(t *testing.T) {
	t.Helper()
	mustGetEnv(t, awsRegionEnv)
	mustGetEnv(t, kubeSvcRoleARNEnv)
	mustGetEnv(t, kubeDiscoverySvcRoleARNEnv)
	mustGetEnv(t, eksClusterNameEnv)
}

func TestKube(t *testing.T) {
	t.Parallel()
	testEnabled := os.Getenv(teleport.KubeRunTests)
	if ok, _ := strconv.ParseBool(testEnabled); !ok {
		t.Skip("Skipping Kubernetes test suite.")
	}
	checkRequiredKubeEnvVars(t)

	t.Run("AWS EKS Discovery - Matched cluster", awsEKSDiscoveryMatchedCluster)
	t.Run("AWS EKS Discovery - Unmatched cluster", awsEKSDiscoveryUnmatchedCluster)
}

// awsEKSDiscoveryMatchedCluster tests that the discovery service can discover an EKS
// cluster and create a KubernetesCluster resource.
func awsEKSDiscoveryMatchedCluster(t *testing.T) {
	t.Parallel()
	matcherLabels := mustGetDiscoveryMatcherLabels(t)
	teleport := createTeleportCluster(t,
		withKubeService(t, services.ResourceMatcher{
			Labels: types.Labels{
				types.Wildcard: []string{types.Wildcard},
			},
			AWS: services.ResourceMatcherAWS{
				AssumeRoleARN: os.Getenv(kubeSvcRoleARNEnv),
			},
		}),
		withKubeDiscoveryService(t, matcherLabels),
		withFullKubeAccessUserRole(t),
	)
	// Get the auth server.
	authC := teleport.Process.GetAuthServer()
	// Wait for the discovery service to discover the cluster and create a
	// KubernetesCluster resource.
	// Discovery service will scan the AWS account each minutes.
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		clusters, err := authC.GetKubernetesClusters(ctx)
		if err != nil || len(clusters) == 0 {
			return false
		}
		// Fail fast if the discovery service creates more than one cluster.
		assert.Equal(t, 1, len(clusters))
		// Fail fast if the discovery service creates a cluster with a different name.
		assert.Equal(t, os.Getenv(eksClusterNameEnv), clusters[0].GetName())
		return true
	}, 3*time.Minute, 10*time.Second, "wait for the discovery service to create a cluster")

	// Wait for the kubernetes service to create a KubernetesServer resource.
	// This will happen after the discovery service creates the KubernetesCluster
	// resource and the kubernetes service receives the event.
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		kubeServers, err := authC.GetKubernetesServers(ctx)
		return err == nil && len(kubeServers) == 1
	}, 2*time.Minute, time.Second, "wait for the kubernetes service to create a KubernetesServer")

	clusters, err := authC.GetKubernetesClusters(context.Background())
	require.NoError(t, err)

	// kubeClient is a Kubernetes client for the user created above
	// that will be used to verify that the user can access the cluster and
	// the permissions are correct.
	kubeClient, _, err := kube.ProxyClient(kube.ProxyConfig{
		T:           teleport,
		Username:    hostUser,
		KubeUsers:   kubeUsers,
		KubeGroups:  kubeGroups,
		KubeCluster: clusters[0].GetName(),
	})
	require.NoError(t, err)

	// Retrieve the list of services in the default namespace to verify that
	// the user can access the cluster and the kubernetes service can
	// impersonate the user's kubernetes_groups and kubernetes_users.
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		list, err := kubeClient.CoreV1().Services(metav1.NamespaceDefault).List(ctx, metav1.ListOptions{})
		return err == nil && len(list.Items) > 0
	}, 30*time.Second, time.Second)
}

// awsEKSDiscoveryUnmatchedCluster tests a scenario where the discovery service
// discovers an EKS cluster but the cluster does not match the discovery
// selectors and therefore no KubernetesCluster resource is created.
func awsEKSDiscoveryUnmatchedCluster(t *testing.T) {
	t.Parallel()
	teleport := createTeleportCluster(t,
		withKubeService(t, services.ResourceMatcher{
			Labels: types.Labels{
				types.Wildcard: []string{types.Wildcard},
			},
			AWS: services.ResourceMatcherAWS{
				AssumeRoleARN: os.Getenv(kubeSvcRoleARNEnv),
			},
		}),
		withKubeDiscoveryService(t, types.Labels{
			// This label will not match the EKS cluster.
			"env": {"tag_not_found"},
		}),
	)
	// Get the auth server.
	authC := teleport.Process.GetAuthServer()
	// Wait for the discovery service to not create a KubernetesCluster resource
	// because the cluster does not match the selectors.
	require.Never(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		clusters, err := authC.GetKubernetesClusters(ctx)
		return err == nil && len(clusters) != 0
	}, 2*time.Minute, 10*time.Second, "discovery service incorrectly created a kube_cluster")
}

// withFullKubeAccessUserRole creates a Teleport role with full access to kube
// clusters.
func withFullKubeAccessUserRole(t *testing.T) testOptionsFunc {
	// Create a new role with full access to all kube clusters.
	return withUserRole(t, hostUser, "kubemaster", types.RoleSpecV6{
		Allow: types.RoleConditions{
			KubeGroups: kubeGroups,
			KubeUsers:  kubeUsers,
			KubernetesLabels: types.Labels{
				types.Wildcard: {types.Wildcard},
			},
			KubernetesResources: []types.KubernetesResource{
				{
					Kind:      types.Wildcard,
					Name:      types.Wildcard,
					Namespace: types.Wildcard,
					Verbs:     []string{types.Wildcard},
				},
			},
		},
	})
}

// withKubeService sets up the kubernetes service to watch for kubernetes
// clusters created by the discovery service.
func withKubeService(t *testing.T, matchers ...services.ResourceMatcher) testOptionsFunc {
	t.Helper()
	mustGetEnv(t, kubeSvcRoleARNEnv)
	return func(options *testOptions) {
		options.serviceConfigFuncs = append(options.serviceConfigFuncs, func(cfg *servicecfg.Config) {
			// Enable kubernetes proxy
			cfg.Proxy.Kube.Enabled = true
			cfg.Proxy.Kube.ListenAddr = *utils.MustParseAddr(helpers.NewListener(t, service.ListenerProxyKube, &(cfg.FileDescriptors)))
			// set kubernetes specific parameters
			cfg.Kube.Enabled = true
			cfg.Kube.ListenAddr = utils.MustParseAddr(helpers.NewListener(t, service.ListenerKube, &(cfg.FileDescriptors)))
			cfg.Kube.ResourceMatchers = matchers
		})
	}
}

func withKubeDiscoveryService(t *testing.T, tags types.Labels) testOptionsFunc {
	t.Helper()
	return withDiscoveryService(t, "kube-e2e-test", types.AWSMatcher{
		Types:   []string{types.AWSMatcherEKS},
		Tags:    tags,
		Regions: []string{os.Getenv(awsRegionEnv)},
		AssumeRole: &types.AssumeRole{
			RoleARN: os.Getenv(kubeDiscoverySvcRoleARNEnv),
		},
	})
}
