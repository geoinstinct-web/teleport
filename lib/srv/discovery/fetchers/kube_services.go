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

package fetchers

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/discovery/common"
)

// KubeAppsFetcherConfig configures kubeAppFetcher
type KubeAppsFetcherConfig struct {
	// Name of the kubernetes cluster
	ClusterName string
	// KubernetesClient is a client for Kubernetes API
	KubernetesClient kubernetes.Interface
	// FilterLabels are the filter criteria.
	FilterLabels types.Labels
	// Namespaces are the kubernetes namespaces in which to discover services
	Namespaces []string
	// Log is a logger to use
	Log logrus.FieldLogger
	// PI inspects port to find your whether they are HTTP/HTTPS or not.
	protocolChecker services.ProtocolChecker
}

// CheckAndSetDefaults validates and sets the defaults values.
func (k *KubeAppsFetcherConfig) CheckAndSetDefaults() error {
	if k.FilterLabels == nil {
		return trace.BadParameter("missing parameter FilterLabels")
	}
	if k.KubernetesClient == nil {
		return trace.BadParameter("missing parameter KubernetesClient")
	}
	if k.Log == nil {
		return trace.BadParameter("missing parameter Log")
	}
	if k.ClusterName == "" {
		return trace.BadParameter("missing parameter ClusterName")
	}
	if k.protocolChecker == nil {
		k.protocolChecker = &noopProtocolChecker{}
	}

	return nil
}

// kubeAppFetcher fetches app resources from Kubernetes services
type kubeAppFetcher struct {
	KubeAppsFetcherConfig
}

// Default implementation, doesn't actually performs HTTP request.
type noopProtocolChecker struct{}

// CheckProtocol for noopProtocolChecker just returns 'tcp'
func (*noopProtocolChecker) CheckProtocol(uri string) string {
	return "tcp"
}

// NewKubeAppsFetcher creates new Kubernetes app fetcher
func NewKubeAppsFetcher(cfg KubeAppsFetcherConfig) (common.Fetcher, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	return &kubeAppFetcher{
		KubeAppsFetcherConfig: cfg,
	}, nil
}

func isInternalKubeService(s v1.Service) bool {
	const kubernetesDefaultServiceName = "kubernetes"
	return (s.GetNamespace() == metav1.NamespaceDefault && s.GetName() == kubernetesDefaultServiceName) ||
		s.GetNamespace() == metav1.NamespaceSystem ||
		s.GetNamespace() == metav1.NamespacePublic
}

func (f *kubeAppFetcher) getServices(ctx context.Context) ([]v1.Service, error) {
	var result []v1.Service
	nextToken := ""
	namespaceFilter := func(ns string) bool {
		return slices.Contains(f.Namespaces, types.Wildcard) || slices.Contains(f.Namespaces, ns)
	}
	for {
		// Get all services in the cluster
		// We need to do this in a loop because the API only returns 500 items at a time
		// and we need to paginate through the results.
		kubeServices, err := f.KubernetesClient.CoreV1().Services(v1.NamespaceAll).List(
			ctx,
			metav1.ListOptions{
				Continue: nextToken,
			})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		for _, s := range kubeServices.Items {
			if !namespaceFilter(s.GetNamespace()) {
				// Namespace is not in the list of namespaces to fetch
				continue
			}
			match, _, err := services.MatchLabels(f.FilterLabels, s.Labels)
			if err != nil {
				return nil, trace.Wrap(err)
			} else if match {
				result = append(result, s)
			} else {
				f.Log.WithField("service_name", s.Name).Debug("Service doesn't match labels.")
			}
		}
		nextToken = kubeServices.Continue
		if nextToken == "" {
			break
		}
	}
	return result, nil
}

// Get fetches Kubernetes apps from the cluster
func (f *kubeAppFetcher) Get(ctx context.Context) (types.ResourcesWithLabels, error) {
	kubeServices, err := f.getServices(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Converting service to apps can involve performing a HTTP ping to the service ports to determine protocol.
	// Both services and ports inside services are processed in parallel to minimize time.
	// We also set limit to prevent potential spike load on a cluster in case there are a lot of services.
	g, _ := errgroup.WithContext(ctx)
	g.SetLimit(10)

	// Convert services to resources
	var (
		appsMu sync.Mutex
		apps   types.Apps
	)
	for _, service := range kubeServices {
		service := service

		g.Go(func() error {
			// Skip kubernetes own internal services
			if isInternalKubeService(service) {
				return nil
			}

			// Skip service if it has type annotation and it's not 'app'
			if v, ok := service.GetAnnotations()[types.DiscoveryTypeLabel]; ok && v != services.KubernetesMatchersApp {
				return nil
			}

			ports, err := getServicePorts(service)
			if err != nil {
				f.Log.WithError(err).Errorf("could not get ports for the service %q", service.GetName())
				return nil
			}

			for _, port := range ports {

			}

			serviceApps, err := services.NewApplicationsFromKubeService(service, f.ClusterName, f.protocolChecker)
			if err != nil {
				f.Log.Warnf("Could not get app from Kubernetes service: %v", err)
				return nil
			}

			appsMu.Lock()
			apps = append(apps, serviceApps...)
			appsMu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, trace.Wrap(err)
	}

	return apps.AsResources(), nil
}

func (f *kubeAppFetcher) ResourceType() string {
	return types.KindApp
}

func (f *kubeAppFetcher) Cloud() string {
	return ""
}

func (f *kubeAppFetcher) String() string {
	return fmt.Sprintf("kubeAppFetcher(Namespaces=%v, Labels=%v)", f.Namespaces, f.FilterLabels)
}

func getServicePorts(s v1.Service) ([]v1.ServicePort, error) {
	preferredPort := ""
	for k, v := range s.GetAnnotations() {
		if k == types.DiscoveryPortLabel {
			preferredPort = v
		}
	}
	availablePorts := []v1.ServicePort{}
	for _, p := range s.Spec.Ports {
		// Only supporting TCP ports.
		if p.Protocol != v1.ProtocolTCP {
			continue
		}
		availablePorts = append(availablePorts, p)
		// If preferred port is specified and we found it in available ports, use this one
		if preferredPort != "" && (preferredPort == strconv.Itoa(int(p.Port)) || p.Name == preferredPort) {
			return []v1.ServicePort{p}, nil
		}
	}

	// If preferred port is specified and we're here, it means we couldn't find it in service's ports.
	if preferredPort != "" {
		return nil, trace.BadParameter("Specified preferred port %s is absent among available service ports", preferredPort)
	}

	return availablePorts, nil
}
