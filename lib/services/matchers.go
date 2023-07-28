/*
Copyright 2021 Gravitational, Inc.

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

package services

import (
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"

	"github.com/gravitational/teleport/api/types"
	apiutils "github.com/gravitational/teleport/api/utils"
	azureutils "github.com/gravitational/teleport/api/utils/azure"
)

// ResourceMatcher matches cluster resources.
type ResourceMatcher struct {
	// Labels match resource labels.
	Labels types.Labels
	// AWS contains AWS specific settings.
	AWS ResourceMatcherAWS
}

// ResourceMatcherAWS contains AWS specific settings.
type ResourceMatcherAWS struct {
	// AssumeRoleARN is the AWS role to assume for accessing the resource.
	AssumeRoleARN string
	// ExternalID is an optional AWS external ID used to enable assuming an AWS
	// role across accounts.
	ExternalID string
}

// ResourceMatchersToTypes converts []]services.ResourceMatchers into []*types.ResourceMatcher
func ResourceMatchersToTypes(in []ResourceMatcher) []*types.DatabaseResourceMatcher {
	out := make([]*types.DatabaseResourceMatcher, len(in))
	for i, resMatcher := range in {
		resMatcher := resMatcher
		out[i] = &types.DatabaseResourceMatcher{
			Labels: &resMatcher.Labels,
			AWS: types.ResourceMatcherAWS{
				AssumeRoleARN: resMatcher.AWS.AssumeRoleARN,
				ExternalID:    resMatcher.AWS.ExternalID,
			},
		}
	}
	return out
}

// AssumeRoleFromAWSMetadata is a conversion helper function that extracts
// AWS IAM role ARN and external ID from AWS metadata.
func AssumeRoleFromAWSMetadata(meta *types.AWS) types.AssumeRole {
	return types.AssumeRole{
		RoleARN:    meta.AssumeRoleARN,
		ExternalID: meta.ExternalID,
	}
}

// SimplifyAzureMatchers returns simplified Azure Matchers.
// Selectors are deduplicated, wildcard in a selector reduces the selector
// to just the wildcard, and defaults are applied.
func SimplifyAzureMatchers(matchers []types.AzureMatcher) []types.AzureMatcher {
	result := make([]types.AzureMatcher, 0, len(matchers))
	for _, m := range matchers {
		subs := apiutils.Deduplicate(m.Subscriptions)
		groups := apiutils.Deduplicate(m.ResourceGroups)
		regions := apiutils.Deduplicate(m.Regions)
		ts := apiutils.Deduplicate(m.Types)
		if len(subs) == 0 || slices.Contains(subs, types.Wildcard) {
			subs = []string{types.Wildcard}
		}
		if len(groups) == 0 || slices.Contains(groups, types.Wildcard) {
			groups = []string{types.Wildcard}
		}
		if len(regions) == 0 || slices.Contains(regions, types.Wildcard) {
			regions = []string{types.Wildcard}
		} else {
			for i, region := range regions {
				regions[i] = azureutils.NormalizeLocation(region)
			}
		}
		result = append(result, types.AzureMatcher{
			Subscriptions:  subs,
			ResourceGroups: groups,
			Regions:        regions,
			Types:          ts,
			ResourceTags:   m.ResourceTags,
			Params:         m.Params,
		})
	}
	return result
}

// MatchResourceLabels returns true if any of the provided selectors matches the provided database.
func MatchResourceLabels(matchers []ResourceMatcher, resource types.ResourceWithLabels) bool {
	for _, matcher := range matchers {
		if len(matcher.Labels) == 0 {
			return false
		}
		match, _, err := MatchLabels(matcher.Labels, resource.GetAllLabels())
		if err != nil {
			logrus.WithError(err).Errorf("Failed to match labels %v: %v.",
				matcher.Labels, resource)
			return false
		}
		if match {
			return true
		}
	}
	return false
}

// ResourceSeenKey is used as a key for a map that keeps track
// of unique resource names and address. Currently "addr"
// only applies to resource Application.
type ResourceSeenKey struct{ name, addr string }

// MatchResourceByFilters returns true if all filter values given matched against the resource.
//
// If no filters were provided, we will treat that as a match.
//
// If a `seenMap` is provided, this will be treated as a request to filter out duplicate matches.
// The map will be modified in place as it adds new keys. Seen keys will return match as false.
//
// Resource KubeService is handled differently b/c of its 1-N relationhip with service-clusters,
// it filters out the non-matched clusters on the kube service and the kube service
// is modified in place with only the matched clusters. Deduplication for resource `KubeService`
// is not provided but is provided for kind `KubernetesCluster`.
func MatchResourceByFilters(resource types.ResourceWithLabels, filter MatchResourceFilter, seenMap map[ResourceSeenKey]struct{}) (bool, error) {
	var specResource types.ResourceWithLabels

	// We assume when filtering for services like KubeService, AppServer, and DatabaseServer
	// the user is wanting to filter the contained resource ie. KubeClusters, Application, and Database.
	resourceKey := ResourceSeenKey{}
	switch filter.ResourceKind {
	case types.KindNode,
		types.KindDatabaseService,
		types.KindKubernetesCluster, types.KindKubePod,
		types.KindWindowsDesktop, types.KindWindowsDesktopService,
		types.KindUserGroup:
		specResource = resource
		resourceKey.name = specResource.GetName()

	case types.KindKubeServer:
		if seenMap != nil {
			return false, trace.BadParameter("checking for duplicate matches for resource kind %q is not supported", filter.ResourceKind)
		}
		return matchAndFilterKubeClusters(resource, filter)

	case types.KindAppServer:
		server, ok := resource.(types.AppServer)
		if !ok {
			return false, trace.BadParameter("expected types.AppServer, got %T", resource)
		}
		specResource = server.GetApp()
		app := server.GetApp()
		resourceKey.name = app.GetName()
		resourceKey.addr = app.GetPublicAddr()

	case types.KindDatabaseServer:
		server, ok := resource.(types.DatabaseServer)
		if !ok {
			return false, trace.BadParameter("expected types.DatabaseServer, got %T", resource)
		}
		specResource = server.GetDatabase()
		resourceKey.name = specResource.GetName()

	case types.KindAppOrSAMLIdPServiceProvider:
		switch appOrSP := resource.(type) {
		case types.AppServer:
			app := appOrSP.GetApp()
			specResource = app
			resourceKey.name = app.GetName()
			resourceKey.addr = app.GetPublicAddr()
		case types.SAMLIdPServiceProvider:
			specResource = appOrSP
			resourceKey.name = appOrSP.GetName()
		default:
			return false, trace.BadParameter("expected types.SAMLIdPServiceProvider or types.AppServer, got %T", resource)
		}
	default:
		return false, trace.NotImplemented("filtering for resource kind %q not supported", filter.ResourceKind)
	}

	var match bool

	if len(filter.Labels) == 0 && len(filter.SearchKeywords) == 0 && filter.PredicateExpression == "" {
		match = true
	}

	if !match {
		var err error
		match, err = matchResourceByFilters(specResource, filter)
		if err != nil {
			return false, trace.Wrap(err)
		}
	}

	// Deduplicate matches.
	if match && seenMap != nil {
		if _, exists := seenMap[resourceKey]; exists {
			return false, nil
		}
		seenMap[resourceKey] = struct{}{}
	}

	return match, nil
}

func matchResourceByFilters(resource types.ResourceWithLabels, filter MatchResourceFilter) (bool, error) {
	if filter.PredicateExpression != "" {
		parser, err := NewResourceParser(resource)
		if err != nil {
			return false, trace.Wrap(err)
		}

		switch match, err := parser.EvalBoolPredicate(filter.PredicateExpression); {
		case err != nil:
			return false, trace.BadParameter("failed to parse predicate expression: %s", err.Error())
		case !match:
			return false, nil
		}
	}

	if !types.MatchLabels(resource, filter.Labels) {
		return false, nil
	}

	if !resource.MatchSearch(filter.SearchKeywords) {
		return false, nil
	}

	return true, nil
}

// matchAndFilterKubeClusters is similar to MatchResourceByFilters, but does two things in addition:
//  1. handles kube service having a 1-N relationship (service-clusters)
//     so each kube cluster goes through the filters
//  2. filters out the non-matched clusters on the kube service and the kube service is
//     modified in place with only the matched clusters
//  3. only returns true if the service contained any matched cluster
func matchAndFilterKubeClusters(resource types.ResourceWithLabels, filter MatchResourceFilter) (bool, error) {
	if len(filter.Labels) == 0 && len(filter.SearchKeywords) == 0 && filter.PredicateExpression == "" {
		return true, nil
	}

	switch server := resource.(type) {
	case types.KubeServer:
		kubeCluster := server.GetCluster()
		if kubeCluster == nil {
			return false, nil
		}
		match, err := matchResourceByFilters(kubeCluster, filter)
		return match, trace.Wrap(err)
	default:
		return false, trace.BadParameter("unexpected kube server of type %T", resource)
	}
}

// MatchResourceFilter holds the filter values to match against a resource.
type MatchResourceFilter struct {
	// ResourceKind is the resource kind and is used to fine tune the filtering.
	ResourceKind string
	// Labels are the labels to match.
	Labels map[string]string
	// SearchKeywords is a list of search keywords to match.
	SearchKeywords []string
	// PredicateExpression holds boolean conditions that must be matched.
	PredicateExpression string
}

const (
	// AWSMatcherEC2 is the AWS matcher type for EC2 instances.
	AWSMatcherEC2 = "ec2"
	// AWSMatcherEKS is the AWS matcher type for AWS Kubernetes.
	AWSMatcherEKS = "eks"
	// AWSMatcherRDS is the AWS matcher type for RDS databases.
	AWSMatcherRDS = "rds"
	// AWSMatcherRDSProxy is the AWS matcher type for RDS Proxy databases.
	AWSMatcherRDSProxy = "rdsproxy"
	// AWSMatcherRedshift is the AWS matcher type for Redshift databases.
	AWSMatcherRedshift = "redshift"
	// AWSMatcherRedshiftServerless is the AWS matcher type for Redshift Serverless databases.
	AWSMatcherRedshiftServerless = "redshift-serverless"
	// AWSMatcherElastiCache is the AWS matcher type for ElastiCache databases.
	AWSMatcherElastiCache = "elasticache"
	// AWSMatcherMemoryDB is the AWS matcher type for MemoryDB databases.
	AWSMatcherMemoryDB = "memorydb"
	// AWSMatcherOpenSearch is the AWS matcher type for OpenSearch databases.
	AWSMatcherOpenSearch = "opensearch"
)

// SupportedAWSMatchers is list of AWS services currently supported by the
// Teleport discovery service.
var SupportedAWSMatchers = append([]string{
	AWSMatcherEC2,
	AWSMatcherEKS,
}, SupportedAWSDatabaseMatchers...)

// SupportedAWSDatabaseMatchers is a list of the AWS databases currently
// supported by the Teleport discovery service.
var SupportedAWSDatabaseMatchers = []string{
	AWSMatcherRDS,
	AWSMatcherRDSProxy,
	AWSMatcherRedshift,
	AWSMatcherRedshiftServerless,
	AWSMatcherElastiCache,
	AWSMatcherMemoryDB,
	AWSMatcherOpenSearch,
}

// RequireAWSIAMRolesAsUsersMatchers is a list of the AWS databases that
// require AWS IAM roles as database users.
// IMPORTANT: if you add database matchers for AWS keyspaces, OpenSearch, or
// DynamoDB discovery, add them here and in RequireAWSIAMRolesAsUsers in
// api/types.
var RequireAWSIAMRolesAsUsersMatchers = []string{
	AWSMatcherRedshiftServerless,
}

const (
	// AzureMatcherVM is the Azure matcher type for Azure VMs.
	AzureMatcherVM = "vm"
	// AzureMatcherKubernetes is the Azure matcher type for Azure Kubernetes.
	AzureMatcherKubernetes = "aks"
	// AzureMatcherMySQL is the Azure matcher type for Azure MySQL databases.
	AzureMatcherMySQL = "mysql"
	// AzureMatcherPostgres is the Azure matcher type for Azure Postgres databases.
	AzureMatcherPostgres = "postgres"
	// AzureMatcherRedis is the Azure matcher type for Azure Cache for Redis databases.
	AzureMatcherRedis = "redis"
	// AzureMatcherSQLServer is the Azure matcher type for SQL Server databases.
	AzureMatcherSQLServer = "sqlserver"
)

// SupportedAzureMatchers is list of Azure services currently supported by the
// Teleport discovery service.
var SupportedAzureMatchers = []string{
	AzureMatcherVM,
	AzureMatcherKubernetes,
	AzureMatcherMySQL,
	AzureMatcherPostgres,
	AzureMatcherRedis,
	AzureMatcherSQLServer,
}

const (
	// GCPMatcherKubernetes is the GCP matcher type for GCP kubernetes.
	GCPMatcherKubernetes = "gke"
	// GCPMatcherCompute is the GCP matcher for GCP VMs.
	GCPMatcherCompute = "gce"
)

// SupportedGCPMatchers is list of GCP services currently supported by the
// Teleport discovery service.
var SupportedGCPMatchers = []string{
	GCPMatcherKubernetes,
	GCPMatcherCompute,
}
