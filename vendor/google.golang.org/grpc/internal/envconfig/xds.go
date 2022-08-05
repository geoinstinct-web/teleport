/*
 *
 * Copyright 2020 gRPC authors.
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
 *
 */

package envconfig

import (
	"os"
	"strings"
)

const (
	// XDSBootstrapFileNameEnv is the env variable to set bootstrap file name.
	// Do not use this and read from env directly. Its value is read and kept in
	// variable XDSBootstrapFileName.
	//
	// When both bootstrap FileName and FileContent are set, FileName is used.
	XDSBootstrapFileNameEnv = "GRPC_XDS_BOOTSTRAP"
	// XDSBootstrapFileContentEnv is the env variable to set bootstrap file
	// content. Do not use this and read from env directly. Its value is read
	// and kept in variable XDSBootstrapFileContent.
	//
	// When both bootstrap FileName and FileContent are set, FileName is used.
	XDSBootstrapFileContentEnv = "GRPC_XDS_BOOTSTRAP_CONFIG"

	ringHashSupportEnv           = "GRPC_XDS_EXPERIMENTAL_ENABLE_RING_HASH"
	clientSideSecuritySupportEnv = "GRPC_XDS_EXPERIMENTAL_SECURITY_SUPPORT"
	aggregateAndDNSSupportEnv    = "GRPC_XDS_EXPERIMENTAL_ENABLE_AGGREGATE_AND_LOGICAL_DNS_CLUSTER"
	rbacSupportEnv               = "GRPC_XDS_EXPERIMENTAL_RBAC"
	outlierDetectionSupportEnv   = "GRPC_EXPERIMENTAL_ENABLE_OUTLIER_DETECTION"
	federationEnv                = "GRPC_EXPERIMENTAL_XDS_FEDERATION"
	rlsInXDSEnv                  = "GRPC_EXPERIMENTAL_XDS_RLS_LB"

	c2pResolverTestOnlyTrafficDirectorURIEnv = "GRPC_TEST_ONLY_GOOGLE_C2P_RESOLVER_TRAFFIC_DIRECTOR_URI"
)

var (
	// XDSBootstrapFileName holds the name of the file which contains xDS
	// bootstrap configuration. Users can specify the location of the bootstrap
	// file by setting the environment variable "GRPC_XDS_BOOTSTRAP".
	//
	// When both bootstrap FileName and FileContent are set, FileName is used.
	XDSBootstrapFileName = os.Getenv(XDSBootstrapFileNameEnv)
	// XDSBootstrapFileContent holds the content of the xDS bootstrap
	// configuration. Users can specify the bootstrap config by setting the
	// environment variable "GRPC_XDS_BOOTSTRAP_CONFIG".
	//
	// When both bootstrap FileName and FileContent are set, FileName is used.
	XDSBootstrapFileContent = os.Getenv(XDSBootstrapFileContentEnv)
	// XDSRingHash indicates whether ring hash support is enabled, which can be
	// disabled by setting the environment variable
	// "GRPC_XDS_EXPERIMENTAL_ENABLE_RING_HASH" to "false".
	XDSRingHash = !strings.EqualFold(os.Getenv(ringHashSupportEnv), "false")
	// XDSClientSideSecurity is used to control processing of security
	// configuration on the client-side.
	//
	// Note that there is no env var protection for the server-side because we
	// have a brand new API on the server-side and users explicitly need to use
	// the new API to get security integration on the server.
	XDSClientSideSecurity = !strings.EqualFold(os.Getenv(clientSideSecuritySupportEnv), "false")
	// XDSAggregateAndDNS indicates whether processing of aggregated cluster
	// and DNS cluster is enabled, which can be enabled by setting the
	// environment variable
	// "GRPC_XDS_EXPERIMENTAL_ENABLE_AGGREGATE_AND_LOGICAL_DNS_CLUSTER" to
	// "true".
	XDSAggregateAndDNS = strings.EqualFold(os.Getenv(aggregateAndDNSSupportEnv), "true")

	// XDSRBAC indicates whether xDS configured RBAC HTTP Filter is enabled,
	// which can be disabled by setting the environment variable
	// "GRPC_XDS_EXPERIMENTAL_RBAC" to "false".
	XDSRBAC = !strings.EqualFold(os.Getenv(rbacSupportEnv), "false")
	// XDSOutlierDetection indicates whether outlier detection support is
	// enabled, which can be enabled by setting the environment variable
	// "GRPC_EXPERIMENTAL_ENABLE_OUTLIER_DETECTION" to "true".
	XDSOutlierDetection = strings.EqualFold(os.Getenv(outlierDetectionSupportEnv), "true")
	// XDSFederation indicates whether federation support is enabled.
	XDSFederation = strings.EqualFold(os.Getenv(federationEnv), "true")

	// XDSRLS indicates whether processing of Cluster Specifier plugins and
	// support for the RLS CLuster Specifier is enabled, which can be enabled by
	// setting the environment variable "GRPC_EXPERIMENTAL_XDS_RLS_LB" to
	// "true".
	XDSRLS = strings.EqualFold(os.Getenv(rlsInXDSEnv), "true")

	// C2PResolverTestOnlyTrafficDirectorURI is the TD URI for testing.
	C2PResolverTestOnlyTrafficDirectorURI = os.Getenv(c2pResolverTestOnlyTrafficDirectorURIEnv)
)
