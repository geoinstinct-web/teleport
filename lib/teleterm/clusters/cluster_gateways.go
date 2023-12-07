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

package clusters

import (
	"context"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/teleterm/api/uri"
	"github.com/gravitational/teleport/lib/teleterm/gateway"
	"github.com/gravitational/teleport/lib/tlsca"
)

type CreateGatewayParams struct {
	// TargetURI is the cluster resource URI
	TargetURI uri.ResourceURI
	// TargetUser is the target user name
	TargetUser string
	// TargetSubresourceName points at a subresource of the remote resource, for example a database
	// name on a database server.
	TargetSubresourceName string
	// LocalPort is the gateway local port
	LocalPort          string
	CLICommandProvider gateway.CLICommandProvider
	TCPPortAllocator   gateway.TCPPortAllocator
	OnExpiredCert      gateway.OnExpiredCertFunc
	KubeconfigsDir     string
}

// CreateGateway creates a gateway
func (c *Cluster) CreateGateway(ctx context.Context, params CreateGatewayParams) (gateway.Gateway, error) {
	switch {
	case params.TargetURI.IsDB():
		gateway, err := c.createDBGateway(ctx, params)
		return gateway, trace.Wrap(err)

	case params.TargetURI.IsKube():
		gateway, err := c.createKubeGateway(ctx, params)
		return gateway, trace.Wrap(err)

	default:
		return nil, trace.NotImplemented("gateway not supported for %v", params.TargetURI)
	}
}

func (c *Cluster) createDBGateway(ctx context.Context, params CreateGatewayParams) (gateway.Gateway, error) {
	db, err := c.GetDatabase(ctx, params.TargetURI)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	routeToDatabase := tlsca.RouteToDatabase{
		ServiceName: db.GetName(),
		Protocol:    db.GetProtocol(),
		Username:    params.TargetUser,
	}

	if err := c.reissueDBCerts(ctx, routeToDatabase); err != nil {
		return nil, trace.Wrap(err)
	}

	gw, err := gateway.New(gateway.Config{
		LocalPort:                     params.LocalPort,
		TargetURI:                     params.TargetURI,
		TargetUser:                    params.TargetUser,
		TargetName:                    db.GetName(),
		TargetSubresourceName:         params.TargetSubresourceName,
		Protocol:                      db.GetProtocol(),
		KeyPath:                       c.status.KeyPath(),
		CertPath:                      c.status.DatabaseCertPathForCluster(c.clusterClient.SiteName, db.GetName()),
		Insecure:                      c.clusterClient.InsecureSkipVerify,
		WebProxyAddr:                  c.clusterClient.WebProxyAddr,
		Log:                           c.Log,
		CLICommandProvider:            params.CLICommandProvider,
		TCPPortAllocator:              params.TCPPortAllocator,
		OnExpiredCert:                 params.OnExpiredCert,
		Clock:                         c.clock,
		TLSRoutingConnUpgradeRequired: c.clusterClient.TLSRoutingConnUpgradeRequired,
		RootClusterCACertPoolFunc:     c.clusterClient.RootClusterCACertPool,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return gw, nil
}

func (c *Cluster) createKubeGateway(ctx context.Context, params CreateGatewayParams) (gateway.Gateway, error) {
	kube := params.TargetURI.GetKubeName()

	// Check if this kube exists and the user has access to it.
	if _, err := c.getKube(ctx, kube); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := AddMetadataToRetryableError(ctx, func() error {
		return trace.Wrap(c.reissueKubeCert(ctx, kube))
	}); err != nil {
		return nil, trace.Wrap(err)
	}

	// TODO support TargetUser (--as), TargetGroups (--as-groups), TargetSubresourceName (--kube-namespace).
	gw, err := gateway.New(gateway.Config{
		LocalPort:                     params.LocalPort,
		TargetURI:                     params.TargetURI,
		TargetName:                    kube,
		KeyPath:                       c.status.KeyPath(),
		CertPath:                      c.status.KubeCertPathForCluster(c.clusterClient.SiteName, kube),
		Insecure:                      c.clusterClient.InsecureSkipVerify,
		WebProxyAddr:                  c.clusterClient.WebProxyAddr,
		Log:                           c.Log,
		CLICommandProvider:            params.CLICommandProvider,
		TCPPortAllocator:              params.TCPPortAllocator,
		OnExpiredCert:                 params.OnExpiredCert,
		Clock:                         c.clock,
		TLSRoutingConnUpgradeRequired: c.clusterClient.TLSRoutingConnUpgradeRequired,
		RootClusterCACertPoolFunc:     c.clusterClient.RootClusterCACertPool,
		ClusterName:                   c.Name,
		Username:                      c.status.Username,
		KubeconfigsDir:                params.KubeconfigsDir,
	})
	return gw, trace.Wrap(err)
}

// ReissueGatewayCerts reissues certificate for provided gateway.
func (c *Cluster) ReissueGatewayCerts(ctx context.Context, g gateway.Gateway) error {
	switch {
	case g.TargetURI().IsDB():
		db, err := gateway.AsDatabase(g)
		if err != nil {
			return trace.Wrap(err)
		}
		return trace.Wrap(c.reissueDBCerts(ctx, db.RouteToDatabase()))
	case g.TargetURI().IsKube():
		return trace.Wrap(c.reissueKubeCert(ctx, g.TargetName()))
	default:
		return nil
	}
}
