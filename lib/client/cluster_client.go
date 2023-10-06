// Copyright 2023 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"context"

	"github.com/gravitational/trace"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport/api/client/proto"
	proxyclient "github.com/gravitational/teleport/api/client/proxy"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/services"
)

// ClusterClient facilitates communicating with both the
// Auth and Proxy services of a cluster.
type ClusterClient struct {
	tc          *TeleportClient
	ProxyClient *proxyclient.Client
	AuthClient  auth.ClientI
	Tracer      oteltrace.Tracer
	cluster     string
	root        string
}

// ClusterName returns the name of the cluster that the client
// is connected to.
func (c *ClusterClient) ClusterName() string {
	return c.cluster
}

// CurrentCluster returns an authenticated auth server client for the local cluster.
// The returned auth server client does not need to be closed, it will be closed
// when the ClusterClient is closed.
func (c *ClusterClient) CurrentCluster() auth.ClientI {
	// The auth.ClientI is wrapped in an sharedAuthClient to prevent callers from
	// being able to close the client. The auth.ClientI is only to be closed
	// when the ClusterClient is closed.
	return sharedAuthClient{ClientI: c.AuthClient}
}

// ConnectToRootCluster connects to the auth server of the root cluster
// via proxy. It returns connected and authenticated auth server client.
func (c *ClusterClient) ConnectToRootCluster(ctx context.Context) (auth.ClientI, error) {
	root, err := c.ConnectToCluster(ctx, c.root)
	return root, trace.Wrap(err)
}

// ConnectToCluster connects to the auth server of the given cluster via proxy. It returns connected and authenticated auth server client
func (c *ClusterClient) ConnectToCluster(ctx context.Context, clusterName string) (auth.ClientI, error) {
	if c.cluster == clusterName {
		return c.CurrentCluster(), nil
	}

	clientConfig := c.ProxyClient.ClientConfig(ctx, clusterName)
	authClient, err := auth.NewClient(clientConfig)
	return authClient, trace.Wrap(err)
}

// Close terminates the connections to Auth and Proxy.
func (c *ClusterClient) Close() error {
	// close auth client first since it is tunneled through the proxy client
	return trace.NewAggregate(c.AuthClient.Close(), c.ProxyClient.Close())
}

// SessionSSHConfig returns the [ssh.ClientConfig] that should be used to connected to the
// provided target for the provided user. If per session MFA is required to establish the
// connection, then the MFA ceremony will be performed.
func (c *ClusterClient) SessionSSHConfig(ctx context.Context, user string, target NodeDetails) (*ssh.ClientConfig, error) {
	ctx, span := c.Tracer.Start(
		ctx,
		"clusterClient/SessionSSHConfig",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(
			attribute.String("cluster", c.tc.SiteName),
		),
	)
	defer span.End()

	sshConfig := c.ProxyClient.SSHConfig(user)

	if target.MFACheck != nil && !target.MFACheck.Required {
		return sshConfig, nil
	}

	key, err := c.tc.localAgent.GetKey(target.Cluster, WithAllCerts...)
	if err != nil {
		return nil, trace.Wrap(MFARequiredUnknown(err))
	}

	// Always connect to root for getting new credentials, but attempt to reuse
	// the existing client if possible.
	rootClusterName, err := key.RootClusterName()
	if err != nil {
		return nil, trace.Wrap(MFARequiredUnknown(err))
	}

	mfaClt := c
	if target.Cluster != rootClusterName {
		authClient, err := auth.NewClient(c.ProxyClient.ClientConfig(ctx, rootClusterName))
		if err != nil {
			return nil, trace.Wrap(MFARequiredUnknown(err))
		}

		mfaClt = &ClusterClient{
			tc:          c.tc,
			ProxyClient: c.ProxyClient,
			AuthClient:  authClient,
			Tracer:      c.Tracer,
			cluster:     rootClusterName,
			root:        rootClusterName,
		}
		// only close the new auth client and not the copied cluster client.
		defer authClient.Close()
	}

	log.Debug("Attempting to issue a single-use user certificate with an MFA check.")
	key, err = c.performMFACeremony(ctx, mfaClt,
		ReissueParams{
			NodeName:       nodeName(target.Addr),
			RouteToCluster: target.Cluster,
			MFACheck:       target.MFACheck,
		},
		key,
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	log.Debug("Issued single-use user certificate after an MFA check.")
	am, err := key.AsAuthMethod()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	sshConfig.Auth = []ssh.AuthMethod{am}
	return sshConfig, nil
}

// reissueUserCerts gets new user certificates from the root Auth server.
func (c *ClusterClient) reissueUserCerts(ctx context.Context, cachePolicy CertCachePolicy, params ReissueParams) (*Key, error) {
	if params.RouteToCluster == "" {
		params.RouteToCluster = c.tc.SiteName
	}
	key := params.ExistingCreds
	if key == nil {
		var err error

		// Don't load the certs if we're going to drop all of them all as part
		// of the re-issue. If we load all of the old certs now we won't be able
		// to differentiate between legacy certificates (that need to be
		// deleted) and newly re-issued certs (that we definitely do *not* want
		// to delete) when it comes time to drop them from the local agent.
		var certOptions []CertOption
		if cachePolicy == CertCacheKeep {
			certOptions = WithAllCerts
		}

		key, err = c.tc.localAgent.GetKey(params.RouteToCluster, certOptions...)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	req, err := c.prepareUserCertsRequest(params, key)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	certs, err := c.AuthClient.GenerateUserCerts(ctx, *req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	key.ClusterName = params.RouteToCluster

	// Only update the parts of key that match the usage. See the docs on
	// proto.UserCertsRequest_CertUsage for which certificates match which
	// usage.
	//
	// This prevents us from overwriting the top-level key.TLSCert with
	// usage-restricted certificates.
	switch params.usage() {
	case proto.UserCertsRequest_All:
		key.Cert = certs.SSH
		key.TLSCert = certs.TLS
	case proto.UserCertsRequest_SSH:
		key.Cert = certs.SSH
	case proto.UserCertsRequest_App:
		key.AppTLSCerts[params.RouteToApp.Name] = certs.TLS
	case proto.UserCertsRequest_Database:
		dbCert, err := makeDatabaseClientPEM(params.RouteToDatabase.Protocol, certs.TLS, key)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		key.DBTLSCerts[params.RouteToDatabase.ServiceName] = dbCert
	case proto.UserCertsRequest_Kubernetes:
		key.KubeTLSCerts[params.KubernetesCluster] = certs.TLS
	case proto.UserCertsRequest_WindowsDesktop:
		key.WindowsDesktopCerts[params.RouteToWindowsDesktop.WindowsDesktop] = certs.TLS
	}
	return key, nil
}

// prepareUserCertsRequest creates a [proto.UserCertsRequest] with the fields
// set accordingly from the provided ReissueParams.
func (c *ClusterClient) prepareUserCertsRequest(params ReissueParams, key *Key) (*proto.UserCertsRequest, error) {
	tlsCert, err := key.TeleportTLSCertificate()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if len(params.AccessRequests) == 0 {
		// Get the active access requests to include in the cert.
		activeRequests, err := key.ActiveRequests()
		// key.ActiveRequests can return a NotFound error if it doesn't have an
		// SSH cert. That's OK, we just assume that there are no AccessRequests
		// in that case.
		if err != nil && !trace.IsNotFound(err) {
			return nil, trace.Wrap(err)
		}
		params.AccessRequests = activeRequests.AccessRequests
	}

	return &proto.UserCertsRequest{
		PublicKey:             key.MarshalSSHPublicKey(),
		Username:              tlsCert.Subject.CommonName,
		Expires:               tlsCert.NotAfter,
		RouteToCluster:        params.RouteToCluster,
		KubernetesCluster:     params.KubernetesCluster,
		AccessRequests:        params.AccessRequests,
		DropAccessRequests:    params.DropAccessRequests,
		RouteToDatabase:       params.RouteToDatabase,
		RouteToWindowsDesktop: params.RouteToWindowsDesktop,
		RouteToApp:            params.RouteToApp,
		NodeName:              params.NodeName,
		Usage:                 params.usage(),
		Format:                c.tc.CertificateFormat,
		RequesterName:         params.RequesterName,
		SSHLogin:              c.tc.HostLogin,
		AttestationStatement:  key.PrivateKey.GetAttestationStatement().ToProto(),
	}, nil
}

// performMFACeremony runs the mfa ceremony to completion. If successful the returned
// [Key] will be authorized to connect to the target.
func (c *ClusterClient) performMFACeremony(ctx context.Context, rootClient *ClusterClient, params ReissueParams, key *Key) (*Key, error) {
	mfaRequiredReq := params.isMFARequiredRequest(rootClient.tc.HostLogin)

	// If connecting to a host in a leaf cluster and MFA failed check to see
	// if the leaf cluster requires MFA. If it doesn't return an error indicating
	// that MFA was not required instead of the error received from the root cluster.
	if c.cluster != rootClient.cluster {
		mfaRequiredResp, err := c.AuthClient.IsMFARequired(ctx, mfaRequiredReq)
		log.Debugf("MFA requirement acquired from leaf, MFARequired=%s", mfaRequiredResp.GetMFARequired())
		switch {
		case err != nil:
			return nil, trace.Wrap(MFARequiredUnknown(err))
		case !mfaRequiredResp.Required:
			return nil, trace.Wrap(services.ErrSessionMFANotRequired)
		}
		mfaRequiredReq = nil // Already checked, don't check again at root.
	}

	// Acquire MFA challenge.
	authnChal, err := rootClient.AuthClient.CreateAuthenticateChallenge(ctx, &proto.CreateAuthenticateChallengeRequest{
		Request: &proto.CreateAuthenticateChallengeRequest_ContextUser{
			ContextUser: &proto.ContextUser{},
		},
		MFARequiredCheck: mfaRequiredReq,
	})
	log.Debugf("MFA requirement from CreateAuthenticateChallenge, MFARequired=%s", authnChal.GetMFARequired())
	if authnChal.MFARequired == proto.MFARequired_MFA_REQUIRED_NO {
		return nil, trace.Wrap(services.ErrSessionMFANotRequired)
	}

	// Prompt user for solution (eg, security key touch).
	authnSolved, err := rootClient.tc.PromptMFA(ctx, authnChal)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Issue certificate.
	certsReq, err := rootClient.prepareUserCertsRequest(params, key)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	certsReq.MFAResponse = authnSolved
	certsReq.Purpose = proto.UserCertsRequest_CERT_PURPOSE_SINGLE_USE_CERTS
	log.Debug("Issuing single-use certificate from unary GenerateUserCerts")
	newCerts, err := rootClient.AuthClient.GenerateUserCerts(ctx, *certsReq)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch {
	case len(newCerts.SSH) > 0:
		key.Cert = newCerts.SSH
	case len(newCerts.TLS) > 0:
		switch certsReq.Usage {
		case proto.UserCertsRequest_Kubernetes:
			key.KubeTLSCerts[certsReq.KubernetesCluster] = newCerts.TLS

		case proto.UserCertsRequest_Database:
			dbCert, err := makeDatabaseClientPEM(params.RouteToDatabase.Protocol, newCerts.TLS, key)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			key.DBTLSCerts[params.RouteToDatabase.ServiceName] = dbCert

		case proto.UserCertsRequest_WindowsDesktop:
			key.WindowsDesktopCerts[params.RouteToWindowsDesktop.WindowsDesktop] = newCerts.TLS

		default:
			return nil, trace.BadParameter("server returned a TLS certificate but cert request usage was %s", certsReq.Usage)
		}
	}
	key.ClusterName = params.RouteToCluster

	return key, nil
}
