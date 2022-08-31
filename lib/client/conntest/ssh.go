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

package conntest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils/sshutils"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/client"
	libsshutils "github.com/gravitational/teleport/lib/sshutils"
)

// SSHConnectionTesterConfig has the necessary fields to create a new SSHConnectionTester.
type SSHConnectionTesterConfig struct {
	// UserClient is an auth client that has a User's identity.
	// This is the user that is running the SSH Connection Test.
	UserClient auth.ClientI

	//ProxyClient is an auth client that has the Proxy's identity.
	ProxyClient auth.ClientI

	// ProxyHostPort is the proxy to use in the `--proxy` format (host:webPort,sshPort)
	ProxyHostPort string

	// TLSRoutingEnabled indicates that proxy supports ALPN SNI server where
	// all proxy services are exposed on a single TLS listener (Proxy Web Listener).
	TLSRoutingEnabled bool
}

// SSHConnectionTester implements the ConnectionTester interface for Testing SSH access
type SSHConnectionTester struct {
	userClient        auth.ClientI
	proxyClient       auth.ClientI
	webProxyAddr      string
	sshProxyAddr      string
	tlsRoutingEnabled bool
}

// NewSSHConnectionTester creates a new SSHConnectionTester
func NewSSHConnectionTester(cfg SSHConnectionTesterConfig) (*SSHConnectionTester, error) {
	parsedProxyHostAddr, err := client.ParseProxyHost(cfg.ProxyHostPort)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &SSHConnectionTester{
		userClient:        cfg.UserClient,
		proxyClient:       cfg.ProxyClient,
		webProxyAddr:      parsedProxyHostAddr.WebProxyAddr,
		sshProxyAddr:      parsedProxyHostAddr.SSHProxyAddr,
		tlsRoutingEnabled: cfg.TLSRoutingEnabled,
	}, nil
}

// TestConnection tests an SSH Connection to the target Node using
//  - the provided client
//  - resource name
//  - principal / linux user
// A new ConnectionDiagnostic is created and used to store the traces as it goes through the checkpoints
// To set up the SSH client, it will generate a new cert and inject the ConnectionDiagnosticID
//   - add a trace of whether the SSH Node was reachable
//   - SSH Node receives the cert and extracts the ConnectionDiagnostiID
//   - the SSH Node will append a trace indicating if the has access (RBAC)
//   - the SSH Node will append a trace indicating if the requested principal is valid for the target Node
func (s *SSHConnectionTester) TestConnection(ctx context.Context, req TestConnectionRequest) (types.ConnectionDiagnostic, error) {
	if req.ResourceKind != types.KindNode {
		return nil, trace.BadParameter("invalid value for ResourceKind, expected %q got %q", types.KindNode, req.ResourceKind)
	}

	connectionDiagnosticID := uuid.NewString()
	connectionDiagnostic, err := types.NewConnectionDiagnosticV1(connectionDiagnosticID, map[string]string{},
		types.ConnectionDiagnosticSpecV1{
			// We start with a failed state so that we don't need an extra update when returning non-happy paths.
			// For the happy path, we do update the Message to Success.
			Message: types.DiagnosticMessageFailed,
		})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := s.userClient.CreateConnectionDiagnostic(ctx, connectionDiagnostic); err != nil {
		return nil, trace.Wrap(err)
	}

	key, err := client.GenerateRSAKey()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	currentUser, err := s.userClient.GetCurrentUser(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	certs, err := s.userClient.GenerateUserCerts(ctx, proto.UserCertsRequest{
		PublicKey:              key.MarshalSSHPublicKey(),
		Username:               currentUser.GetName(),
		Expires:                time.Now().Add(time.Minute).UTC(),
		ConnectionDiagnosticID: connectionDiagnosticID,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	key.Cert = certs.SSH
	key.TLSCert = certs.TLS

	certAuths, err := s.userClient.GetCertAuthorities(ctx, types.HostCA, false /* loadKeys */)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	hostkeyCallback, err := hostKeyCallbackFromCAs(certAuths)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	key.TrustedCA = auth.AuthoritiesToTrustedCerts(certAuths)

	keyAuthMethod, err := key.AsAuthMethod()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	clusterName, err := s.userClient.GetClusterName()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	clientConfTLS, err := key.TeleportClientTLSConfig(nil, []string{clusterName.GetClusterName()})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	key.KeyIndex = client.KeyIndex{
		Username:    req.SSHPrincipal,
		ProxyHost:   s.webProxyAddr,
		ClusterName: clusterName.GetClusterName(),
	}

	host, err := s.getNodeHost(ctx, req.ResourceName)
	if err != nil {
		if trace.IsNotFound(err) {
			connDiag, err := s.userClient.AppendDiagnosticTrace(ctx, connectionDiagnosticID, types.NewTraceDiagnosticConnection(
				types.ConnectionDiagnosticTrace_RBAC_NODE,
				"Node not found. Ensure the Node exists and your role allows you to access it.",
				err,
			))
			if err != nil {
				return nil, trace.Wrap(err)
			}

			return connDiag, nil
		}

		return nil, trace.Wrap(err)
	}

	processStdout := &bytes.Buffer{}

	clientConf := client.MakeDefaultConfig()
	clientConf.AddKeysToAgent = client.AddKeysToAgentNo
	clientConf.AuthMethods = []ssh.AuthMethod{keyAuthMethod}
	clientConf.Host = host
	clientConf.HostKeyCallback = hostkeyCallback
	clientConf.HostLogin = req.SSHPrincipal
	clientConf.SkipLocalAuth = true
	clientConf.SSHProxyAddr = s.sshProxyAddr
	clientConf.Stderr = io.Discard
	clientConf.Stdin = &bytes.Buffer{}
	clientConf.Stdout = processStdout
	clientConf.TLS = clientConfTLS
	clientConf.TLSRoutingEnabled = s.tlsRoutingEnabled
	clientConf.UseKeyPrincipals = true
	clientConf.Username = currentUser.GetName()
	clientConf.WebProxyAddr = s.webProxyAddr

	tc, err := client.NewClient(clientConf)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	ctxWithTimeout, cancelFunc := context.WithTimeout(ctx, req.DialTimeout)
	defer cancelFunc()

	if err := tc.SSH(ctxWithTimeout, []string{"whoami"}, false); err != nil {
		return s.handleErrFromSSH(ctx, connectionDiagnosticID, req.SSHPrincipal, err, processStdout)
	}

	connDiag, err := s.userClient.AppendDiagnosticTrace(ctx, connectionDiagnosticID, types.NewTraceDiagnosticConnection(
		types.ConnectionDiagnosticTrace_NODE_PRINCIPAL,
		fmt.Sprintf("%q user exists in target node", req.SSHPrincipal),
		nil,
	))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	connDiag.SetMessage(types.DiagnosticMessageSuccess)
	connDiag.SetSuccess(true)

	if err := s.userClient.UpdateConnectionDiagnostic(ctx, connDiag); err != nil {
		return nil, trace.Wrap(err)
	}

	return connDiag, nil
}

func (s SSHConnectionTester) getNodeHost(ctx context.Context, nodeName string) (host string, err error) {
	if s.tlsRoutingEnabled {
		return nodeName, nil
	}

	node, err := s.proxyClient.GetNode(ctx, defaults.Namespace, nodeName)
	if err != nil {
		return "", trace.Wrap(err)
	}

	return node.GetHostname(), nil
}

func (s SSHConnectionTester) handleErrFromSSH(ctx context.Context, connectionDiagnosticID string, sshPrincipal string, sshError error, processStdout *bytes.Buffer) (types.ConnectionDiagnostic, error) {
	if trace.IsConnectionProblem(sshError) {
		connDiag, err := s.userClient.AppendDiagnosticTrace(ctx, connectionDiagnosticID, types.NewTraceDiagnosticConnection(
			types.ConnectionDiagnosticTrace_CONNECTIVITY,
			`Failed to connect to the Node. Ensure teleport service is running using "systemctl status teleport".`,
			sshError,
		))
		if err != nil {
			return nil, trace.Wrap(err)
		}

		return connDiag, nil
	}

	processStdoutString := strings.TrimSpace(processStdout.String())
	if strings.HasPrefix(processStdoutString, "Failed to launch: user: unknown user") {
		connDiag, err := s.userClient.AppendDiagnosticTrace(ctx, connectionDiagnosticID, types.NewTraceDiagnosticConnection(
			types.ConnectionDiagnosticTrace_NODE_PRINCIPAL,
			fmt.Sprintf("Invalid user. Please ensure the principal %q is a valid Linux login in the target node. Output from Node: %v", sshPrincipal, processStdoutString),
			sshError,
		))
		if err != nil {
			return nil, trace.Wrap(err)
		}

		return connDiag, nil
	}

	// This happens when the principal is not part of the allowed ones.
	// A trace was already added by the Node and, here, we just return the diagnostic.
	if trace.IsAccessDenied(sshError) {
		connDiag, err := s.userClient.GetConnectionDiagnostic(ctx, connectionDiagnosticID)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		return connDiag, nil
	}

	connDiag, err := s.userClient.AppendDiagnosticTrace(ctx, connectionDiagnosticID, types.NewTraceDiagnosticConnection(
		types.ConnectionDiagnosticTrace_UNKNOWN_ERROR,
		"Unknown error.",
		sshError,
	))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return connDiag, nil
}

func hostKeyCallbackFromCAs(certAuths []types.CertAuthority) (ssh.HostKeyCallback, error) {
	var certPublicKeys []ssh.PublicKey
	for _, ca := range certAuths {
		caCheckers, err := libsshutils.GetCheckers(ca)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		certPublicKeys = append(certPublicKeys, caCheckers...)
	}

	hostKeyCallback, err := sshutils.NewHostKeyCallback(sshutils.HostKeyCallbackConfig{
		GetHostCheckers: func() ([]ssh.PublicKey, error) {
			return certPublicKeys, nil
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return hostKeyCallback, nil
}
