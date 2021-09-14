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

package reversetunnel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// TestAgentCertChecker validates that reverse tunnel agents properly validate
// SSH host certificates.
func TestAgentCertChecker(t *testing.T) {
	handler := sshutils.NewChanHandlerFunc(func(_ context.Context, ccx *sshutils.ConnectionContext, nch ssh.NewChannel) {
		ch, _, err := nch.Accept()
		require.NoError(t, err)
		require.NoError(t, ch.Close())
	})

	ca, err := sshutils.MakeTestSSHCA()
	require.NoError(t, err)

	spoofedCert, err := sshutils.MakeSpoofedHostCert(ca)
	require.NoError(t, err)

	sshServer, err := sshutils.NewServer(
		"test",
		utils.NetAddr{AddrNetwork: "tcp", Addr: "localhost:0"},
		handler,
		[]ssh.Signer{spoofedCert},
		sshutils.AuthMethods{NoClient: true},
		sshutils.SetInsecureSkipHostValidation(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { sshServer.Close() })
	require.NoError(t, sshServer.Start())

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)

	events := make(chan string)

	agent, err := NewAgent(AgentConfig{
		Addr:        *utils.MustParseAddr(sshServer.Addr()),
		EventsC:     events,
		Context:     context.Background(),
		Client:      &fakeClient{caKey: ca.PublicKey()},
		AccessPoint: &fakeClient{caKey: ca.PublicKey()},
		Signer:      signer,
		Username:    "foo",
	})
	require.NoError(t, err)

	_, err = agent.connect()
	require.Error(t, err, "agent should reject invalid host certificate")
}

type fakeClient struct {
	auth.Client
	caKey ssh.PublicKey
}

func (fc *fakeClient) GetCertAuthorities(caType services.CertAuthType, loadKeys bool, opts ...services.MarshalOption) ([]services.CertAuthority, error) {
	return []services.CertAuthority{services.NewCertAuthority(
		services.HostCA,
		"example.com",
		nil,
		[][]byte{ssh.MarshalAuthorizedKey(fc.caKey)},
		nil,
		services.CertAuthoritySpecV2_RSA_SHA2_512),
	}, nil
}

func (fc *fakeClient) GetClusterConfig(opts ...services.MarshalOption) (services.ClusterConfig, error) {
	return services.NewClusterConfig(services.ClusterConfigSpecV3{
		SessionRecording:    "off",
		ProxyChecksHostKeys: "yes",
	})
}
