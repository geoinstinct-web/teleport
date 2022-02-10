// Copyright 2021 Gravitational, Inc
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

package desktop

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/srv/desktop/tdp"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
)

func TestConfigWildcardBaseDN(t *testing.T) {
	cfg := &WindowsServiceConfig{
		DiscoveryBaseDN: "*",
		LDAPConfig: LDAPConfig{
			Domain: "test.goteleport.com",
		},
	}
	require.NoError(t, cfg.checkAndSetDiscoveryDefaults())
	require.Equal(t, "DC=test,DC=goteleport,DC=com", cfg.DiscoveryBaseDN)
}

func TestConfigDesktopDiscovery(t *testing.T) {
	for _, test := range []struct {
		desc    string
		baseDN  string
		filters []string
		assert  require.ErrorAssertionFunc
	}{
		{
			desc:   "NOK - invalid base DN",
			baseDN: "example.com",
			assert: require.Error,
		},
		{
			desc:    "NOK - invalid filter",
			baseDN:  "DC=example,DC=goteleport,DC=com",
			filters: []string{"invalid!"},
			assert:  require.Error,
		},
		{
			desc:   "OK - wildcard base DN",
			baseDN: "*",
			assert: require.NoError,
		},
		{
			desc:   "OK - no filters",
			baseDN: "DC=example,DC=goteleport,DC=com",
			assert: require.NoError,
		},
		{
			desc:    "OK - valid filters",
			baseDN:  "DC=example,DC=goteleport,DC=com",
			filters: []string{"(!(primaryGroupID=516))"},
			assert:  require.NoError,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			cfg := &WindowsServiceConfig{
				DiscoveryBaseDN:      test.baseDN,
				DiscoveryLDAPFilters: test.filters,
			}
			test.assert(t, cfg.checkAndSetDiscoveryDefaults())
		})
	}
}

func TestCRLDN(t *testing.T) {
	for _, test := range []struct {
		clusterName string
		crlDN       string
	}{
		{
			clusterName: "test",
			crlDN:       "CN=test,CN=Teleport,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=goteleport,DC=com",
		},
		{
			clusterName: "cluster.goteleport.com",
			crlDN:       "CN=cluster.goteleport.com,CN=Teleport,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=goteleport,DC=com",
		},
	} {
		t.Run(test.clusterName, func(t *testing.T) {
			w := &WindowsService{
				clusterName: test.clusterName,
				cfg: WindowsServiceConfig{
					LDAPConfig: LDAPConfig{
						Domain: "test.goteleport.com",
					},
				},
			}
			require.Equal(t, test.crlDN, w.crlDN())
		})
	}
}

// TestGenerateCredentials verifies that the smartcard certificates generated
// by Teleport meet the requirements for Windows logon.
func TestGenerateCredentials(t *testing.T) {
	const (
		clusterName = "test"
		user        = "test-user"
		domain      = "test.example.com"
	)

	authServer, err := auth.NewTestAuthServer(auth.TestAuthServerConfig{
		ClusterName: clusterName,
		Dir:         t.TempDir(),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, authServer.Close())
	})

	tlsServer, err := authServer.NewTestTLSServer()
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, tlsServer.Close())
	})

	client, err := tlsServer.NewClient(auth.TestServerID(types.RoleWindowsDesktop, "test-host-id"))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, client.Close())
	})

	w := &WindowsService{
		clusterName: clusterName,
		cfg: WindowsServiceConfig{
			LDAPConfig: LDAPConfig{
				Domain: domain,
			},
			AuthClient: client,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	certb, keyb, err := w.generateCredentials(ctx, user, domain, windowsDesktopCertTTL)
	require.NoError(t, err)
	require.NotNil(t, certb)
	require.NotNil(t, keyb)

	cert, err := x509.ParseCertificate(certb)
	require.NoError(t, err)
	require.NotNil(t, cert)

	require.Equal(t, user, cert.Subject.CommonName)
	require.Contains(t, cert.CRLDistributionPoints,
		`ldap:///CN=test,CN=Teleport,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=example,DC=com?certificateRevocationList?base?objectClass=cRLDistributionPoint`)

	foundKeyUsage := false
	foundAltName := false
	for _, extension := range cert.Extensions {
		switch {
		case extension.Id.Equal(enhancedKeyUsageExtensionOID):
			foundKeyUsage = true
			var oids []asn1.ObjectIdentifier
			_, err = asn1.Unmarshal(extension.Value, &oids)
			require.NoError(t, err)
			require.Len(t, oids, 2)
			require.Contains(t, oids, clientAuthenticationOID)
			require.Contains(t, oids, smartcardLogonOID)

		case extension.Id.Equal(subjectAltNameExtensionOID):
			foundAltName = true
			var san subjectAltName
			_, err = asn1.Unmarshal(extension.Value, &san)
			require.NoError(t, err)

			require.Equal(t, san.OtherName.OID, upnOtherNameOID)
			require.Equal(t, san.OtherName.Value.Value, user+"@"+domain)
		}
	}
	require.True(t, foundKeyUsage)
	require.True(t, foundAltName)
}

func TestEmitsRecordingEventsOnSend(t *testing.T) {
	clock := clockwork.NewFakeClock()
	s := &WindowsService{
		cfg: WindowsServiceConfig{
			Clock: clock,
		},
	}

	// a fake PNG Frame message
	encoded := []byte{byte(tdp.TypePNGFrame), 0x01, 0x02}

	ch := make(chan events.AuditEvent)
	go func() {
		delay := func() int64 { return 0 }
		handler := s.makeTDPSendHandler(context.Background(), &channelEmitter{eventsCh: ch}, delay)

		// the handler accepts both the message structure and its encoded form,
		// but our logic only depends on the encoded form, so pass a nil message
		var msg tdp.Message = nil
		handler(msg, encoded)
	}()

	select {
	case e := <-ch:
		dr, ok := e.(*events.DesktopRecording)
		require.True(t, ok)
		require.Equal(t, encoded, dr.Message)
	case <-time.After(1 * time.Second):
		require.FailNow(t, "timed out waiting for event")
	}
}

func TestEmitsRecordingEventsOnReceive(t *testing.T) {
	clock := clockwork.NewFakeClock()
	s := &WindowsService{
		cfg: WindowsServiceConfig{
			Clock: clock,
		},
	}

	msg := tdp.MouseButton{
		Button: tdp.LeftMouseButton,
		State:  tdp.ButtonPressed,
	}

	ch := make(chan events.AuditEvent)
	go func() {
		delay := func() int64 { return 0 }
		handler := s.makeTDPRecieveHandler(context.Background(), &channelEmitter{eventsCh: ch}, delay)
		handler(msg)
	}()

	select {
	case e := <-ch:
		dr, ok := e.(*events.DesktopRecording)
		require.True(t, ok)
		decoded, err := tdp.Decode(dr.Message)
		require.NoError(t, err)
		require.Equal(t, msg, decoded)
	case <-time.After(1 * time.Second):
		require.FailNow(t, "timed out waiting for event")
	}
}

// TODO(zmb3): this is duplicated from lib/events/emitter_test.go
// move common testing emitters to a testevents package

type channelEmitter struct {
	eventsCh chan events.AuditEvent
}

func (c *channelEmitter) EmitAuditEvent(ctx context.Context, event events.AuditEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.eventsCh <- event:
		return nil
	}
}
