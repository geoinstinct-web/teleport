package proxy

import (
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/ttlmap"
	"gopkg.in/check.v1"
)

type ForwarderSuite struct{}

var _ = check.Suite(ForwarderSuite{})

func (s ForwarderSuite) TestRequestCertificate(c *check.C) {
	cl := &mockClient{
		csrResp: auth.KubeCSRResponse{
			Cert:            []byte("mock cert"),
			CertAuthorities: [][]byte{[]byte("mock CA")},
			TargetAddr:      "mock addr",
		},
	}
	f := &Forwarder{
		ForwarderConfig: ForwarderConfig{
			Keygen: testauthority.New(),
			Client: cl,
		},
	}
	user, err := services.NewUser("bob")
	c.Assert(err, check.IsNil)
	ctx := authContext{
		cluster: cluster{
			RemoteSite: mockRemoteSite{name: "site a"},
		},
		AuthContext: auth.AuthContext{
			User: user,
			Identity: auth.WrapIdentity(tlsca.Identity{
				Username:         "remote-bob",
				Groups:           []string{"remote group a", "remote group b"},
				Usage:            []string{"usage a", "usage b"},
				Principals:       []string{"principal a", "principal b"},
				KubernetesGroups: []string{"remote k8s group a", "remote k8s group b"},
				Traits:           map[string][]string{"trait a": []string{"b", "c"}},
			}),
			UnmappedIdentity: auth.WrapIdentity(tlsca.Identity{
				Username:         "bob",
				Groups:           []string{"group a", "group b"},
				Usage:            []string{"usage a", "usage b"},
				Principals:       []string{"principal a", "principal b"},
				KubernetesGroups: []string{"k8s group a", "k8s group b"},
				Traits:           map[string][]string{"trait a": []string{"b", "c"}},
			}),
		},
	}

	b, err := f.requestCertificate(ctx)
	c.Assert(err, check.IsNil)
	// All fields except b.key are predictable.
	c.Assert(b.Certificates[0].Certificate[0], check.DeepEquals, cl.csrResp.Cert)
	c.Assert(len(b.RootCAs.Subjects()), check.Equals, 1)

	// Check the KubeCSR fields.
	c.Assert(cl.gotCSR.Username, check.DeepEquals, ctx.User.GetName())
	c.Assert(cl.gotCSR.ClusterName, check.DeepEquals, ctx.cluster.GetName())

	// Parse x509 CSR and check the subject.
	csrBlock, _ := pem.Decode(cl.gotCSR.CSR)
	c.Assert(csrBlock, check.NotNil)
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	c.Assert(err, check.IsNil)
	idFromCSR, err := tlsca.FromSubject(csr.Subject, time.Time{})
	c.Assert(err, check.IsNil)
	c.Assert(*idFromCSR, check.DeepEquals, ctx.UnmappedIdentity.GetIdentity())
}

func (s ForwarderSuite) TestGetClusterSession(c *check.C) {
	clusterSessions, err := ttlmap.New(defaults.ClientCacheSize)
	c.Assert(err, check.IsNil)
	f := &Forwarder{
		clusterSessions: clusterSessions,
	}

	user, err := services.NewUser("bob")
	c.Assert(err, check.IsNil)
	remote := &mockRemoteSite{name: "site a"}
	ctx := authContext{
		cluster: cluster{
			isRemote:   true,
			RemoteSite: remote,
		},
		AuthContext: auth.AuthContext{
			User: user,
		},
	}
	sess := &clusterSession{authContext: ctx}

	// Initial clusterSessions is empty, no session should be found.
	c.Assert(f.getClusterSession(ctx), check.IsNil)

	// Add a session to clusterSessions, getClusterSession should find it.
	clusterSessions.Set(ctx.key(), sess, time.Hour)
	c.Assert(f.getClusterSession(ctx), check.Equals, sess)

	// Close the RemoteSite out-of-band (like when a remote cluster got removed
	// via tctl), getClusterSession should notice this and discard the
	// clusterSession.
	remote.closed = true
	c.Assert(f.getClusterSession(ctx), check.IsNil)
	_, ok := f.clusterSessions.Get(ctx.key())
	c.Assert(ok, check.Equals, false)
}

// mockClient to intercept ProcessKubeCSR requests, record them and return a
// stub response.
type mockClient struct {
	auth.ClientI

	csrResp auth.KubeCSRResponse
	gotCSR  auth.KubeCSR
}

func (c *mockClient) ProcessKubeCSR(csr auth.KubeCSR) (*auth.KubeCSRResponse, error) {
	c.gotCSR = csr
	return &c.csrResp, nil
}

// mockRemoteSite is a reversetunnel.RemoteSite implementation with hardcoded
// name, because there's no easy way to construct a real
// reversetunnel.RemoteSite.
type mockRemoteSite struct {
	reversetunnel.RemoteSite
	name   string
	closed bool
}

func (s mockRemoteSite) GetName() string { return s.name }
func (s mockRemoteSite) IsClosed() bool  { return s.closed }
