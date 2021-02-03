/*
Copyright 2015 Gravitational, Inc.

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

package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/auth/u2f"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/lite"
	"github.com/gravitational/teleport/lib/backend/memory"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	. "gopkg.in/check.v1"
)

type AuthInitSuite struct {
	tempDir string
}

var _ = Suite(&AuthInitSuite{})

func (s *AuthInitSuite) SetUpSuite(c *C) {
	utils.InitLoggerForTests(testing.Verbose())
}

func (s *AuthInitSuite) SetUpTest(c *C) {
	var err error
	s.tempDir, err = ioutil.TempDir("", "auth-init-test-")
	c.Assert(err, IsNil)
}

func (s *AuthInitSuite) TearDownTest(c *C) {
	err := os.RemoveAll(s.tempDir)
	c.Assert(err, IsNil)
}

// TestReadIdentity makes parses identity from private key and certificate
// and checks that all parameters are valid
func (s *AuthInitSuite) TestReadIdentity(c *C) {
	clock := clockwork.NewFakeClock()
	t := testauthority.NewWithClock(clock)
	priv, pub, err := t.GenerateKeyPair("")
	c.Assert(err, IsNil)

	cert, err := t.GenerateHostCert(services.HostCertParams{
		PrivateCASigningKey: priv,
		CASigningAlg:        defaults.CASignatureAlgorithm,
		PublicHostKey:       pub,
		HostID:              "id1",
		NodeName:            "node-name",
		ClusterName:         "example.com",
		Roles:               teleport.Roles{teleport.RoleNode},
		TTL:                 0,
	})
	c.Assert(err, IsNil)

	id, err := ReadSSHIdentityFromKeyPair(priv, cert)
	c.Assert(err, IsNil)
	c.Assert(id.ClusterName, Equals, "example.com")
	c.Assert(id.ID, DeepEquals, IdentityID{HostUUID: "id1.example.com", Role: teleport.RoleNode})
	c.Assert(id.CertBytes, DeepEquals, cert)
	c.Assert(id.KeyBytes, DeepEquals, priv)

	// test TTL by converting the generated cert to text -> back and making sure ExpireAfter is valid
	ttl := 10 * time.Second
	expiryDate := clock.Now().Add(ttl)
	bytes, err := t.GenerateHostCert(services.HostCertParams{
		PrivateCASigningKey: priv,
		CASigningAlg:        defaults.CASignatureAlgorithm,
		PublicHostKey:       pub,
		HostID:              "id1",
		NodeName:            "node-name",
		ClusterName:         "example.com",
		Roles:               teleport.Roles{teleport.RoleNode},
		TTL:                 ttl,
	})
	c.Assert(err, IsNil)
	pk, _, _, _, err := ssh.ParseAuthorizedKey(bytes)
	c.Assert(err, IsNil)
	copy, ok := pk.(*ssh.Certificate)
	c.Assert(ok, Equals, true)
	c.Assert(uint64(expiryDate.Unix()), Equals, copy.ValidBefore)
}

func (s *AuthInitSuite) TestBadIdentity(c *C) {
	t := testauthority.New()
	priv, pub, err := t.GenerateKeyPair("")
	c.Assert(err, IsNil)

	// bad cert type
	_, err = ReadSSHIdentityFromKeyPair(priv, pub)
	c.Assert(trace.IsBadParameter(err), Equals, true, Commentf("%#v", err))

	// missing authority domain
	cert, err := t.GenerateHostCert(services.HostCertParams{
		PrivateCASigningKey: priv,
		CASigningAlg:        defaults.CASignatureAlgorithm,
		PublicHostKey:       pub,
		HostID:              "id2",
		NodeName:            "",
		ClusterName:         "",
		Roles:               teleport.Roles{teleport.RoleNode},
		TTL:                 0,
	})
	c.Assert(err, IsNil)

	_, err = ReadSSHIdentityFromKeyPair(priv, cert)
	c.Assert(trace.IsBadParameter(err), Equals, true, Commentf("%#v", err))

	// missing host uuid
	cert, err = t.GenerateHostCert(services.HostCertParams{
		PrivateCASigningKey: priv,
		CASigningAlg:        defaults.CASignatureAlgorithm,
		PublicHostKey:       pub,
		HostID:              "example.com",
		NodeName:            "",
		ClusterName:         "",
		Roles:               teleport.Roles{teleport.RoleNode},
		TTL:                 0,
	})
	c.Assert(err, IsNil)

	_, err = ReadSSHIdentityFromKeyPair(priv, cert)
	c.Assert(trace.IsBadParameter(err), Equals, true, Commentf("%#v", err))

	// unrecognized role
	cert, err = t.GenerateHostCert(services.HostCertParams{
		PrivateCASigningKey: priv,
		CASigningAlg:        defaults.CASignatureAlgorithm,
		PublicHostKey:       pub,
		HostID:              "example.com",
		NodeName:            "",
		ClusterName:         "id1",
		Roles:               teleport.Roles{teleport.Role("bad role")},
		TTL:                 0,
	})
	c.Assert(err, IsNil)

	_, err = ReadSSHIdentityFromKeyPair(priv, cert)
	c.Assert(trace.IsBadParameter(err), Equals, true, Commentf("%#v", err))
}

// TestAuthPreference ensures that the act of creating an AuthServer sets
// the AuthPreference (type and second factor) on the backend.
func (s *AuthInitSuite) TestAuthPreference(c *C) {
	bk, err := lite.New(context.TODO(), backend.Params{"path": s.tempDir})
	c.Assert(err, IsNil)

	ap, err := services.NewAuthPreference(services.AuthPreferenceSpecV2{
		Type:         "local",
		SecondFactor: "u2f",
		U2F: &services.U2F{
			AppID:  "foo",
			Facets: []string{"bar", "baz"},
		},
	})
	c.Assert(err, IsNil)

	clusterName, err := services.NewClusterName(services.ClusterNameSpecV2{
		ClusterName: "me.localhost",
	})
	c.Assert(err, IsNil)
	staticTokens, err := services.NewStaticTokens(services.StaticTokensSpecV2{
		StaticTokens: []services.ProvisionTokenV1{},
	})
	c.Assert(err, IsNil)

	ac := InitConfig{
		DataDir:        s.tempDir,
		HostUUID:       "00000000-0000-0000-0000-000000000000",
		NodeName:       "foo",
		Backend:        bk,
		Authority:      testauthority.New(),
		ClusterConfig:  services.DefaultClusterConfig(),
		ClusterName:    clusterName,
		StaticTokens:   staticTokens,
		AuthPreference: ap,
	}
	as, err := Init(ac)
	c.Assert(err, IsNil)
	defer as.Close()

	cap, err := as.GetAuthPreference()
	c.Assert(err, IsNil)
	c.Assert(cap.GetType(), Equals, "local")
	c.Assert(cap.GetSecondFactor(), Equals, "u2f")
	u, err := cap.GetU2F()
	c.Assert(err, IsNil)
	c.Assert(u.AppID, Equals, "foo")
	c.Assert(u.Facets, DeepEquals, []string{"bar", "baz"})
}

func (s *AuthInitSuite) TestClusterID(c *C) {
	bk, err := lite.New(context.TODO(), backend.Params{"path": c.MkDir()})
	c.Assert(err, IsNil)

	clusterName, err := services.NewClusterName(services.ClusterNameSpecV2{
		ClusterName: "me.localhost",
	})
	c.Assert(err, IsNil)

	authPreference, err := services.NewAuthPreference(services.AuthPreferenceSpecV2{
		Type: "local",
	})
	c.Assert(err, IsNil)

	authServer, err := Init(InitConfig{
		DataDir:        c.MkDir(),
		HostUUID:       "00000000-0000-0000-0000-000000000000",
		NodeName:       "foo",
		Backend:        bk,
		Authority:      testauthority.New(),
		ClusterConfig:  services.DefaultClusterConfig(),
		ClusterName:    clusterName,
		StaticTokens:   services.DefaultStaticTokens(),
		AuthPreference: authPreference,
	})
	c.Assert(err, IsNil)
	defer authServer.Close()

	cc, err := authServer.GetClusterConfig()
	c.Assert(err, IsNil)
	clusterID := cc.GetClusterID()
	c.Assert(clusterID, Not(Equals), "")

	// do it again and make sure cluster ID hasn't changed
	authServer, err = Init(InitConfig{
		DataDir:        c.MkDir(),
		HostUUID:       "00000000-0000-0000-0000-000000000000",
		NodeName:       "foo",
		Backend:        bk,
		Authority:      testauthority.New(),
		ClusterConfig:  services.DefaultClusterConfig(),
		ClusterName:    clusterName,
		StaticTokens:   services.DefaultStaticTokens(),
		AuthPreference: authPreference,
	})
	c.Assert(err, IsNil)
	defer authServer.Close()

	cc, err = authServer.GetClusterConfig()
	c.Assert(err, IsNil)
	c.Assert(cc.GetClusterID(), Equals, clusterID)
}

// TestClusterName ensures that a cluster can not be renamed.
func (s *AuthInitSuite) TestClusterName(c *C) {
	bk, err := lite.New(context.TODO(), backend.Params{"path": c.MkDir()})
	c.Assert(err, IsNil)

	clusterName, err := services.NewClusterName(services.ClusterNameSpecV2{
		ClusterName: "me.localhost",
	})
	c.Assert(err, IsNil)

	authPreference, err := services.NewAuthPreference(services.AuthPreferenceSpecV2{
		Type: "local",
	})
	c.Assert(err, IsNil)

	authServer, err := Init(InitConfig{
		DataDir:        c.MkDir(),
		HostUUID:       "00000000-0000-0000-0000-000000000000",
		NodeName:       "foo",
		Backend:        bk,
		Authority:      testauthority.New(),
		ClusterConfig:  services.DefaultClusterConfig(),
		ClusterName:    clusterName,
		StaticTokens:   services.DefaultStaticTokens(),
		AuthPreference: authPreference,
	})
	c.Assert(err, IsNil)
	defer authServer.Close()

	// Start the auth server with a different cluster name. The auth server
	// should start, but with the original name.
	clusterName, err = services.NewClusterName(services.ClusterNameSpecV2{
		ClusterName: "dev.localhost",
	})
	c.Assert(err, IsNil)

	authServer, err = Init(InitConfig{
		DataDir:        c.MkDir(),
		HostUUID:       "00000000-0000-0000-0000-000000000000",
		NodeName:       "foo",
		Backend:        bk,
		Authority:      testauthority.New(),
		ClusterConfig:  services.DefaultClusterConfig(),
		ClusterName:    clusterName,
		StaticTokens:   services.DefaultStaticTokens(),
		AuthPreference: authPreference,
	})
	c.Assert(err, IsNil)
	defer authServer.Close()

	cn, err := authServer.GetClusterName()
	c.Assert(err, IsNil)
	c.Assert(cn.GetClusterName(), Equals, "me.localhost")
}

func (s *AuthInitSuite) TestCASigningAlg(c *C) {
	bk, err := lite.New(context.TODO(), backend.Params{"path": c.MkDir()})
	c.Assert(err, IsNil)

	clusterName, err := services.NewClusterName(services.ClusterNameSpecV2{
		ClusterName: "me.localhost",
	})
	c.Assert(err, IsNil)

	authPreference, err := services.NewAuthPreference(services.AuthPreferenceSpecV2{
		Type: "local",
	})
	c.Assert(err, IsNil)

	conf := InitConfig{
		DataDir:        c.MkDir(),
		HostUUID:       "00000000-0000-0000-0000-000000000000",
		NodeName:       "foo",
		Backend:        bk,
		Authority:      testauthority.New(),
		ClusterConfig:  services.DefaultClusterConfig(),
		ClusterName:    clusterName,
		StaticTokens:   services.DefaultStaticTokens(),
		AuthPreference: authPreference,
	}

	verifyCAs := func(auth *Server, alg string) {
		hostCAs, err := auth.GetCertAuthorities(services.HostCA, false)
		c.Assert(err, IsNil)
		for _, ca := range hostCAs {
			c.Assert(sshutils.GetSigningAlgName(ca), Equals, alg)
		}
		userCAs, err := auth.GetCertAuthorities(services.UserCA, false)
		c.Assert(err, IsNil)
		for _, ca := range userCAs {
			c.Assert(sshutils.GetSigningAlgName(ca), Equals, alg)
		}
	}

	// Start a new server without specifying a signing alg.
	auth, err := Init(conf)
	c.Assert(err, IsNil)
	verifyCAs(auth, ssh.SigAlgoRSASHA2512)

	c.Assert(auth.Close(), IsNil)

	// Reset the auth server state.
	conf.Backend, err = lite.New(context.TODO(), backend.Params{"path": c.MkDir()})
	c.Assert(err, IsNil)
	conf.DataDir = c.MkDir()

	// Start a new server with non-default signing alg.
	signingAlg := ssh.SigAlgoRSA
	conf.CASigningAlg = &signingAlg
	auth, err = Init(conf)
	c.Assert(err, IsNil)
	defer auth.Close()
	verifyCAs(auth, ssh.SigAlgoRSA)

	// Start again, using a different alg. This should not change the existing
	// CA.
	signingAlg = ssh.SigAlgoRSASHA2256
	auth, err = Init(conf)
	c.Assert(err, IsNil)
	verifyCAs(auth, ssh.SigAlgoRSA)
}

func TestMigrateMFADevices(t *testing.T) {
	ctx := context.Background()
	clock := clockwork.NewFakeClock()

	// Set up an auth server with all prerequisites.
	bk, err := memory.New(memory.Config{Context: ctx})
	require.NoError(t, err)
	authPreference, err := services.NewAuthPreference(services.AuthPreferenceSpecV2{
		Type: "local",
	})
	require.NoError(t, err)
	clusterName, err := services.NewClusterName(services.ClusterNameSpecV2{
		ClusterName: "foo",
	})
	require.NoError(t, err)
	staticTokens, err := services.NewStaticTokens(services.StaticTokensSpecV2{
		StaticTokens: []services.ProvisionTokenV1{},
	})
	require.NoError(t, err)
	ac := InitConfig{
		DataDir:        t.TempDir(),
		HostUUID:       "00000000-0000-0000-0000-000000000000",
		NodeName:       "foo",
		Backend:        bk,
		Authority:      testauthority.New(),
		ClusterConfig:  services.DefaultClusterConfig(),
		ClusterName:    clusterName,
		StaticTokens:   staticTokens,
		AuthPreference: authPreference,
	}
	as, err := Init(ac)
	require.NoError(t, err)
	defer as.Close()
	as.SetClock(clock)

	// Fake credentials and MFA secrets for migration.
	fakePasswordHash := []byte(`$2a$10$Yy.e6BmS2SrGbBDsyDLVkOANZmvjjMR890nUGSXFJHBXWzxe7T44m`)
	totpKey := "totp-key"
	u2fPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	u2fPubKey := u2fPrivKey.PublicKey
	u2fPubKeyBin, err := x509.MarshalPKIXPublicKey(&u2fPubKey)
	require.NoError(t, err)
	u2fKeyHandle := []byte("dummy handle")

	// Create un-migrated users.
	for name, localAuth := range map[string]*backend.Item{
		"no-mfa-user": nil,
		// Insert MFA data in the legacy format by manually writing to the
		// backend. All the code for writing these in lib/services/local was
		// removed.
		"totp-user": {
			Key:   []byte("/web/users/totp-user/totp"),
			Value: []byte(totpKey),
		},
		"u2f-user": {
			Key: []byte("/web/users/u2f-user/u2fregistration"),
			Value: []byte(fmt.Sprintf(`{"keyhandle":%q,"marshalled_pubkey":%q}`,
				base64.StdEncoding.EncodeToString(u2fKeyHandle),
				base64.StdEncoding.EncodeToString(u2fPubKeyBin),
			)),
		},
	} {
		u, err := services.NewUser(name)
		require.NoError(t, err)
		// Set a fake but valid bcrypt password hash.
		u.SetLocalAuth(&types.LocalAuthSecrets{PasswordHash: fakePasswordHash})
		err = as.CreateUser(ctx, u)
		require.NoError(t, err)

		if localAuth != nil {
			_, err = bk.Put(ctx, *localAuth)
			require.NoError(t, err)
		}
	}

	// Run the migration.
	err = migrateMFADevices(ctx, as)
	require.NoError(t, err)

	// Generate expected users with migrated MFA.
	requireNewDevice := func(d *types.MFADevice, err error) []*types.MFADevice {
		require.NoError(t, err)
		return []*types.MFADevice{d}
	}
	wantUsers := []services.User{
		newUserWithAuth(t, "no-mfa-user", &types.LocalAuthSecrets{PasswordHash: fakePasswordHash}),
		newUserWithAuth(t, "totp-user", &types.LocalAuthSecrets{
			PasswordHash: fakePasswordHash,
			TOTPKey:      totpKey,
			MFA:          requireNewDevice(services.NewTOTPDevice("totp", totpKey, clock.Now())),
		}),
		newUserWithAuth(t, "u2f-user", &types.LocalAuthSecrets{
			PasswordHash: fakePasswordHash,
			U2FRegistration: &types.U2FRegistrationData{
				KeyHandle: u2fKeyHandle,
				PubKey:    u2fPubKeyBin,
			},
			MFA: requireNewDevice(u2f.NewDevice("u2f", &u2f.Registration{
				KeyHandle: u2fKeyHandle,
				PubKey:    u2fPubKey,
			}, clock.Now())),
		}),
	}
	cmpOpts := []cmp.Option{
		cmpopts.IgnoreFields(types.UserSpecV2{}, "CreatedBy"),
		cmpopts.IgnoreFields(types.MFADevice{}, "Id"),
		cmpopts.SortSlices(func(a, b types.User) bool { return a.GetName() < b.GetName() }),
	}

	// Check the actual users from the backend.
	users, err := as.GetUsers(true)
	require.NoError(t, err)
	require.Empty(t, cmp.Diff(users, wantUsers, cmpOpts...))

	// A second migration should be a noop.
	err = migrateMFADevices(ctx, as)
	require.NoError(t, err)

	users, err = as.GetUsers(true)
	require.NoError(t, err)
	require.Empty(t, cmp.Diff(users, wantUsers, cmpOpts...))
}

func newUserWithAuth(t *testing.T, name string, auth *types.LocalAuthSecrets) services.User {
	u, err := services.NewUser(name)
	require.NoError(t, err)
	u.SetLocalAuth(auth)
	return u
}
