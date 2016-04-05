// +build test

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

package services

import (
	"sync/atomic"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services/suite"

	"github.com/gokyle/hotp"
	"golang.org/x/crypto/ssh"

	. "gopkg.in/check.v1"
)

// NewTestCA returns new test authority with a test key as a public and
// signing key
func NewTestCA(caType CertAuthType, domainName string) *CertAuthority {
	keyBytes := suite.PEMBytes["rsa"]
	key, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		panic(err)
	}
	pubKey := key.PublicKey()

	return &CertAuthority{
		Type:         caType,
		DomainName:   domainName,
		CheckingKeys: [][]byte{ssh.MarshalAuthorizedKey(pubKey)},
		SigningKeys:  [][]byte{keyBytes},
	}
}

type ServicesTestSuite struct {
	CAS           *CAService
	LockS         *LockService
	PresenceS     *PresenceService
	ProvisioningS *ProvisioningService
	WebS          *WebService
	ChangesC      chan interface{}
}

func NewServicesTestSuite(backend backend.Backend) *ServicesTestSuite {
	s := ServicesTestSuite{}
	s.CAS = NewCAService(backend)
	s.LockS = NewLockService(backend)
	s.PresenceS = NewPresenceService(backend)
	s.ProvisioningS = NewProvisioningService(backend)
	s.WebS = NewWebService(backend)
	s.ChangesC = make(chan interface{})
	return &s
}

func (s *ServicesTestSuite) collectChanges(c *C, expected int) []interface{} {
	changes := make([]interface{}, expected)
	for i := range changes {
		select {
		case changes[i] = <-s.ChangesC:
			// successfully collected changes
		case <-time.After(2 * time.Second):
			c.Fatalf("Timeout occured waiting for events")
		}
	}
	return changes
}

func (s *ServicesTestSuite) expectChanges(c *C, expected ...interface{}) {
	changes := s.collectChanges(c, len(expected))
	for i, ch := range changes {
		c.Assert(ch, DeepEquals, expected[i])
	}
}

func (s *ServicesTestSuite) UsersCRUD(c *C) {
	u, err := s.WebS.GetUsers()
	c.Assert(err, IsNil)
	c.Assert(len(u), Equals, 0)

	c.Assert(s.WebS.UpsertPasswordHash("user1", []byte("hash")), IsNil)
	c.Assert(s.WebS.UpsertPasswordHash("user2", []byte("hash2")), IsNil)

	u, err = s.WebS.GetUsers()
	c.Assert(err, IsNil)
	c.Assert(toSet(u), DeepEquals, map[string]User{"user1": User{Name: "user1"}, "user2": User{Name: "user2"}})

	out, err := s.WebS.GetUser("user1")
	c.Assert(err, IsNil)
	c.Assert(*out, DeepEquals, User{Name: "user1"})

	user := User{Name: "user1", AllowedLogins: []string{"admin", "root"}}
	c.Assert(s.WebS.UpsertUser(user), IsNil)

	out, err = s.WebS.GetUser("user1")
	c.Assert(err, IsNil)
	c.Assert(*out, DeepEquals, user)

	user.AllowedLogins = nil
	c.Assert(s.WebS.UpsertUser(user), IsNil)

	out, err = s.WebS.GetUser("user1")
	c.Assert(err, IsNil)
	c.Assert(*out, DeepEquals, user)

	c.Assert(s.WebS.DeleteUser("user1"), IsNil)

	u, err = s.WebS.GetUsers()
	c.Assert(err, IsNil)
	c.Assert(toSet(u), DeepEquals, map[string]User{"user2": User{Name: "user2"}})

	err = s.WebS.DeleteUser("user1")
	c.Assert(teleport.IsNotFound(err), Equals, true, Commentf("unexpected %T %#v", err, err))

	// bad username
	err = s.WebS.UpsertUser(User{Name: ""})
	c.Assert(teleport.IsBadParameter(err), Equals, true, Commentf("expected bad parameter error, got %T", err))

	// bad allowed login
	err = s.WebS.UpsertUser(User{Name: "bob", AllowedLogins: []string{"oops  typo!"}})
	c.Assert(teleport.IsBadParameter(err), Equals, true, Commentf("expected bad parameter error, got %T", err))
}

func (s *ServicesTestSuite) CertAuthCRUD(c *C) {
	ca := NewTestCA(UserCA, "example.com")
	c.Assert(s.CAS.UpsertCertAuthority(
		*ca, backend.Forever), IsNil)

	out, err := s.CAS.GetCertAuthority(*ca.ID(), true)
	c.Assert(err, IsNil)
	c.Assert(out, DeepEquals, ca)

	cas, err := s.CAS.GetCertAuthorities(UserCA, false)
	c.Assert(err, IsNil)
	ca2 := *ca
	ca2.SigningKeys = nil
	c.Assert(cas[0], DeepEquals, &ca2)

	cas, err = s.CAS.GetCertAuthorities(UserCA, true)
	c.Assert(err, IsNil)
	c.Assert(cas[0], DeepEquals, ca)

	err = s.CAS.DeleteCertAuthority(*ca.ID())
	c.Assert(err, IsNil)
}

func (s *ServicesTestSuite) ServerCRUD(c *C) {
	out, err := s.PresenceS.GetNodes()
	c.Assert(err, IsNil)
	c.Assert(len(out), Equals, 0)

	srv := Server{ID: "srv1", Addr: "localhost:2022"}
	c.Assert(s.PresenceS.UpsertNode(srv, 0), IsNil)

	out, err = s.PresenceS.GetNodes()
	c.Assert(err, IsNil)
	c.Assert(out, DeepEquals, []Server{srv})

	out, err = s.PresenceS.GetProxies()
	c.Assert(err, IsNil)
	c.Assert(len(out), Equals, 0)

	proxy := Server{ID: "proxy1", Addr: "localhost:2023"}
	c.Assert(s.PresenceS.UpsertProxy(proxy, 0), IsNil)

	out, err = s.PresenceS.GetProxies()
	c.Assert(err, IsNil)
	c.Assert(out, DeepEquals, []Server{proxy})

	out, err = s.PresenceS.GetAuthServers()
	c.Assert(err, IsNil)
	c.Assert(len(out), Equals, 0)

	auth := Server{ID: "auth1", Addr: "localhost:2025"}
	c.Assert(s.PresenceS.UpsertAuthServer(auth, 0), IsNil)

	out, err = s.PresenceS.GetAuthServers()
	c.Assert(err, IsNil)
	c.Assert(out, DeepEquals, []Server{auth})
}

func (s *ServicesTestSuite) ReverseTunnelsCRUD(c *C) {
	out, err := s.PresenceS.GetReverseTunnels()
	c.Assert(err, IsNil)
	c.Assert(len(out), Equals, 0)

	tunnel := ReverseTunnel{DomainName: "example.com", DialAddrs: []string{"example.com:2023"}}
	c.Assert(s.PresenceS.UpsertReverseTunnel(tunnel, 0), IsNil)

	out, err = s.PresenceS.GetReverseTunnels()
	c.Assert(err, IsNil)
	c.Assert(out, DeepEquals, []ReverseTunnel{tunnel})

	err = s.PresenceS.DeleteReverseTunnel(tunnel.DomainName)
	c.Assert(err, IsNil)

	out, err = s.PresenceS.GetReverseTunnels()
	c.Assert(err, IsNil)
	c.Assert(len(out), Equals, 0)

	err = s.PresenceS.UpsertReverseTunnel(ReverseTunnel{DomainName: " bad domain", DialAddrs: []string{"example.com:2023"}}, 0)
	c.Assert(teleport.IsBadParameter(err), Equals, true, Commentf("%#v", err))

	err = s.PresenceS.UpsertReverseTunnel(ReverseTunnel{DomainName: "example.com", DialAddrs: []string{"bad address"}}, 0)
	c.Assert(teleport.IsBadParameter(err), Equals, true, Commentf("%#v", err))

	err = s.PresenceS.UpsertReverseTunnel(ReverseTunnel{DomainName: "example.com"}, 0)
	c.Assert(teleport.IsBadParameter(err), Equals, true, Commentf("%#v", err))
}

func (s *ServicesTestSuite) PasswordHashCRUD(c *C) {
	_, err := s.WebS.GetPasswordHash("user1")
	c.Assert(err, FitsTypeOf, &teleport.NotFoundError{})

	err = s.WebS.UpsertPasswordHash("user1", []byte("hello123"))
	c.Assert(err, IsNil)

	hash, err := s.WebS.GetPasswordHash("user1")
	c.Assert(err, IsNil)
	c.Assert(hash, DeepEquals, []byte("hello123"))

	err = s.WebS.UpsertPasswordHash("user1", []byte("hello321"))
	c.Assert(err, IsNil)

	hash, err = s.WebS.GetPasswordHash("user1")
	c.Assert(err, IsNil)
	c.Assert(hash, DeepEquals, []byte("hello321"))
}

func (s *ServicesTestSuite) WebSessionCRUD(c *C) {
	_, err := s.WebS.GetWebSession("user1", "sid1")
	c.Assert(err, FitsTypeOf, &teleport.NotFoundError{})

	dt := time.Date(2015, 6, 5, 4, 3, 2, 1, time.UTC).UTC()
	ws := WebSession{
		Pub:     []byte("pub123"),
		Priv:    []byte("priv123"),
		Expires: dt,
	}
	err = s.WebS.UpsertWebSession("user1", "sid1", ws, 0)
	c.Assert(err, IsNil)

	out, err := s.WebS.GetWebSession("user1", "sid1")
	c.Assert(err, IsNil)
	c.Assert(out, DeepEquals, &ws)

	ws1 := WebSession{Pub: []byte("pub321"), Priv: []byte("priv321"), Expires: dt}
	err = s.WebS.UpsertWebSession("user1", "sid1", ws1, 0)
	c.Assert(err, IsNil)

	out2, err := s.WebS.GetWebSession("user1", "sid1")
	c.Assert(err, IsNil)
	c.Assert(out2, DeepEquals, &ws1)

	keys, err := s.WebS.GetWebSessionsKeys("user1")
	c.Assert(err, IsNil)
	c.Assert(keys[0].Value, DeepEquals, out2.Pub)

	c.Assert(s.WebS.DeleteWebSession("user1", "sid1"), IsNil)

	_, err = s.WebS.GetWebSession("user1", "sid1")
	c.Assert(err, FitsTypeOf, &teleport.NotFoundError{})
}

func (s *ServicesTestSuite) Locking(c *C) {
	tok1 := "token1"
	tok2 := "token2"

	c.Assert(s.LockS.ReleaseLock(tok1), FitsTypeOf, &teleport.NotFoundError{})

	c.Assert(s.LockS.AcquireLock(tok1, 30*time.Second), IsNil)
	x := int32(7)
	go func() {
		atomic.StoreInt32(&x, 9)
		c.Assert(s.LockS.ReleaseLock(tok1), IsNil)
	}()
	c.Assert(s.LockS.AcquireLock(tok1, 0), IsNil)
	atomic.AddInt32(&x, 9)

	c.Assert(atomic.LoadInt32(&x), Equals, int32(18))
	c.Assert(s.LockS.ReleaseLock(tok1), IsNil)

	c.Assert(s.LockS.AcquireLock(tok1, 0), IsNil)
	atomic.StoreInt32(&x, 7)
	go func() {
		atomic.StoreInt32(&x, 9)
		c.Assert(s.LockS.ReleaseLock(tok1), IsNil)
	}()
	c.Assert(s.LockS.AcquireLock(tok1, 0), IsNil)
	atomic.AddInt32(&x, 9)
	c.Assert(atomic.LoadInt32(&x), Equals, int32(18))
	c.Assert(s.LockS.ReleaseLock(tok1), IsNil)

	y := int32(0)
	go func() {
		c.Assert(s.LockS.AcquireLock(tok1, 0), IsNil)
		c.Assert(s.LockS.AcquireLock(tok2, 0), IsNil)

		c.Assert(s.LockS.ReleaseLock(tok1), IsNil)
		c.Assert(s.LockS.ReleaseLock(tok2), IsNil)
		atomic.StoreInt32(&y, 15)
	}()

	time.Sleep(1 * time.Second)
	c.Assert(atomic.LoadInt32(&y), Equals, int32(15))

	c.Assert(s.LockS.ReleaseLock(tok1), FitsTypeOf, &teleport.NotFoundError{})
}

func (s *ServicesTestSuite) TokenCRUD(c *C) {
	_, err := s.ProvisioningS.GetToken("token")
	c.Assert(err, FitsTypeOf, &teleport.NotFoundError{})

	c.Assert(s.ProvisioningS.UpsertToken("token", "RoleExample", 0), IsNil)

	token, err := s.ProvisioningS.GetToken("token")
	c.Assert(token.Role, Equals, "RoleExample")
	c.Assert(token.TTL > 0 && token.TTL <= defaults.MaxProvisioningTokenTTL, Equals, true, Commentf("%v", token.TTL))
	c.Assert(err, IsNil)

	c.Assert(s.ProvisioningS.DeleteToken("token"), IsNil)

	_, err = s.ProvisioningS.GetToken("token")
	c.Assert(err, FitsTypeOf, &teleport.NotFoundError{})

	outputToken, err := JoinTokenRole("token1", "Auth")
	c.Assert(err, IsNil)

	tok, role, err := SplitTokenRole(outputToken)
	c.Assert(err, IsNil)
	c.Assert(tok, Equals, "token1")
	c.Assert(role, Equals, "Auth")

	c.Assert(s.ProvisioningS.UpsertToken("token2", "RoleExample", 2*defaults.MaxProvisioningTokenTTL), IsNil)

	token, err = s.ProvisioningS.GetToken("token2")
	c.Assert(token.Role, Equals, "RoleExample")
	c.Assert(token.TTL > 0 && token.TTL <= defaults.MaxProvisioningTokenTTL, Equals, true, Commentf("%v", token.TTL))
	c.Assert(err, IsNil)
}

func (s *ServicesTestSuite) PasswordCRUD(c *C) {
	pass := []byte("abc123")

	err := s.WebS.CheckPassword("user1", pass, "123456")
	c.Assert(err, NotNil)

	hotpURL, _, err := s.WebS.UpsertPassword("user1", pass)
	c.Assert(err, IsNil)

	otp, label, err := hotp.FromURL(hotpURL)
	c.Assert(err, IsNil)
	c.Assert(label, Equals, "user1")
	otp.Increment()

	token1 := otp.OTP()
	c.Assert(s.WebS.CheckPassword("user1", pass, "123456"), FitsTypeOf, &teleport.BadParameterError{})
	c.Assert(s.WebS.CheckPassword("user1", pass, token1), IsNil)
	c.Assert(s.WebS.CheckPassword("user1", pass, token1), FitsTypeOf, &teleport.BadParameterError{})

	token2 := otp.OTP()
	c.Assert(s.WebS.CheckPassword("user1", []byte("abc123123"), token2), FitsTypeOf, &teleport.BadParameterError{})
	c.Assert(s.WebS.CheckPassword("user1", pass, "123456"), FitsTypeOf, &teleport.BadParameterError{})
	c.Assert(s.WebS.CheckPassword("user1", pass, token2), IsNil)
	c.Assert(s.WebS.CheckPassword("user1", pass, token1), FitsTypeOf, &teleport.BadParameterError{})

	_ = otp.OTP()
	_ = otp.OTP()
	_ = otp.OTP()
	token6 := otp.OTP()
	token7 := otp.OTP()
	c.Assert(s.WebS.CheckPassword("user1", pass, token7), FitsTypeOf, &teleport.BadParameterError{})
	c.Assert(s.WebS.CheckPassword("user1", pass, token6), IsNil)
	c.Assert(s.WebS.CheckPassword("user1", pass, "123456"), FitsTypeOf, &teleport.BadParameterError{})
	c.Assert(s.WebS.CheckPassword("user1", pass, token7), IsNil)

	_ = otp.OTP()
	token9 := otp.OTP()
	c.Assert(s.WebS.CheckPassword("user1", pass, token9), IsNil)

}

func (s *ServicesTestSuite) PasswordGarbage(c *C) {
	garbage := [][]byte{
		nil,
		make([]byte, defaults.MaxPasswordLength+1),
		make([]byte, defaults.MinPasswordLength-1),
	}
	for _, g := range garbage {
		err := s.WebS.CheckPassword("user1", g, "123456")
		c.Assert(err, NotNil)
	}
}

func toSet(vals []User) map[string]User {
	out := make(map[string]User, len(vals))
	for _, v := range vals {
		out[v.Name] = v
	}
	return out
}
