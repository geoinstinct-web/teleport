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
	"path/filepath"
	"testing"

	"github.com/gravitational/teleport/lib/backend/boltbk"
	"github.com/gravitational/teleport/lib/utils"
	. "gopkg.in/check.v1"
)

func TestServices(t *testing.T) {
	utils.InitLoggerForTests()
	TestingT(t)
}

type BoltSuite struct {
	bk    *boltbk.BoltBackend
	suite *ServicesTestSuite
	dir   string
}

var _ = Suite(&BoltSuite{})

func (s *BoltSuite) SetUpTest(c *C) {
	s.dir = c.MkDir()

	var err error
	s.bk, err = boltbk.New(filepath.Join(s.dir, "db"))
	c.Assert(err, IsNil)
	s.suite = NewServicesTestSuite(s.bk)
}

func (s *BoltSuite) TearDownTest(c *C) {
	c.Assert(s.bk.Close(), IsNil)
}

func (s *BoltSuite) TestUserCACRUD(c *C) {
	s.suite.CertAuthCRUD(c)
}

func (s *BoltSuite) TestServerCRUD(c *C) {
	s.suite.ServerCRUD(c)
}

func (s *BoltSuite) TestUsersCRUD(c *C) {
	s.suite.UsersCRUD(c)
}

func (s *BoltSuite) TestPasswordHashCRUD(c *C) {
	s.suite.PasswordHashCRUD(c)
}

func (s *BoltSuite) TestPasswordAndHotpCRUD(c *C) {
	s.suite.PasswordCRUD(c)
}

func (s *BoltSuite) TestPasswordGarbage(c *C) {
	s.suite.PasswordGarbage(c)
}

func (s *BoltSuite) TestWebSessionCRUD(c *C) {
	s.suite.WebSessionCRUD(c)
}

func (s *BoltSuite) TestWebTunCRUD(c *C) {
	s.suite.WebTunCRUD(c)
}

func (s *BoltSuite) TestLocking(c *C) {
	s.suite.Locking(c)
}

func (s *BoltSuite) TestToken(c *C) {
	s.suite.TokenCRUD(c)
}
