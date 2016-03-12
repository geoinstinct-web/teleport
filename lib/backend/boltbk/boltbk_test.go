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
package boltbk

import (
	"path/filepath"
	"testing"

	"github.com/gravitational/teleport/lib/backend/test"
	"github.com/gravitational/teleport/lib/utils"

	. "gopkg.in/check.v1"
)

func TestBolt(t *testing.T) {
	utils.InitLoggerForTests()
	TestingT(t)
}

type BoltSuite struct {
	bk    *BoltBackend
	suite test.BackendSuite
	dir   string
}

var _ = Suite(&BoltSuite{})

func (s *BoltSuite) SetUpTest(c *C) {
	s.dir = c.MkDir()

	var err error
	s.bk, err = New(filepath.Join(s.dir, "db"))
	c.Assert(err, IsNil)

	s.suite.ChangesC = make(chan interface{})
	s.suite.B = s.bk
}

func (s *BoltSuite) TearDownTest(c *C) {
	c.Assert(s.bk.Close(), IsNil)
}

func (s *BoltSuite) TestBasicCRUD(c *C) {
	s.suite.BasicCRUD(c)
}

func (s *BoltSuite) TestCompareAndSwap(c *C) {
	s.suite.CompareAndSwap(c)
}

func (s *BoltSuite) TestExpiration(c *C) {
	s.suite.Expiration(c)
}

func (s *BoltSuite) TestRenewal(c *C) {
	s.suite.Renewal(c)
}

func (s *BoltSuite) TestCreate(c *C) {
	s.suite.Create(c)
}

func (s *BoltSuite) TestLock(c *C) {
	s.suite.Locking(c)
}

func (s *BoltSuite) TestValueAndTTL(c *C) {
	s.suite.ValueAndTTl(c)
}
