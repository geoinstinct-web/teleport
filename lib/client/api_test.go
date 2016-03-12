/*
Copyright 2016 Gravitational, Inc.

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
package client

import (
	"github.com/gravitational/teleport/lib/utils"
	"gopkg.in/check.v1"
	"testing"
)

// register test suite
type APITestSuite struct {
}

// bootstrap check
func TestClientAPI(t *testing.T) {
	utils.InitLoggerForTests()
	check.TestingT(t)
}

var _ = check.Suite(&APITestSuite{})

func (s *APITestSuite) SetUpSuite(c *check.C) {
}

func (s *APITestSuite) TestConfig(c *check.C) {
	var conf Config
	c.Assert(conf.ProxySpecified(), check.Equals, false)
	conf.ProxyHost = "example.org"
	c.Assert(conf.ProxySpecified(), check.Equals, true)
	c.Assert(conf.ProxyHostPort(12), check.Equals, "example.org:12")
}

func (s *APITestSuite) TestParseLabels(c *check.C) {
	// valid spec
	m, err := ParseLabelSpec(`type="database";" role"=master,ver="mongoDB v1,2"`)
	c.Assert(m, check.NotNil)
	c.Assert(err, check.IsNil)
	c.Assert(m, check.HasLen, 3)
	c.Assert(m["role"], check.Equals, "master")
	c.Assert(m["type"], check.Equals, "database")
	c.Assert(m["ver"], check.Equals, "mongoDB v1,2")
	// invalid specs
	m, err = ParseLabelSpec(`type="database,"role"=master,ver="mongoDB v1,2"`)
	c.Assert(m, check.IsNil)
	c.Assert(err, check.NotNil)
	m, err = ParseLabelSpec(`type="database",role,master`)
	c.Assert(m, check.IsNil)
	c.Assert(err, check.NotNil)
}
