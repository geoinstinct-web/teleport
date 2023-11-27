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
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/windows"
	"github.com/gravitational/teleport/lib/utils"
)

// TestDiscoveryLDAPFilter verifies that WindowsService produces a valid
// LDAP filter when given valid configuration.
func TestDiscoveryLDAPFilter(t *testing.T) {
	for _, test := range []struct {
		desc    string
		filters []string
		assert  require.ErrorAssertionFunc
	}{
		{
			desc:   "OK - no custom filters",
			assert: require.NoError,
		},
		{
			desc:    "OK - custom filters",
			filters: []string{"(computerName=test)", "(location=Oakland)"},
			assert:  require.NoError,
		},
		{
			desc:    "NOK - invalid custom filter",
			filters: []string{"invalid"},
			assert:  require.Error,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			s := &WindowsService{
				cfg: WindowsServiceConfig{
					DiscoveryLDAPFilters: test.filters,
				},
			}

			filter := s.ldapSearchFilter()
			_, err := ldap.CompileFilter(filter)
			test.assert(t, err)
		})
	}
}

func TestAppliesLDAPLabels(t *testing.T) {
	l := make(map[string]string)
	entry := ldap.NewEntry("CN=test,DC=example,DC=com", map[string][]string{
		windows.AttrDNSHostName:       {"foo.example.com"},
		windows.AttrName:              {"foo"},
		windows.AttrOS:                {"Windows Server"},
		windows.AttrOSVersion:         {"6.1"},
		windows.AttrDistinguishedName: {"CN=foo,OU=IT,DC=goteleport,DC=com"},
		windows.AttrCommonName:        {"foo"},
		"bar":                         {"baz"},
		"quux":                        {""},
	})

	s := &WindowsService{
		cfg: WindowsServiceConfig{
			DiscoveryLDAPAttributeLabels: []string{"bar"},
		},
	}
	s.applyLabelsFromLDAP(entry, l)

	// check default labels
	require.Equal(t, types.OriginDynamic, l[types.OriginLabel])
	require.Equal(t, "foo.example.com", l[types.DiscoveryLabelWindowsDNSHostName])
	require.Equal(t, "foo", l[types.DiscoveryLabelWindowsComputerName])
	require.Equal(t, "Windows Server", l[types.DiscoveryLabelWindowsOS])
	require.Equal(t, "6.1", l[types.DiscoveryLabelWindowsOSVersion])

	// check OU label
	require.Equal(t, "OU=IT,DC=goteleport,DC=com", l[types.DiscoveryLabelWindowsOU])

	// check custom labels
	require.Equal(t, "baz", l["ldap/bar"])
	require.Empty(t, l["ldap/quux"])
}

func TestLabelsDomainControllers(t *testing.T) {
	s := &WindowsService{}
	for _, test := range []struct {
		desc   string
		entry  *ldap.Entry
		assert require.BoolAssertionFunc
	}{
		{
			desc: "DC",
			entry: ldap.NewEntry("CN=test,DC=example,DC=com", map[string][]string{
				windows.AttrPrimaryGroupID: {windows.WritableDomainControllerGroupID},
			}),
			assert: require.True,
		},
		{
			desc: "RODC",
			entry: ldap.NewEntry("CN=test,DC=example,DC=com", map[string][]string{
				windows.AttrPrimaryGroupID: {windows.ReadOnlyDomainControllerGroupID},
			}),
			assert: require.True,
		},
		{
			desc: "computer",
			entry: ldap.NewEntry("CN=test,DC=example,DC=com", map[string][]string{
				windows.AttrPrimaryGroupID: {"515"},
			}),
			assert: require.False,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			l := make(map[string]string)
			s.applyLabelsFromLDAP(test.entry, l)

			b, _ := strconv.ParseBool(l[types.DiscoveryLabelWindowsIsDomainController])
			test.assert(t, b)
		})
	}
}

// TestDNSErrors verifies that errors are handled quickly
// and do not block discovery for too long.
func TestDNSErrors(t *testing.T) {
	logger := utils.NewLoggerForTests()
	logger.SetLevel(logrus.PanicLevel)
	logger.SetOutput(io.Discard)

	s := &WindowsService{
		cfg: WindowsServiceConfig{
			Log:   logger,
			Clock: clockwork.NewRealClock(),
		},
		dnsResolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, errors.New("this resolver always fails")
			},
		},
	}

	start := time.Now()
	_, err := s.lookupDesktop(context.Background(), "$invalid hostname")
	require.Less(t, time.Since(start), dnsQueryTimeout-1*time.Second)
	require.Error(t, err)
}
