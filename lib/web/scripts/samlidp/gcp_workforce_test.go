/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package samlidp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSAMLIdPBuildScriptCheckAndSetDefaults(t *testing.T) {
	tests := []struct {
		name             string
		orgID            string
		poolName         string
		poolProviderName string
		errAssertion     require.ErrorAssertionFunc
	}{
		{
			name:  "empty organization id",
			orgID: "",
			errAssertion: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorContains(t, err, "required")
			},
		},
		{
			name:  "organization id with alphabet",
			orgID: "123abc123",
			errAssertion: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorContains(t, err, "numeric value")
			},
		},
		{
			name:             "valid organization name",
			orgID:            "123423452",
			poolName:         "test-pool-name",
			poolProviderName: "test-pool-provider-name",
			errAssertion:     require.NoError,
		},
		{
			name:     "empty pool name",
			orgID:    "123423452",
			poolName: "",
			errAssertion: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorContains(t, err, "empty")
			},
		},
		{
			name:             "empty pool name",
			orgID:            "123423452",
			poolName:         "test-pool-name",
			poolProviderName: "test-pool-provider-name",
			errAssertion:     require.NoError,
		},
		{
			name:             "empty pool provider name",
			orgID:            "123423452",
			poolName:         "test-pool-name",
			poolProviderName: "",
			errAssertion: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorContains(t, err, "empty")
			},
		},
		{
			name:             "empty pool name",
			orgID:            "123423452",
			poolName:         "test-pool-name",
			poolProviderName: "test-pool-provider-name",
			errAssertion:     require.NoError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := BuildScript(GCPWorkforceConfigParams{
				OrgID:            test.orgID,
				PoolName:         test.poolName,
				PoolProviderName: test.poolProviderName,
			})
			test.errAssertion(t, err)
		})
	}
}

func TestValidateGCPResourceName(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{
			name:  "empty name",
			value: "",
		},
		{
			name:  "longer than 63 character",
			value: "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij",
		},
		{
			name:  "starts with number",
			value: "1abcde",
		},
		{
			name:  "contains underscore",
			value: "abcde_abcde",
		},
		{
			name:  "contains captial letter",
			value: "abcdeABCDEabcde",
		},
		{
			name:  "contains hyphen at the end",
			value: "abcde-",
		},
		{
			name:  "contains asterisk at the end",
			value: "abc*de",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateGCPResourceName(test.value)
			require.Error(t, err)
		})
	}
}
