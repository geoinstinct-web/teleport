/*
Copyright 2015-2019 Gravitational, Inc.

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
	"encoding/json"
	"fmt"
	"testing"

	"github.com/coreos/go-oidc/jose"
	"github.com/google/go-cmp/cmp"
	saml2 "github.com/russellhaering/gosaml2"
	samltypes "github.com/russellhaering/gosaml2/types"
	"github.com/stretchr/testify/require"

	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
)

func TestTraits(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		traitName string
	}{
		// Windows trait names are URLs.
		{
			traitName: "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname",
		},
		// Simple strings are the most common trait names.
		{
			traitName: "user-groups",
		},
	}

	for _, tt := range tests {
		user := &types.UserV2{
			Kind:    types.KindUser,
			Version: types.V2,
			Metadata: types.Metadata{
				Name:      "foo",
				Namespace: apidefaults.Namespace,
			},
			Spec: types.UserSpecV2{
				Traits: map[string][]string{
					tt.traitName: {"foo"},
				},
			},
		}

		data, err := json.Marshal(user)
		require.NoError(t, err)

		_, err = UnmarshalUser(data)
		require.NoError(t, err)
	}
}

type oidcInput struct {
	comment       string
	claims        jose.Claims
	expectedRoles []string
	warnings      []string
}

var oidcTestCases = []struct {
	comment  string
	mappings []types.ClaimMapping
	inputs   []oidcInput
}{
	{
		comment: "no mappings",
		inputs: []oidcInput{
			{
				comment:       "no match",
				claims:        jose.Claims{"a": "b"},
				expectedRoles: nil,
			},
		},
	},
	{
		comment: "simple mappings",
		mappings: []types.ClaimMapping{
			{Claim: "role", Value: "admin", Roles: []string{"admin", "bob"}},
			{Claim: "role", Value: "user", Roles: []string{"user"}},
		},
		inputs: []oidcInput{
			{
				comment:       "no match",
				claims:        jose.Claims{"a": "b"},
				expectedRoles: nil,
			},
			{
				comment:       "no value match",
				claims:        jose.Claims{"role": "b"},
				expectedRoles: nil,
			},
			{
				comment:       "direct admin value match",
				claims:        jose.Claims{"role": "admin"},
				expectedRoles: []string{"admin", "bob"},
			},
			{
				comment:       "direct user value match",
				claims:        jose.Claims{"role": "user"},
				expectedRoles: []string{"user"},
			},
			{
				comment:       "direct user value match with array",
				claims:        jose.Claims{"role": []string{"user"}},
				expectedRoles: []string{"user"},
			},
		},
	},
	{
		comment: "regexp mappings match",
		mappings: []types.ClaimMapping{
			{Claim: "role", Value: "^admin-(.*)$", Roles: []string{"role-$1", "bob"}},
		},
		inputs: []oidcInput{
			{
				comment:       "no match",
				claims:        jose.Claims{"a": "b"},
				expectedRoles: nil,
			},
			{
				comment:       "no match - subprefix",
				claims:        jose.Claims{"role": "adminz"},
				expectedRoles: nil,
			},
			{
				comment:       "value with capture match",
				claims:        jose.Claims{"role": "admin-hello"},
				expectedRoles: []string{"role-hello", "bob"},
			},
			{
				comment:       "multiple value with capture match, deduplication",
				claims:        jose.Claims{"role": []string{"admin-hello", "admin-ola"}},
				expectedRoles: []string{"role-hello", "bob", "role-ola"},
			},
			{
				comment:       "first matches, second does not",
				claims:        jose.Claims{"role": []string{"hello", "admin-ola"}},
				expectedRoles: []string{"role-ola", "bob"},
			},
		},
	},
	{
		comment: "regexp compilation",
		mappings: []types.ClaimMapping{
			{Claim: "role", Value: `^admin-(?!)$`, Roles: []string{"admin"}}, // "?!" is invalid.
			{Claim: "role", Value: "^admin-(.*)$", Roles: []string{"role-$1", "bob"}},
			{Claim: "role", Value: `^admin2-(?!)$`, Roles: []string{"admin2"}}, // "?!" is invalid.
		},
		inputs: []oidcInput{
			{
				comment:       "invalid regexp",
				claims:        jose.Claims{"role": []string{"admin-hello", "dev"}},
				expectedRoles: []string{"role-hello", "bob"},
				warnings: []string{
					`case-insensitive expression "^admin-(?!)$" is not a valid regexp`,
					`case-insensitive expression "^admin2-(?!)$" is not a valid regexp`,
				},
			},
			{
				comment:       "regexp are not compiled if not needed",
				claims:        jose.Claims{},
				expectedRoles: nil,
				// if the regexp were compiled, we would have the same warnings as above
				warnings: nil,
			},
		},
	},
	{
		comment: "empty expands are skipped",
		mappings: []types.ClaimMapping{
			{Claim: "role", Value: "^admin-(.*)$", Roles: []string{"$2", "bob"}},
		},
		inputs: []oidcInput{
			{
				comment:       "value with capture match",
				claims:        jose.Claims{"role": "admin-hello"},
				expectedRoles: []string{"bob"},
			},
		},
	},
	{
		comment: "glob wildcard match",
		mappings: []types.ClaimMapping{
			{Claim: "role", Value: "*", Roles: []string{"admin"}},
		},
		inputs: []oidcInput{
			{
				comment:       "empty value match",
				claims:        jose.Claims{"role": ""},
				expectedRoles: []string{"admin"},
			},
			{
				comment:       "any value match",
				claims:        jose.Claims{"role": "zz"},
				expectedRoles: []string{"admin"},
			},
		},
	},
	{
		comment: "Whitespace/dashes",
		mappings: []types.ClaimMapping{
			{Claim: "groups", Value: "DemoCorp - Backend Engineers", Roles: []string{"backend"}},
			{Claim: "groups", Value: "DemoCorp - SRE Managers", Roles: []string{"approver"}},
			{Claim: "groups", Value: "DemoCorp - SRE", Roles: []string{"approver"}},
			{Claim: "groups", Value: "DemoCorp Infrastructure", Roles: []string{"approver", "backend"}},
		},
		inputs: []oidcInput{
			{
				comment: "Matches multiple groups",
				claims: jose.Claims{
					"groups": []string{"DemoCorp - Backend Engineers", "DemoCorp Infrastructure"},
				},
				expectedRoles: []string{"backend", "approver"},
			},
			{
				comment: "Matches one group",
				claims: jose.Claims{
					"groups": []string{"DemoCorp - SRE"},
				},
				expectedRoles: []string{"approver"},
			},
			{
				comment: "Matches one group with multiple roles",
				claims: jose.Claims{
					"groups": []string{"DemoCorp Infrastructure"},
				},
				expectedRoles: []string{"approver", "backend"},
			},
			{
				comment: "No match only due to case-sensitivity",
				claims: jose.Claims{
					"groups": []string{"Democorp - SRE"},
				},
				expectedRoles: []string(nil),
				warnings: []string{
					`trait "Democorp - SRE" matches value "DemoCorp - SRE" case-insensitively and would have yielded "approver" role`,
				},
			},
		},
	},
}

func TestOIDCMapping(t *testing.T) {
	t.Parallel()

	for i, testCase := range oidcTestCases {
		conn := types.OIDCConnectorV3{
			Spec: types.OIDCConnectorSpecV3{
				ClaimsToRoles: testCase.mappings,
			},
		}
		for _, input := range testCase.inputs {
			comment := fmt.Sprintf("OIDC Test case %v %q, input %q", i, testCase.comment, input.comment)
			_, outRoles := TraitsToRoles(conn.GetTraitMappings(), OIDCClaimsToTraits(input.claims))
			require.Empty(t, cmp.Diff(outRoles, input.expectedRoles), comment)
		}

		samlConn := types.SAMLConnectorV2{
			Spec: types.SAMLConnectorSpecV2{
				AttributesToRoles: claimMappingsToAttributeMappings(testCase.mappings),
			},
		}
		for _, input := range testCase.inputs {
			comment := fmt.Sprintf("SAML Test case %v %v, input %#v", i, testCase.comment, input)
			warnings, outRoles := TraitsToRoles(samlConn.GetTraitMappings(), SAMLAssertionsToTraits(claimsToAttributes(input.claims)))
			require.Empty(t, cmp.Diff(outRoles, input.expectedRoles), comment)
			require.Empty(t, cmp.Diff(warnings, input.warnings), comment)
		}
	}
}


/*
goos: darwin
goarch: arm64

❯ go test -bench ^BenchmarkTraitToRoles$ github.com/gravitational/teleport/lib/services | grep BenchmarkTraitToRoles | awk '{printf "%-100s%-15s %7s %s\n", $1, $2, $3, $4}'
BenchmarkTraitToRoles/no_mappings_no_match-10                                                       374511232         3.049 ns/op
BenchmarkTraitToRoles/simple_mappings_no_match-10                                                   18636192          64.57 ns/op
BenchmarkTraitToRoles/simple_mappings_no_value_match-10                                             97311             12264 ns/op
BenchmarkTraitToRoles/simple_mappings_direct_admin_value_match-10                                   92966             12802 ns/op
BenchmarkTraitToRoles/simple_mappings_direct_user_value_match-10                                    100602            11805 ns/op
BenchmarkTraitToRoles/simple_mappings_direct_user_value_match_with_array-10                         100832            11814 ns/op
BenchmarkTraitToRoles/regexp_mappings_match_no_match-10                                             36021477          33.60 ns/op
BenchmarkTraitToRoles/regexp_mappings_match_no_match_-_subprefix-10                                 166546             7118 ns/op
BenchmarkTraitToRoles/regexp_mappings_match_value_with_capture_match-10                             134823             8808 ns/op
BenchmarkTraitToRoles/regexp_mappings_match_multiple_value_with_capture_match,_deduplication-10     115350            10400 ns/op
BenchmarkTraitToRoles/regexp_mappings_match_first_matches,_second_does_not-10                       98511             12234 ns/op
BenchmarkTraitToRoles/regexp_compilation_invalid_regexp-10                                          58684             20419 ns/op
BenchmarkTraitToRoles/regexp_compilation_regexp_are_not_compiled_if_not_needed-10                   42062830          28.59 ns/op
BenchmarkTraitToRoles/empty_expands_are_skipped_value_with_capture_match-10                         148668             8227 ns/op
BenchmarkTraitToRoles/glob_wildcard_match_empty_value_match-10                                      230226             5171 ns/op
BenchmarkTraitToRoles/glob_wildcard_match_any_value_match-10                                        222951             5325 ns/op
BenchmarkTraitToRoles/Whitespace/dashes_Matches_multiple_groups-10                                  19573             61473 ns/op
BenchmarkTraitToRoles/Whitespace/dashes_Matches_one_group-10                                        28248             42368 ns/op
BenchmarkTraitToRoles/Whitespace/dashes_Matches_one_group_with_multiple_roles-10                    27547             44463 ns/op
BenchmarkTraitToRoles/Whitespace/dashes_No_match_only_due_to_case-sensitivity-10                    26466             44907 ns/op
*/
func BenchmarkTraitToRoles(b *testing.B) {
	for _, testCase := range oidcTestCases {
		samlConn := types.SAMLConnectorV2{
			Spec: types.SAMLConnectorSpecV2{
				AttributesToRoles: claimMappingsToAttributeMappings(testCase.mappings),
			},
		}
		mappings := samlConn.GetTraitMappings()
		for _, input := range testCase.inputs {
			testCaseInputName := fmt.Sprintf("%s %s", testCase.comment, input.comment)
			traits := SAMLAssertionsToTraits(claimsToAttributes(input.claims))

			b.Run(testCaseInputName, func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					TraitsToRoles(mappings, traits)
				}
			})
		}
	}
}

// claimMappingsToAttributeMappings converts oidc claim mappings to
// attribute mappings, used in tests
func claimMappingsToAttributeMappings(in []types.ClaimMapping) []types.AttributeMapping {
	var out []types.AttributeMapping
	for _, m := range in {
		out = append(out, types.AttributeMapping{
			Name:  m.Claim,
			Value: m.Value,
			Roles: append([]string{}, m.Roles...),
		})
	}
	return out
}

// claimsToAttributes maps jose.Claims type to attributes for testing
func claimsToAttributes(claims jose.Claims) saml2.AssertionInfo {
	info := saml2.AssertionInfo{
		Values: make(map[string]samltypes.Attribute),
	}
	for claim, values := range claims {
		attr := samltypes.Attribute{
			Name: claim,
		}
		switch val := values.(type) {
		case string:
			attr.Values = []samltypes.AttributeValue{{Value: val}}
		case []string:
			for _, v := range val {
				attr.Values = append(attr.Values, samltypes.AttributeValue{Value: v})
			}
		default:
			panic(fmt.Sprintf("unsupported type %T", val))
		}
		info.Values[claim] = attr
	}
	return info
}
