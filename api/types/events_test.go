/*
 *
 * Copyright 2023 Gravitational, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestWatchKindContains tests that the WatchKind.Contains method correctly detects whether its receiver contains its
// argument.
func TestWatchKindContains(t *testing.T) {
	testCases := []struct {
		name           string
		kind           WatchKind
		other          WatchKind
		expectedResult bool
	}{
		{
			name: "yes: kind and subkind match",
			kind: WatchKind{
				Kind:    "a",
				SubKind: "b",
			},
			other: WatchKind{
				Kind:    "a",
				SubKind: "b",
			},
			expectedResult: true,
		},
		{
			name: "no: kind and subkind don't match",
			kind: WatchKind{
				Kind:    "a",
				SubKind: "b",
			},
			other: WatchKind{
				Kind:    "a",
				SubKind: "c",
			},
			expectedResult: false,
		},
		{
			name: "yes: superset doesn't specify version",
			kind: WatchKind{
				Kind:    "a",
				SubKind: "b",
			},
			other: WatchKind{
				Kind:    "a",
				SubKind: "b",
				Version: V1,
			},
			expectedResult: true,
		},
		{
			name: "yes: subset doesn't specify version",
			kind: WatchKind{
				Kind:    "a",
				SubKind: "b",
				Version: V1,
			},
			other: WatchKind{
				Kind:    "a",
				SubKind: "b",
			},
			expectedResult: true,
		},
		{
			name: "no: different versions",
			kind: WatchKind{
				Kind:    "a",
				SubKind: "b",
				Version: V1,
			},
			other: WatchKind{
				Kind:    "a",
				SubKind: "b",
				Version: V2,
			},
			expectedResult: false,
		},
		{
			name: "yes: only subset specifies name",
			kind: WatchKind{
				Kind:    "a",
				SubKind: "b",
			},
			other: WatchKind{
				Kind:    "a",
				SubKind: "b",
				Name:    "c",
			},
			expectedResult: true,
		},
		{
			name: "no: subset is missing name when superset has one",
			kind: WatchKind{
				Kind:    "a",
				SubKind: "b",
				Name:    "c",
			},
			other: WatchKind{
				Kind:    "a",
				SubKind: "b",
			},
			expectedResult: false,
		},
		{
			name: "no: different names",
			kind: WatchKind{
				Kind:    "a",
				SubKind: "b",
				Name:    "c",
			},
			other: WatchKind{
				Kind:    "a",
				SubKind: "b",
				Name:    "d",
			},
			expectedResult: false,
		},
		{
			name: "yes: subset has narrower filter",
			kind: WatchKind{
				Kind:    "a",
				SubKind: "b",
				Filter: map[string]string{
					"c": "d",
				},
			},
			other: WatchKind{
				Kind:    "a",
				SubKind: "b",
				Filter: map[string]string{
					"c": "d",
					"e": "f",
				},
			},
			expectedResult: true,
		},
		{
			name: "no: subset has no filter",
			kind: WatchKind{
				Kind:    "a",
				SubKind: "b",
				Filter: map[string]string{
					"c": "d",
				},
			},
			other: WatchKind{
				Kind:    "a",
				SubKind: "b",
			},
			expectedResult: false,
		},
		{
			name: "no: subset has wider filter",
			kind: WatchKind{
				Kind:    "a",
				SubKind: "b",
				Filter: map[string]string{
					"c": "d",
					"e": "f",
				},
			},
			other: WatchKind{
				Kind:    "a",
				SubKind: "b",
				Filter: map[string]string{
					"e": "f",
				},
			},
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expectedResult, tc.kind.Contains(tc.other))
		})
	}
}
