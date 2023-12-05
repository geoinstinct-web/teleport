/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
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

package version

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	semverLow         = "v11.3.2"
	semverMid         = "v11.5.4"
	semverHigh        = "v12.2.1"
	invalidSemverHigh = "12.2.1"
)

func TestValidVersionChange(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		current string
		next    string
		want    bool
	}{
		{
			name:    "upgrade",
			current: semverMid,
			next:    semverHigh,
			want:    true,
		},
		{
			name:    "same version",
			current: semverMid,
			next:    semverMid,
			want:    false,
		},
		{
			name:    "unknown current version",
			current: "",
			next:    semverMid,
			want:    true,
		},
		{
			name:    "non-semver current version",
			current: semverMid,
			next:    invalidSemverHigh,
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ValidVersionChange(ctx, tt.current, tt.next))
		})
	}
}
