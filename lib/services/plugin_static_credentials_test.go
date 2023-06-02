/*
Copyright 2023 Gravitational, Inc.

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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
)

func TestMarshalPluginStaticCredentialsRoundTrip(t *testing.T) {
	spec := types.PluginStaticCredentialsSpecV1{
		Credentials: &types.PluginStaticCredentialsSpecV1_APIToken{
			APIToken: "some-token",
		},
	}

	creds, err := types.NewPluginStaticCredentials(types.Metadata{
		Name: "test-creds",
	}, spec)
	require.NoError(t, err)

	payload, err := MarshalPluginStaticCredentials(creds)
	require.NoError(t, err)

	unmarshaled, err := UnmarshalPluginStaticCredentials(payload)
	require.NoError(t, err)
	require.Empty(t, cmp.Diff(creds, unmarshaled))
}
