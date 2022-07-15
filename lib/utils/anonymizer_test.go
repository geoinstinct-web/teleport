/*
Copyright 2018 Gravitational, Inc.

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

package utils

import (
	"testing"

	"github.com/gravitational/trace"

	"github.com/stretchr/testify/require"
)

func TestHMACAnonymizer(t *testing.T) {
	t.Parallel()

	a, err := NewHMACAnonymizer(" ")
	require.IsType(t, err, trace.BadParameter(""))
	require.Nil(t, a)

	a, err = NewHMACAnonymizer("key")
	require.NoError(t, err)
	require.NotNil(t, a)

	data := "secret"
	result := a.Anonymize([]byte(data))
	require.NotEqual(t, result, "")
	require.NotEqual(t, result, data)
}
