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

package version

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/integrations/kube-agent-updater/pkg/basichttp"
	"github.com/gravitational/teleport/integrations/kube-agent-updater/pkg/constants"
)

const basicHTTPTestPath = "/v1/cloud-stable"

func Test_basicHTTPVersionClient_Get(t *testing.T) {
	mock := basichttp.NewServerMock(basicHTTPTestPath + "/" + constants.VersionPath)
	t.Cleanup(mock.Srv.Close)
	serverURL, err := url.Parse(mock.Srv.URL)
	serverURL.Path = basicHTTPTestPath
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name       string
		statusCode int
		response   string
		expected   string
		assertErr  require.ErrorAssertionFunc
	}{
		{
			name:       "all good",
			statusCode: http.StatusOK,
			response:   "12.0.3",
			expected:   "v12.0.3",
			assertErr:  require.NoError,
		},
		{
			name:       "all good with newline",
			statusCode: http.StatusOK,
			response:   "12.0.3\n",
			expected:   "v12.0.3",
			assertErr:  require.NoError,
		},
		{
			name:       "non-semver",
			statusCode: http.StatusOK,
			response:   "hello",
			expected:   "",
			assertErr: func(t2 require.TestingT, err2 error, _ ...interface{}) {
				require.IsType(t2, &trace.BadParameterError{}, trace.Unwrap(err2))
			},
		},
		{
			name:       "empty",
			statusCode: http.StatusOK,
			response:   "",
			expected:   "",
			assertErr: func(t2 require.TestingT, err2 error, _ ...interface{}) {
				require.IsType(t2, &trace.BadParameterError{}, trace.Unwrap(err2))
			},
		},
		{
			name:       "non-200 response",
			statusCode: http.StatusInternalServerError,
			response:   "ERROR - SOMETHING WENT WRONG",
			expected:   "",
			assertErr:  require.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &basicHTTPVersionClient{
				baseURL: serverURL,
				client:  &basichttp.Client{Client: mock.Srv.Client()},
			}
			mock.SetResponse(t, tt.statusCode, tt.response)
			result, err := b.Get(ctx)
			tt.assertErr(t, err)
			require.Equal(t, tt.expected, result)
		})
	}
}
