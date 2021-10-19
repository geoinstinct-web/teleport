/*
Copyright 2021 Gravitational, Inc.

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

package aws

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestExtractCredFromAuthHeader test the extractCredFromAuthHeader function logic.
func TestExtractCredFromAuthHeader(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		expCred *SigV4
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:  "valid header",
			input: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024",
			expCred: &SigV4{
				KeyID:     "AKIAIOSFODNN7EXAMPLE",
				Date:      "20130524",
				Region:    "us-east-1",
				Service:   "s3",
				Signature: "fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024",
				SignedHeaders: []string{
					"host",
					"range",
					"x-amz-date",
				},
			},
			wantErr: require.NoError,
		},
		{
			name:  "signed headers section missing",
			input: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024",
			expCred: &SigV4{
				KeyID:     "AKIAIOSFODNN7EXAMPLE",
				Date:      "20130524",
				Region:    "us-east-1",
				Service:   "s3",
				Signature: "fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024",
			},
			wantErr: require.NoError,
		},
		{
			name:    "credential  section missing",
			input:   "AWS4-HMAC-SHA256 SignedHeaders=host;range;x-amz-date, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024",
			wantErr: require.Error,
		},
		{
			name:    "invalid format",
			input:   "Credential=AKIAIOSFODNN7EXAMPLE/us-east-1/s3/aws4_request",
			wantErr: require.Error,
		},
		{
			name:    "missing credentials section",
			input:   "AWS4-HMAC-SHA256 SignedHeaders=host",
			wantErr: require.Error,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: require.Error,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSigV4(tc.input)
			tc.wantErr(t, err)
			require.Equal(t, tc.expCred, got)
		})
	}
}
