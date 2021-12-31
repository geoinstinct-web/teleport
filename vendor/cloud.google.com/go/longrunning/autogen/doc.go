// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go_gapic. DO NOT EDIT.

// Package longrunning is an auto-generated package for the
// Long Running Operations API.
//
//   NOTE: This package is in alpha. It is not stable, and is likely to change.
//
// Example usage
//
// To get started with this package, create a client.
//  ctx := context.Background()
//  c, err := longrunning.NewOperationsClient(ctx)
//  if err != nil {
//  	// TODO: Handle error.
//  }
//  defer c.Close()
//
// The client will use your default application credentials. Clients should be reused instead of created as needed.
// The methods of Client are safe for concurrent use by multiple goroutines.
// The returned client must be Closed when it is done being used.
//
// Using the Client
//
// The following is an example of making an API call with the newly created client.
//
//  ctx := context.Background()
//  c, err := longrunning.NewOperationsClient(ctx)
//  if err != nil {
//  	// TODO: Handle error.
//  }
//  defer c.Close()
//
//  req := &longrunningpb.ListOperationsRequest{
//  	// TODO: Fill request struct fields.
//  	// See https://pkg.go.dev/google.golang.org/genproto/googleapis/longrunning#ListOperationsRequest.
//  }
//  it := c.ListOperations(ctx, req)
//  for {
//  	resp, err := it.Next()
//  	if err == iterator.Done {
//  		break
//  	}
//  	if err != nil {
//  		// TODO: Handle error.
//  	}
//  	// TODO: Use resp.
//  	_ = resp
//  }
//
// Use of Context
//
// The ctx passed to NewClient is used for authentication requests and
// for creating the underlying connection, but is not used for subsequent calls.
// Individual methods on the client use the ctx given to them.
//
// To close the open connection, use the Close() method.
//
// For information about setting deadlines, reusing contexts, and more
// please visit https://pkg.go.dev/cloud.google.com/go.
package longrunning // import "cloud.google.com/go/longrunning/autogen"

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unicode"

	"google.golang.org/api/option"
	"google.golang.org/grpc/metadata"
)

// For more information on implementing a client constructor hook, see
// https://github.com/googleapis/google-cloud-go/wiki/Customizing-constructors.
type clientHookParams struct{}
type clientHook func(context.Context, clientHookParams) ([]option.ClientOption, error)

const versionClient = "20211206"

func insertMetadata(ctx context.Context, mds ...metadata.MD) context.Context {
	out, _ := metadata.FromOutgoingContext(ctx)
	out = out.Copy()
	for _, md := range mds {
		for k, v := range md {
			out[k] = append(out[k], v...)
		}
	}
	return metadata.NewOutgoingContext(ctx, out)
}

func checkDisableDeadlines() (bool, error) {
	raw, ok := os.LookupEnv("GOOGLE_API_GO_EXPERIMENTAL_DISABLE_DEFAULT_DEADLINE")
	if !ok {
		return false, nil
	}

	b, err := strconv.ParseBool(raw)
	return b, err
}

// DefaultAuthScopes reports the default set of authentication scopes to use with this package.
func DefaultAuthScopes() []string {
	return []string{}
}

// versionGo returns the Go runtime version. The returned string
// has no whitespace, suitable for reporting in header.
func versionGo() string {
	const develPrefix = "devel +"

	s := runtime.Version()
	if strings.HasPrefix(s, develPrefix) {
		s = s[len(develPrefix):]
		if p := strings.IndexFunc(s, unicode.IsSpace); p >= 0 {
			s = s[:p]
		}
		return s
	}

	notSemverRune := func(r rune) bool {
		return !strings.ContainsRune("0123456789.", r)
	}

	if strings.HasPrefix(s, "go1") {
		s = s[2:]
		var prerelease string
		if p := strings.IndexFunc(s, notSemverRune); p >= 0 {
			s, prerelease = s[:p], s[p:]
		}
		if strings.HasSuffix(s, ".") {
			s += "0"
		} else if strings.Count(s, ".") < 2 {
			s += ".0"
		}
		if prerelease != "" {
			s += "-" + prerelease
		}
		return s
	}
	return "UNKNOWN"
}
