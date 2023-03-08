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

package aws

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"

	"github.com/gravitational/teleport/lib/srv/app/common"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
)

func updateAssumeRoleDuration(identity *tlsca.Identity, w http.ResponseWriter, req *http.Request, clock clockwork.Clock) error {
	// Skip non-AssumeRole request
	query, found, err := getAssumeRoleQuery(req)
	if err != nil || !found {
		return trace.Wrap(err)
	}

	// Deny access if identity duration is shorter than the minimum that can be
	// requested.
	identityTTL := identity.Expires.Sub(clock.Now())
	if identityTTL < assumeRoleMinDuration {
		// TODO write error message in XML so the client can understand.
		return trace.AccessDenied("minimum AWS session duration is %v but Teleport identity expires in %v. Please re-login the app and try again.", assumeRoleMinDuration, identityTTL)
	}

	// Use shorter requested duration (no update required).
	if getAssumeRoleQueryDuration(query) <= identityTTL {
		return nil
	}

	// Rewrite the request.
	if err := rewriteAssumeRoleQuery(req, withAssumeRoleQueryDuration(query, identityTTL)); err != nil {
		return trace.Wrap(err)
	}
	w.Header().Add(common.TeleportAPIInfoHeader, fmt.Sprintf("requested DurationSeconds of AssumeRole is lowered to \"%d\" as the Teleport identity will expire at %v", int(identityTTL.Seconds()), identity.Expires))
	return nil
}

// getAssumeRoleQuery extracts AssumeRole query values from provided request.
//
// AWS SDK reference:
// https://github.com/aws/aws-sdk-go/blob/main/private/protocol/query/build.go
// https://github.com/aws/aws-sdk-go/blob/main/service/sts/api.go
func getAssumeRoleQuery(req *http.Request) (url.Values, bool, error) {
	// http.Request.ParseForm may drain the body. Use a clone.
	clone, err := cloneRequest(req)
	if err != nil {
		return nil, false, trace.Wrap(err)
	}
	if err := clone.ParseForm(); err != nil || clone.PostForm == nil {
		return nil, false, nil
	}
	if clone.PostForm.Get("Action") != "AssumeRole" {
		return nil, false, nil
	}
	return clone.PostForm, true, nil
}

func getAssumeRoleQueryDuration(query url.Values) time.Duration {
	if durationSeconds, err := strconv.ParseInt(query.Get(assumeRoleQueryKeyDurationSeconds), 10, 32); err == nil {
		return time.Duration(durationSeconds) * time.Second
	}
	return assumeRoleDefaultDuration
}
func withAssumeRoleQueryDuration(query url.Values, duration time.Duration) url.Values {
	query.Set(assumeRoleQueryKeyDurationSeconds, strconv.Itoa(int(duration.Seconds())))
	return query
}

func rewriteAssumeRoleQuery(req *http.Request, query url.Values) error {
	return trace.Wrap(utils.ReplaceRequestBody(req, io.NopCloser(strings.NewReader(query.Encode()))))
}

const (
	// assumeRoleQueryKeyDurationSeconds is the query key for the duration
	// seconds for the AssumeRole request.
	assumeRoleQueryKeyDurationSeconds = "DurationSeconds"

	// assumeRoleMinDuration is the minimum duration that can be set for
	// the AssumeRole request.
	//
	// https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
	assumeRoleMinDuration = 15 * time.Minute
	// assumeRoleMinDuration is the default duration if DurationSeconds is not
	// explicitly set in the AssumeRole request.
	//
	// https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
	assumeRoleDefaultDuration = 1 * time.Hour
)
