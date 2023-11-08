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

package spacelift

import "github.com/gravitational/trace"

// IDTokenClaims
// See the following for the structure:
// https://docs.spacelift.io/integrations/cloud-providers/oidc/#standard-claims
type IDTokenClaims struct {
	// Sub provides some information about the Spacelift run that generated this
	// token.
	// space:<space_id>:(stack|module):<stack_id|module_id>:run_type:<run_type>:scope:<read|write>
	Sub string `json:"sub"`
	// SpaceID is the ID of the space in which the run that owns the token was
	// executed.
	SpaceID string `json:"spaceId"`
	// CallerType is the type of the caller, ie. the entity that owns the run -
	// either stack or module.
	CallerType string `json:"callerType"`
	// CallerID is the ID of the caller, ie. the stack or module that generated
	// the run.
	CallerID string `json:"callerId"`
	// RunType is the type of the run.
	// (PROPOSED, TRACKED, TASK, TESTING or DESTROY)
	RunType string `json:"runType"`
	// RunID is the ID of the run that owns the token.
	RunID string `json:"runId"`
	// Scope is the scope of the token - either read or write.
	Scope string `json:"scope"`
}

type envGetter func(key string) string

// IDTokenSource allows a SpaceLift ID token to be fetched whilst within a
// SpaceLift execution.
type IDTokenSource struct {
	getEnv envGetter
}

func (its *IDTokenSource) GetIDToken() (string, error) {
	tok := its.getEnv("SPACELIFT_OIDC_TOKEN")
	if tok == "" {
		return "", trace.BadParameter(
			"SPACELIFT_OIDC_TOKEN environment variable missing",
		)
	}

	return tok, nil
}

func NewIDTokenSource(getEnv envGetter) *IDTokenSource {
	return &IDTokenSource{
		getEnv,
	}
}
