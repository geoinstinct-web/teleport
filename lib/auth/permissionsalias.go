// Copyright 2023 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"context"

	"github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/authz"
)

// The following are all temporary aliases to ensure that e still compiles
// while we migrate it over.
// TODO(mdwn): Cleanup authorizer aliases after transition.
const ContextUser authz.ContextKey = "teleport-user"

type Authorizer = authz.Authorizer
type Context = authz.Context
type LocalUser = authz.LocalUser
type BuiltinRole = authz.BuiltinRole
type AuthorizerOpts = authz.AuthorizerOpts

func NewAuthorizer(opts AuthorizerOpts) (Authorizer, error) {
	return authz.NewAuthorizer(opts)
}

func ClientUserMetadata(ctx context.Context) events.UserMetadata {
	return authz.ClientUserMetadata(ctx)
}
