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

package userloginstate

import (
	"context"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/header"
	"github.com/gravitational/teleport/api/types/trait"
	"github.com/gravitational/teleport/api/types/userloginstate"
	"github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"
	"github.com/gravitational/teleport/lib/tlsca"
)

// GeneratorConfig is the configuration for the user login state generator.
type GeneratorConfig struct {
	// AccessLists is a service for retrieving access lists from the backend.
	AccessLists services.AccessListsGetter

	// Roles is a service for retrieving roles from the backend.
	Roles services.RoleGetter

	// Clock is the clock to use for the generator.
	Clock clockwork.Clock
}

func (g *GeneratorConfig) CheckAndSetDefaults() error {
	if g.AccessLists == nil {
		return trace.BadParameter("missing access lists")
	}

	if g.Roles == nil {
		return trace.BadParameter("missing roles")
	}

	if g.Clock == nil {
		g.Clock = clockwork.NewRealClock()
	}

	return nil
}

// Generator will generate a user login state from a user.
type Generator struct {
	accessLists services.AccessListsGetter
	roles       services.RoleGetter
	clock       clockwork.Clock
}

// NewGenerator creates a new user login state generator.
func NewGenerator(config GeneratorConfig) (*Generator, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	return &Generator{
		accessLists: config.AccessLists,
		roles:       config.Roles,
		clock:       config.Clock,
	}, nil
}

// Generate will generate the user login state for the given user.
func (g *Generator) Generate(ctx context.Context, user types.User) (*userloginstate.UserLoginState, error) {
	// Create a new empty user login state.
	uls, err := userloginstate.New(
		header.Metadata{
			Name: user.GetName(),
		}, userloginstate.Spec{
			Roles:  []string{},
			Traits: trait.Traits{},
		})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := g.addAccessListsToState(ctx, user, uls); err != nil {
		return nil, trace.Wrap(err)
	}

	deduplicateRolesAndTraits(uls)

	// Remove roles that don't exist in the backend so that we don't generate certs for non-existent roles.
	// Doing so can prevent login from working properly. This could occur if access lists refer to roles that
	// no longer exist, for example.
	existingRoles := []string{}
	for _, role := range uls.Spec.Roles {
		if _, err := g.roles.GetRole(ctx, role); err == nil {
			existingRoles = append(existingRoles, role)
		} else if !trace.IsNotFound(err) {
			return nil, trace.Wrap(err)
		}
	}
	uls.Spec.Roles = existingRoles

	return uls, nil
}

// addAccessListsToState will added the user's applicable access lists to the user login state.
func (g *Generator) addAccessListsToState(ctx context.Context, user types.User, state *userloginstate.UserLoginState) error {
	accessLists, err := g.accessLists.GetAccessLists(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	// Create an identity for testing membership to access lists.
	identity := tlsca.Identity{
		Username: user.GetName(),
		Groups:   user.GetRoles(),
		Traits:   user.GetTraits(),
	}

	for _, accessList := range accessLists {
		if err := services.IsMember(identity, g.clock, accessList); err != nil {
			continue
		}

		state.Spec.Roles = append(state.Spec.Roles, accessList.Spec.Grants.Roles...)

		for k, values := range accessList.Spec.Grants.Traits {
			state.Spec.Traits[k] = append(state.Spec.Traits[k], values...)
		}
	}

	return nil
}

func deduplicateRolesAndTraits(state *userloginstate.UserLoginState) {
	state.Spec.Roles = utils.Deduplicate(state.Spec.Roles)

	for k, v := range state.Spec.Traits {
		state.Spec.Traits[k] = utils.Deduplicate(v)
	}
}

// NewLoginHook creates a login hook from the Generator and the user login state service.
func NewLoginHook(ulsGenerator *Generator, ulsService *local.UserLoginStateService) func(context.Context, types.User) error {
	return func(ctx context.Context, user types.User) error {
		uls, err := ulsGenerator.Generate(ctx, user)
		if err != nil {
			return trace.Wrap(err)
		}

		_, err = ulsService.UpsertUserLoginState(ctx, uls)
		return trace.Wrap(err)
	}
}
