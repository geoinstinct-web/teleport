// Teleport
// Copyright (C) 2024 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package clusterconfigv1

import (
	"context"

	"github.com/gravitational/trace"

	clusterconfigpb "github.com/gravitational/teleport/api/gen/proto/go/teleport/clusterconfig/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/authz"
	dtconfig "github.com/gravitational/teleport/lib/devicetrust/config"
	"github.com/gravitational/teleport/lib/modules"
)

// Cache is used by the [Service] to query cluster config resources.
type Cache interface {
	GetAuthPreference(context.Context) (types.AuthPreference, error)
}

// Backend is used by the [Service] to mutate cluster config resources.
type Backend interface {
	CreateAuthPreference(ctx context.Context, preference types.AuthPreference) (types.AuthPreference, error)
	UpdateAuthPreference(ctx context.Context, preference types.AuthPreference) (types.AuthPreference, error)
	UpsertAuthPreference(ctx context.Context, preference types.AuthPreference) (types.AuthPreference, error)
}

// ServiceConfig contain dependencies required to create a [Service].
type ServiceConfig struct {
	Cache      Cache
	Backend    Backend
	Authorizer authz.Authorizer
}

// Service implements the teleport.clusterconfig.v1.ClusterConfigService RPC service.
type Service struct {
	clusterconfigpb.UnimplementedClusterConfigServiceServer

	cache      Cache
	backend    Backend
	authorizer authz.Authorizer
}

// NewService validates the provided configuration and returns a [Service].
func NewService(cfg ServiceConfig) (*Service, error) {
	switch {
	case cfg.Cache == nil:
		return nil, trace.BadParameter("cache service is required")
	case cfg.Backend == nil:
		return nil, trace.BadParameter("backend service is required")
	case cfg.Authorizer == nil:
		return nil, trace.BadParameter("authorizer is required")
	}

	return &Service{cache: cfg.Cache, backend: cfg.Backend, authorizer: cfg.Authorizer}, nil
}

// GetAuthPreference returns the locally cached auth preference.
func (s Service) GetAuthPreference(ctx context.Context, _ *clusterconfigpb.GetAuthPreferenceRequest) (*types.AuthPreferenceV2, error) {
	authzCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := authzCtx.CheckAccessToKind(types.KindClusterAuthPreference, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}

	pref, err := s.cache.GetAuthPreference(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	authPrefV2, ok := pref.(*types.AuthPreferenceV2)
	if !ok {
		return nil, trace.Wrap(trace.BadParameter("unexpected auth preference type %T (expected %T)", pref, authPrefV2))
	}

	return authPrefV2, nil
}

// CreateAuthPreference creates a new auth preference if one does not exist. This
// is an internal API and is not exposed via [clusterconfigv1.ClusterConfigServiceServer]. It
// is only meant to be called directly from the first time an Auth instance is started.
func (s Service) CreateAuthPreference(ctx context.Context, p types.AuthPreference) (types.AuthPreference, error) {
	authzCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if !authz.HasBuiltinRole(*authzCtx, string(types.RoleAuth)) {
		return nil, trace.AccessDenied("this request can be only executed by an auth server")
	}

	// check that the given RequireMFAType is supported in this build.
	if p.GetPrivateKeyPolicy().IsHardwareKeyPolicy() && modules.GetModules().BuildType() != modules.BuildEnterprise {
		return nil, trace.AccessDenied("Hardware Key support is only available with an enterprise license")
	}

	if err := dtconfig.ValidateConfigAgainstModules(p.GetDeviceTrust()); err != nil {
		return nil, trace.Wrap(err)
	}

	created, err := s.backend.CreateAuthPreference(ctx, p)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	authPrefV2, ok := created.(*types.AuthPreferenceV2)
	if !ok {
		return nil, trace.Wrap(trace.BadParameter("unexpected auth preference type %T (expected %T)", created, authPrefV2))
	}

	return authPrefV2, nil
}

// UpdateAuthPreference conditional updates an existing auth preference if the value
// wasn't concurrently modified.
func (s Service) UpdateAuthPreference(ctx context.Context, req *clusterconfigpb.UpdateAuthPreferenceRequest) (*types.AuthPreferenceV2, error) {
	authzCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := authzCtx.CheckAccessToKind(types.KindClusterAuthPreference, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := authzCtx.AuthorizeAdminAction(); err != nil {
		return nil, trace.Wrap(err)
	}

	// check that the given RequireMFAType is supported in this build.
	if req.AuthPreference.GetPrivateKeyPolicy().IsHardwareKeyPolicy() && modules.GetModules().BuildType() != modules.BuildEnterprise {
		return nil, trace.AccessDenied("Hardware Key support is only available with an enterprise license")
	}

	if err := dtconfig.ValidateConfigAgainstModules(req.AuthPreference.GetDeviceTrust()); err != nil {
		return nil, trace.Wrap(err)
	}

	req.AuthPreference.SetOrigin(types.OriginDynamic)

	updated, err := s.backend.UpdateAuthPreference(ctx, req.AuthPreference)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	authPrefV2, ok := updated.(*types.AuthPreferenceV2)
	if !ok {
		return nil, trace.Wrap(trace.BadParameter("unexpected auth preference type %T (expected %T)", updated, authPrefV2))
	}

	return authPrefV2, nil
}

// UpsertAuthPreference creates a new auth preference or overwrites an existing auth preference.
func (s Service) UpsertAuthPreference(ctx context.Context, req *clusterconfigpb.UpsertAuthPreferenceRequest) (*types.AuthPreferenceV2, error) {
	authzCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := authzCtx.CheckAccessToKind(types.KindClusterAuthPreference, types.VerbCreate, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}

	// Support reused MFA for bulk tctl create requests.
	if err := authzCtx.AuthorizeAdminActionAllowReusedMFA(); err != nil {
		return nil, trace.Wrap(err)
	}

	// check that the given RequireMFAType is supported in this build.
	if req.AuthPreference.GetPrivateKeyPolicy().IsHardwareKeyPolicy() && modules.GetModules().BuildType() != modules.BuildEnterprise {
		return nil, trace.AccessDenied("Hardware Key support is only available with an enterprise license")
	}

	if err := dtconfig.ValidateConfigAgainstModules(req.AuthPreference.GetDeviceTrust()); err != nil {
		return nil, trace.Wrap(err)
	}

	req.AuthPreference.SetOrigin(types.OriginDynamic)

	updated, err := s.backend.UpsertAuthPreference(ctx, req.AuthPreference)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	authPrefV2, ok := updated.(*types.AuthPreferenceV2)
	if !ok {
		return nil, trace.Wrap(trace.BadParameter("unexpected auth preference type %T (expected %T)", updated, authPrefV2))
	}

	return authPrefV2, nil
}

// ResetAuthPreference restores the auth preferences to the default value.
func (s Service) ResetAuthPreference(ctx context.Context, req *clusterconfigpb.ResetAuthPreferenceRequest) (*types.AuthPreferenceV2, error) {
	authzCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := authzCtx.CheckAccessToKind(types.KindClusterAuthPreference, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := authzCtx.AuthorizeAdminAction(); err != nil {
		return nil, trace.Wrap(err)
	}

	defaultPreference := types.DefaultAuthPreference()
	const iterationLimit = 3
	// Attempt a few iterations in case the conditional update fails
	// due to spurious networking conditions.
	for i := 0; i < iterationLimit; i++ {
		pref, err := s.cache.GetAuthPreference(ctx)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		if pref.Origin() == types.OriginConfigFile {
			return nil, trace.BadParameter("auth preference has been defined via the config file and cannot be reset back to defaults dynamically.")
		}

		defaultPreference.SetRevision(pref.GetRevision())

		reset, err := s.backend.UpdateAuthPreference(ctx, defaultPreference)
		if err != nil {
			if trace.IsCompareFailed(err) {
				continue
			}
			return nil, trace.Wrap(err)
		}

		authPrefV2, ok := reset.(*types.AuthPreferenceV2)
		if !ok {
			return nil, trace.Wrap(trace.BadParameter("unexpected auth preference type %T (expected %T)", reset, authPrefV2))
		}

		return authPrefV2, nil
	}

	return nil, trace.LimitExceeded("failed to reset networking config within %v iterations", iterationLimit)
}
