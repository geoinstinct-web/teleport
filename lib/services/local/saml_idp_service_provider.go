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

package local

import (
	"context"
	"time"

	"github.com/crewjam/saml/samlsp"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"
)

const (
	samlIDPServiceProviderPrefix        = "saml_idp_service_provider"
	samlIDPServiceProviderModifyLock    = "saml_idp_service_provider_modify_lock"
	samlIDPServiceProviderModifyLockTTL = time.Second * 5
	samlIDPServiceProviderMaxPageSize   = 200
)

// SAMLIdPServiceProviderService manages IdP service providers in the Backend.
type SAMLIdPServiceProviderService struct {
	backend.Backend
}

// NewSAMLIdPServiceProviderService creates a new SAMLIdPServiceProviderService.
func NewSAMLIdPServiceProviderService(backend backend.Backend) *SAMLIdPServiceProviderService {
	return &SAMLIdPServiceProviderService{Backend: backend}
}

// ListSAMLIdPServiceProviders returns a paginated list of SAML IdP service provider resources.
func (s *SAMLIdPServiceProviderService) ListSAMLIdPServiceProviders(ctx context.Context, pageSize int, pageToken string) ([]types.SAMLIdPServiceProvider, string, error) {
	rangeStart := backend.Key(samlIDPServiceProviderPrefix, pageToken)
	rangeEnd := backend.RangeEnd(rangeStart)

	// Adjust page size, so it can't be too large.
	if pageSize <= 0 || pageSize > samlIDPServiceProviderMaxPageSize {
		pageSize = samlIDPServiceProviderMaxPageSize
	}

	// Increment pageSize to allow for the extra item represented by nextKey.
	// We skip this item in the results below.
	limit := pageSize + 1
	var out []types.SAMLIdPServiceProvider

	// no filter provided get the range directly
	result, err := s.GetRange(ctx, rangeStart, rangeEnd, limit)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}

	out = make([]types.SAMLIdPServiceProvider, 0, len(result.Items))
	for _, item := range result.Items {
		sp, err := services.UnmarshalSAMLIdPServiceProvider(item.Value)
		if err != nil {
			return nil, "", trace.Wrap(err)
		}
		out = append(out, sp)
	}

	var nextKey string
	if len(out) > pageSize {
		nextKey = backend.GetPaginationKey(out[len(out)-1])
		// Truncate the last item that was used to determine next row existence.
		out = out[:pageSize]
	}

	return out, nextKey, nil
}

// GetSAMLIdPServiceProvider returns the specified SAML IdP service provider resource.
func (s *SAMLIdPServiceProviderService) GetSAMLIdPServiceProvider(ctx context.Context, name string) (types.SAMLIdPServiceProvider, error) {
	item, err := s.Get(ctx, backend.Key(samlIDPServiceProviderPrefix, name))
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.NotFound("%s %q doesn't exist", types.KindSAMLIdPServiceProvider, name)
		}
		return nil, trace.Wrap(err)
	}
	sp, err := services.UnmarshalSAMLIdPServiceProvider(item.Value,
		services.WithResourceID(item.ID), services.WithExpires(item.Expires))
	return sp, trace.Wrap(err)
}

// CreateSAMLIdPServiceProvider creates a new SAML IdP service provider resource.
func (s *SAMLIdPServiceProviderService) CreateSAMLIdPServiceProvider(ctx context.Context, sp types.SAMLIdPServiceProvider) error {
	if err := sp.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	if err := s.ensureEntityDescriptorMatchesEntityID(sp); err != nil {
		return trace.Wrap(err)
	}

	value, err := services.MarshalSAMLIdPServiceProvider(sp)
	if err != nil {
		return trace.Wrap(err)
	}
	item := backend.Item{
		Key:     backend.Key(samlIDPServiceProviderPrefix, sp.GetName()),
		Value:   value,
		Expires: sp.Expiry(),
		ID:      sp.GetResourceID(),
	}

	return trace.Wrap(backend.RunWhileLocked(ctx, s.Backend, samlIDPServiceProviderModifyLock, samlIDPServiceProviderModifyLockTTL, func(ctx context.Context) error {
		if err := s.ensureEntityIDIsUnique(ctx, sp); err != nil {
			return trace.Wrap(err)
		}

		_, err = s.Create(ctx, item)
		if trace.IsAlreadyExists(err) {
			return trace.AlreadyExists("%s %q already exists", types.KindSAMLIdPServiceProvider, sp.GetName())
		}
		return trace.Wrap(err)
	}))
}

// UpdateSAMLIdPServiceProvider updates an existing SAML IdP service provider resource.
func (s *SAMLIdPServiceProviderService) UpdateSAMLIdPServiceProvider(ctx context.Context, sp types.SAMLIdPServiceProvider) error {
	if err := sp.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	if err := s.ensureEntityDescriptorMatchesEntityID(sp); err != nil {
		return trace.Wrap(err)
	}

	value, err := services.MarshalSAMLIdPServiceProvider(sp)
	if err != nil {
		return trace.Wrap(err)
	}
	item := backend.Item{
		Key:     backend.Key(samlIDPServiceProviderPrefix, sp.GetName()),
		Value:   value,
		Expires: sp.Expiry(),
		ID:      sp.GetResourceID(),
	}

	return trace.Wrap(backend.RunWhileLocked(ctx, s.Backend, samlIDPServiceProviderModifyLock, samlIDPServiceProviderModifyLockTTL, func(ctx context.Context) error {
		if err := s.ensureEntityIDIsUnique(ctx, sp); err != nil {
			return trace.Wrap(err)
		}

		_, err = s.Update(ctx, item)
		if trace.IsNotFound(err) {
			return trace.NotFound("%s %q doesn't exist", types.KindSAMLIdPServiceProvider, sp.GetName())
		}

		return trace.Wrap(err)
	}))
}

// DeleteSAMLIdPServiceProvider removes the specified SAML IdP service provider resource.
func (s *SAMLIdPServiceProviderService) DeleteSAMLIdPServiceProvider(ctx context.Context, name string) error {
	err := s.Delete(ctx, backend.Key(samlIDPServiceProviderPrefix, name))
	if err != nil {
		if trace.IsNotFound(err) {
			return trace.NotFound("%s %q doesn't exist", types.KindSAMLIdPServiceProvider, name)
		}
		return trace.Wrap(err)
	}
	return nil
}

// DeleteAllSAMLIdPServiceProviders removes all SAML IdP service provider resources.
func (s *SAMLIdPServiceProviderService) DeleteAllSAMLIdPServiceProviders(ctx context.Context) error {
	startKey := backend.Key(samlIDPServiceProviderPrefix)
	err := s.DeleteRange(ctx, startKey, backend.RangeEnd(startKey))
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// ensureEntityIDIsUnique makes sure that the entity ID in the service provider doesn't already exist in the backend.
func (s *SAMLIdPServiceProviderService) ensureEntityIDIsUnique(ctx context.Context, sp types.SAMLIdPServiceProvider) error {
	// Make sure no other service provider has the same entity ID.
	var nextToken string
	for {
		var listSps []types.SAMLIdPServiceProvider
		var err error
		listSps, nextToken, err = s.ListSAMLIdPServiceProviders(ctx, samlIDPServiceProviderMaxPageSize, nextToken)

		if err != nil {
			return trace.Wrap(err)
		}

		for _, listSp := range listSps {
			// Only check entity ID duplicates if we're looking at objects other than the one we're trying to validate.
			// This ensures updates will work and that creates will return an already exists error.
			if listSp.GetName() != sp.GetName() && listSp.GetEntityID() == sp.GetEntityID() {
				return trace.BadParameter("%s %q has the same entity ID %q", types.KindSAMLIdPServiceProvider, listSp.GetName(), listSp.GetEntityID())
			}
		}
		if nextToken == "" {
			break
		}
	}

	return nil
}

// ensureEntityDescriptorMatchesEntityID ensures that the entity ID in the entity descriptor is the same as the entity ID
// in the SAMLIdPServiceProvider object.
func (s *SAMLIdPServiceProviderService) ensureEntityDescriptorMatchesEntityID(sp types.SAMLIdPServiceProvider) error {
	ed, err := samlsp.ParseMetadata([]byte(sp.GetEntityDescriptor()))
	if err != nil {
		return trace.Wrap(err)
	}

	if ed.EntityID != sp.GetEntityID() {
		return trace.BadParameter("entity ID parsed from the entity descriptor does not match the entity ID in the SAML IdP service provider object")
	}

	return nil
}
