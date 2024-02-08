/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package generic

import (
	"context"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"
)

// NewService153 will return a new generic service for a given RFD 153-style resource.
func NewService153[T types.ResourceMetadata](
	backend backend.Backend,
	resourceKind string,
	backendPrefix string,
	marshalFunc MarshalFunc[T],
	unmarshalFunc UnmarshalFunc[T]) (*Service153[T], error) {

	cfg := &ServiceConfig[resourceMetadataAdapter[T]]{
		Backend:       backend,
		ResourceKind:  resourceKind,
		PageLimit:     0, // use default page limit
		BackendPrefix: backendPrefix,
		MarshalFunc: func(w resourceMetadataAdapter[T], option ...services.MarshalOption) ([]byte, error) {
			return marshalFunc(w.resource)
		},
		UnmarshalFunc: func(bytes []byte, option ...services.MarshalOption) (resourceMetadataAdapter[T], error) {
			r, err := unmarshalFunc(bytes, option...)
			return newResourceMetadataAdapter(r), trace.Wrap(err)
		},
	}
	service, err := NewService[resourceMetadataAdapter[T]](cfg)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &Service153[T]{service: service}, nil
}

// Service153 is an adapter for Service that makes it usable with RFD 153-style resources,
// which implement types.ResourceMetadata.
//
// Not all methods from Service are exported, in the effort to reduce the API complexity
// as well as adhere to the guidance from RFD 153, but additional methods may be exported in the future as needed.
type Service153[T types.ResourceMetadata] struct {
	service *Service[resourceMetadataAdapter[T]]
}

// UpsertResource upserts a resource.
func (s Service153[T]) UpsertResource(ctx context.Context, resource T) (T, error) {
	adapter, err := s.service.UpsertResource(ctx, newResourceMetadataAdapter(resource))
	return adapter.resource, trace.Wrap(err)
}

// UpdateResource updates an existing resource.
func (s Service153[T]) UpdateResource(ctx context.Context, resource T) (T, error) {
	adapter, err := s.service.UpdateResource(ctx, newResourceMetadataAdapter(resource))
	return adapter.resource, trace.Wrap(err)
}

// CreateResource creates a new resource.
func (s Service153[T]) CreateResource(ctx context.Context, resource T) (T, error) {
	adapter, err := s.service.CreateResource(ctx, newResourceMetadataAdapter(resource))
	return adapter.resource, trace.Wrap(err)
}

// GetResource returns the specified resource.
func (s Service153[T]) GetResource(ctx context.Context, name string) (resource T, err error) {
	adapter, err := s.service.GetResource(ctx, name)
	return adapter.resource, trace.Wrap(err)
}

// DeleteResource removes the specified resource.
func (s Service153[T]) DeleteResource(ctx context.Context, name string) error {
	return trace.Wrap(s.service.DeleteResource(ctx, name))
}

// ListResources returns a paginated list of resources.
func (s Service153[T]) ListResources(ctx context.Context, pageSize int, pageToken string) ([]T, string, error) {
	adapters, nextToken, err := s.service.ListResources(ctx, pageSize, pageToken)
	out := make([]T, 0, len(adapters))
	for _, adapter := range adapters {
		out = append(out, adapter.resource)
	}
	return out, nextToken, trace.Wrap(err)
}
