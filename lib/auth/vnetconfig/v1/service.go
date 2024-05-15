/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
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

package vnetconfig

import (
	"context"

	"github.com/gravitational/trace"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/gravitational/teleport/api/gen/proto/go/teleport/vnet/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/services/local"
)

type Service struct {
	// Opting out of forward compatibility, this service must implement all service methods.
	vnet.UnsafeVnetConfigServiceServer

	storage    *local.VnetConfigService
	authorizer authz.Authorizer
}

func NewService(storage *local.VnetConfigService, authorizer authz.Authorizer) *Service {
	return &Service{
		storage:    storage,
		authorizer: authorizer,
	}
}

func (s *Service) GetVnetConfig(ctx context.Context, _ *vnet.GetVnetConfigRequest) (*vnet.VnetConfig, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := authCtx.CheckAccessToKind(types.KindVnetConfig, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}

	vnetConfig, err := s.storage.GetVnetConfig(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return vnetConfig, nil
}

func (s *Service) CreateVnetConfig(ctx context.Context, req *vnet.CreateVnetConfigRequest) (*vnet.VnetConfig, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := authCtx.CheckAccessToKind(types.KindVnetConfig, types.VerbCreate); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := authCtx.AuthorizeAdminAction(); err != nil {
		return nil, trace.Wrap(err)
	}

	vnetConfig, err := s.storage.CreateVnetConfig(ctx, req.VnetConfig)
	return vnetConfig, trace.Wrap(err)
}

func (s *Service) UpdateVnetConfig(ctx context.Context, req *vnet.UpdateVnetConfigRequest) (*vnet.VnetConfig, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := authCtx.CheckAccessToKind(types.KindVnetConfig, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := authCtx.AuthorizeAdminAction(); err != nil {
		return nil, trace.Wrap(err)
	}

	vnetConfig, err := s.storage.UpdateVnetConfig(ctx, req.VnetConfig)
	return vnetConfig, trace.Wrap(err)
}

func (s *Service) UpsertVnetConfig(ctx context.Context, req *vnet.UpsertVnetConfigRequest) (*vnet.VnetConfig, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// To upsert you must be allowed to Create and Update the new resource.
	if err := authCtx.CheckAccessToKind(types.KindVnetConfig, types.VerbCreate, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := authCtx.AuthorizeAdminAction(); err != nil {
		return nil, trace.Wrap(err)
	}

	vnetConfig, err := s.storage.UpsertVnetConfig(ctx, req.VnetConfig)
	return vnetConfig, trace.Wrap(err)
}

func (s *Service) DeleteVnetConfig(ctx context.Context, _ *vnet.DeleteVnetConfigRequest) (*emptypb.Empty, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := authCtx.CheckAccessToKind(types.KindVnetConfig, types.VerbDelete); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := authCtx.AuthorizeAdminAction(); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := s.storage.DeleteVnetConfig(ctx); err != nil {
		return nil, trace.Wrap(err)
	}
	return &emptypb.Empty{}, nil
}
