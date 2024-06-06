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

package local

import (
	"context"

	"github.com/gravitational/trace"

	accessgraphsecretspb "github.com/gravitational/teleport/api/gen/proto/go/teleport/accessgraph/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local/generic"
)

const (
	authorizedKeysPrefix = "ssh_authorized_keys"
)

// AccessGraphSecretsService manages secrets found on Teleport Nodes and
// enrolled devices.
type AccessGraphSecretsService struct {
	authorizedKeysSvc *generic.ServiceWrapper[*accessgraphsecretspb.AuthorizedKey]
}

// NewAccessGraphSecretsService returns a new Access Graph Secrets service.
// This service in Teleport is used to keep track of secrets found in Teleport
// Nodes and on enrolled devices. Currently, it only stores secrets related with
// SSH Keys. Future implementations might extend them.
func NewAccessGraphSecretsService(backend backend.Backend) (*AccessGraphSecretsService, error) {
	authorizedKeysSvc, err := generic.NewServiceWrapper(
		backend,
		types.KindAccessGraphSecretAuthorizedKey,
		authorizedKeysPrefix,
		services.MarshalAccessGraphAuthorizedKey,
		services.UnmarshalAccessGraphAuthorizedKey,
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &AccessGraphSecretsService{
		authorizedKeysSvc: authorizedKeysSvc,
	}, nil
}

// ListAllAuthorizedKeys lists all authorized keys stored in the backend.
func (k *AccessGraphSecretsService) ListAllAuthorizedKeys(ctx context.Context, pageSize int, pageToken string) ([]*accessgraphsecretspb.AuthorizedKey, string, error) {
	out, next, err := k.authorizedKeysSvc.ListResourcesReturnNextResource(ctx, pageSize, pageToken)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	return out, nextToken(next), nil
}

// ListAuthorizedKeysForServer lists all authorized keys for a given hostID.
func (k *AccessGraphSecretsService) ListAuthorizedKeysForServer(ctx context.Context, hostID string, pageSize int, pageToken string) ([]*accessgraphsecretspb.AuthorizedKey, string, error) {
	if hostID == "" {
		return nil, "", trace.BadParameter("server name is required")
	}
	svc := k.authorizedKeysSvc.WithPrefix(hostID)
	out, next, err := svc.ListResources(ctx, pageSize, pageToken)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	return out, next, nil
}

// UpsertAuthorizedKey upserts a new authorized key.
func (k *AccessGraphSecretsService) UpsertAuthorizedKey(ctx context.Context, in *accessgraphsecretspb.AuthorizedKey) (*accessgraphsecretspb.AuthorizedKey, error) {
	svc := k.authorizedKeysSvc.WithPrefix(in.Spec.HostId)
	out, err := svc.UpsertResource(ctx, in)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return out, nil
}

// DeleteAuthorizedKey deletes a specific authorized key.
func (k *AccessGraphSecretsService) DeleteAuthorizedKey(ctx context.Context, hostID, name string) error {
	svc := k.authorizedKeysSvc.WithPrefix(hostID)
	return trace.Wrap(svc.DeleteResource(ctx, name))
}

// DeleteAllAuthorizedKeys deletes all authorized keys.
func (k *AccessGraphSecretsService) DeleteAllAuthorizedKeys(ctx context.Context) error {
	return trace.Wrap(k.authorizedKeysSvc.DeleteAllResources(ctx))
}

func nextToken(next **accessgraphsecretspb.AuthorizedKey) string {
	if next == nil {
		return ""
	}
	return (*next).Spec.HostId + string(backend.Separator) + (*next).Metadata.Name
}
