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

	kubewaitingcontainerclient "github.com/gravitational/teleport/api/client/kubewaitingcontainer"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/kubewaitingcontainer"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local/generic"
)

const (
	kubeWaitingContPrefix = "k8s_waiting_container"
)

// KubeWaitingContainerService manages Kubernetes ephemeral containers
// that are waiting to be created until moderated session conditions are met.
type KubeWaitingContainerService struct {
	svc *generic.Service[*kubewaitingcontainer.KubeWaitingContainer]
}

// NewKubeWaitingContainerService returns a new Kubernetes waiting
// container service.
func NewKubeWaitingContainerService(backend backend.Backend) (*KubeWaitingContainerService, error) {
	svc, err := generic.NewService(&generic.ServiceConfig[*kubewaitingcontainer.KubeWaitingContainer]{
		Backend:       backend,
		ResourceKind:  types.KindKubeWaitingContainer,
		BackendPrefix: kubeWaitingContPrefix,
		MarshalFunc:   services.MarshalKubeWaitingContainer,
		UnmarshalFunc: services.UnmarshalKubeWaitingContainer,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &KubeWaitingContainerService{
		svc: svc,
	}, nil
}

// ListKubernetesWaitingContainers lists Kubernetes ephemeral
// containers that are waiting to be created until moderated
// session conditions are met.
func (k *KubeWaitingContainerService) ListKubernetesWaitingContainers(ctx context.Context, pageSize int, pageToken string) ([]*kubewaitingcontainer.KubeWaitingContainer, string, error) {
	out, nextToken, err := k.svc.ListResources(ctx, pageSize, pageToken)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}

	return out, nextToken, nil
}

// GetKubernetesWaitingContainers returns all Kubernetes ephemeral
// containers that are waiting to be created until moderated
// session conditions are met.
func (k *KubeWaitingContainerService) GetKubernetesWaitingContainers(ctx context.Context) ([]*kubewaitingcontainer.KubeWaitingContainer, error) {
	out, err := k.svc.GetResources(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return out, nil
}

// GetKubernetesWaitingContainer returns a Kubernetes ephemeral
// container that are waiting to be created until moderated
// session conditions are met.
func (k *KubeWaitingContainerService) GetKubernetesWaitingContainer(ctx context.Context, req kubewaitingcontainerclient.KubeWaitingContainerRequest) (*kubewaitingcontainer.KubeWaitingContainer, error) {
	out, err := k.svc.WithPrefix(req.Username, req.Cluster, req.Namespace, req.PodName).GetResource(ctx, req.ContainerName)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return out, nil
}

// CreateKubernetesWaitingContainer creates a Kubernetes ephemeral
// container that are waiting to be created until moderated
// session conditions are met.
func (k *KubeWaitingContainerService) CreateKubernetesWaitingContainer(ctx context.Context, in *kubewaitingcontainer.KubeWaitingContainer) (*kubewaitingcontainer.KubeWaitingContainer, error) {
	out, err := k.svc.WithPrefix(in.GetParts()...).CreateResource(ctx, in)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return out, nil
}

// UpsertKubernetesWaitingContainer upserts a Kubernetes ephemeral
// container that are waiting to be created until moderated
// session conditions are met.
func (k *KubeWaitingContainerService) UpsertKubernetesWaitingContainer(ctx context.Context, in *kubewaitingcontainer.KubeWaitingContainer) (*kubewaitingcontainer.KubeWaitingContainer, error) {
	out, err := k.svc.WithPrefix(in.GetParts()...).UpsertResource(ctx, in)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return out, nil
}

// DeleteKubernetesWaitingContainer deletes a Kubernetes ephemeral
// container that are waiting to be created until moderated
// session conditions are met.
func (k *KubeWaitingContainerService) DeleteKubernetesWaitingContainer(ctx context.Context, req kubewaitingcontainerclient.KubeWaitingContainerRequest) error {
	return trace.Wrap(k.svc.WithPrefix(req.Username, req.Cluster, req.Namespace, req.PodName).DeleteResource(ctx, req.ContainerName))
}

// DeleteAllKubernetesWaitingContainers deletes all Kubernetes ephemeral
// containers that are waiting to be created until moderated
// session conditions are met.
func (k *KubeWaitingContainerService) DeleteAllKubernetesWaitingContainers(ctx context.Context) error {
	return trace.Wrap(k.svc.DeleteAllResources(ctx))
}
