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
	"slices"

	"github.com/gravitational/trace"

	accessmonitoringrulesv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/accessmonitoringrules/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local/generic"
)

const accessMonitoringRulesPrefix = "access_monitoring_rule"

// AccessMonitoringRulesService manages AccessMonitoringRules in the Backend.
type AccessMonitoringRulesService struct {
	backend backend.Backend
	svc     *generic.ServiceWrapper[*accessmonitoringrulesv1.AccessMonitoringRule]
}

// NewAccessMonitoringRulesService creates a new AccessMonitoringRulesService.
func NewAccessMonitoringRulesService(backend backend.Backend) (*AccessMonitoringRulesService, error) {
	service, err := generic.NewServiceWrapper(backend,
		types.KindAccessMonitoringRule,
		accessMonitoringRulesPrefix,
		services.MarshalAccessMonitoringRule,
		services.UnmarshalAccessMonitoringRule)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &AccessMonitoringRulesService{
		svc: service,
	}, nil
}

// ListAccessMonitoringRules returns a paginated list of AccessMonitoringRule resources.
func (s *AccessMonitoringRulesService) ListAccessMonitoringRules(ctx context.Context, pageSize int, pageToken string) ([]*accessmonitoringrulesv1.AccessMonitoringRule, string, error) {
	igs, nextKey, err := s.svc.ListResources(ctx, pageSize, pageToken)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}

	return igs, nextKey, nil
}

// GetAccessMonitoringRule returns the specified AccessMonitoringRule resource.
func (s *AccessMonitoringRulesService) GetAccessMonitoringRule(ctx context.Context, name string) (*accessmonitoringrulesv1.AccessMonitoringRule, error) {
	ig, err := s.svc.GetResource(ctx, name)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return ig, nil
}

// CreateAccessMonitoringRule creates a new AccessMonitoringRule resource.
func (s *AccessMonitoringRulesService) CreateAccessMonitoringRule(ctx context.Context, amr *accessmonitoringrulesv1.AccessMonitoringRule) (*accessmonitoringrulesv1.AccessMonitoringRule, error) {
	if err := services.ValidateAccessMonitoringRule(amr); err != nil {
		return nil, trace.Wrap(err)
	}
	created, err := s.svc.CreateResource(ctx, amr)
	return created, trace.Wrap(err)
}

// UpdateAccessMonitoringRule updates an existing AccessMonitoringRule resource.
func (s *AccessMonitoringRulesService) UpdateAccessMonitoringRule(ctx context.Context, amr *accessmonitoringrulesv1.AccessMonitoringRule) (*accessmonitoringrulesv1.AccessMonitoringRule, error) {
	if err := services.ValidateAccessMonitoringRule(amr); err != nil {
		return nil, trace.Wrap(err)
	}

	updated, err := s.svc.UpdateResource(ctx, amr)
	return updated, trace.Wrap(err)
}

// UpsertAccessMonitoringRule upserts an existing AccessMonitoringRule resource.
func (s *AccessMonitoringRulesService) UpsertAccessMonitoringRule(ctx context.Context, amr *accessmonitoringrulesv1.AccessMonitoringRule) (*accessmonitoringrulesv1.AccessMonitoringRule, error) {
	if err := services.ValidateAccessMonitoringRule(amr); err != nil {
		return nil, trace.Wrap(err)
	}

	upserted, err := s.svc.UpsertResource(ctx, amr)
	return upserted, trace.Wrap(err)
}

// DeleteAccessMonitoringRule removes the specified AccessMonitoringRule resource.
func (s *AccessMonitoringRulesService) DeleteAccessMonitoringRule(ctx context.Context, name string) error {
	return trace.Wrap(s.svc.DeleteResource(ctx, name))
}

// DeleteAllAccessMonitoringRules removes all AccessMonitoringRule resources.
func (s *AccessMonitoringRulesService) DeleteAllAccessMonitoringRules(ctx context.Context) error {
	return trace.Wrap(s.svc.DeleteAllResources(ctx))
}

func (s *AccessMonitoringRulesService) ListAccessMonitoringRulesWithFilter(ctx context.Context, pageSize int, pageToken string, subjects []string, notificationName string) ([]*accessmonitoringrulesv1.AccessMonitoringRule, string, error) {

	var keyPrefix []string
	var unmarshalItemFunc backendItemToResourceFunc

	rangeStart := backend.Key(accessMonitoringRulesPrefix, pageToken)
	rangeEnd := backend.RangeEnd(backend.ExactKey(keyPrefix...))

	// Get most limit+1 results to determine if there will be a next key.
	maxLimit := pageSize + 1
	var resources []*accessmonitoringrulesv1.AccessMonitoringRule
	if err := backend.IterateRange(ctx, s.backend, rangeStart, rangeEnd, maxLimit, func(items []backend.Item) (stop bool, err error) {
		for _, item := range items {
			if len(resources) == maxLimit {
				break
			}

			resource, err := unmarshalItemFunc(item)
			if err != nil {
				return false, trace.Wrap(err)
			}
			accessMonitoringRule := types.LegacyToResource153(resource).(*accessmonitoringrulesv1.AccessMonitoringRule)
			if ok := match(accessMonitoringRule, subjects, notificationName); ok {
				resources = append(resources, accessMonitoringRule)
			}
		}

		return len(resources) == maxLimit, nil
	}); err != nil {
		return nil, "", trace.Wrap(err)
	}

	var nextKey string
	if len(resources) > pageSize {
		nextKey = resources[len(resources)-1].Metadata.Name
		// Truncate the last item that was used to determine next row existence.
		resources = resources[:pageSize]
	}

	return resources, nextKey, nil
}

func match(rule *accessmonitoringrulesv1.AccessMonitoringRule, subjects []string, notificationName string) bool {
	for _, subject := range subjects {
		if ok := slices.ContainsFunc(rule.Spec.Subjects, func(s string) bool {
			return s == subject
		}); !ok {
			return false
		}
	}
	if notificationName != "" {
		if rule.Spec.Notification == nil || rule.Spec.Notification.Name != notificationName {
			return false
		}
	}
	return true
}
