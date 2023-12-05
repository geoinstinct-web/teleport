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

package handler

import (
	"context"
	"fmt"

	"github.com/gravitational/trace"
	"google.golang.org/protobuf/types/known/timestamppb"

	api "github.com/gravitational/teleport/gen/proto/go/teleport/lib/teleterm/v1"
	"github.com/gravitational/teleport/lib/teleterm/clusters"
)

func (s *Handler) GetRequestableRoles(ctx context.Context, req *api.GetRequestableRolesRequest) (*api.GetRequestableRolesResponse, error) {
	roles, err := s.DaemonService.GetRequestableRoles(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return roles, nil
}

// GetAccessRequests returns a list of all available access requests the user can view.
func (s *Handler) GetAccessRequests(ctx context.Context, req *api.GetAccessRequestsRequest) (*api.GetAccessRequestsResponse, error) {
	requests, err := s.DaemonService.GetAccessRequests(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	response := &api.GetAccessRequestsResponse{}
	for _, req := range requests {
		response.Requests = append(response.Requests, newAPIAccessRequest(req))
	}

	return response, nil
}

// GetAccessRequest returns a single access request by id.
func (s *Handler) GetAccessRequest(ctx context.Context, req *api.GetAccessRequestRequest) (*api.GetAccessRequestResponse, error) {
	request, err := s.DaemonService.GetAccessRequest(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	response := &api.GetAccessRequestResponse{}
	response.Request = newAPIAccessRequest(*request)

	return response, nil
}

// CreateAccessRequest creates an Access Request.
func (s *Handler) CreateAccessRequest(ctx context.Context, req *api.CreateAccessRequestRequest) (*api.CreateAccessRequestResponse, error) {
	request, err := s.DaemonService.CreateAccessRequest(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	createdRequest := &api.CreateAccessRequestResponse{
		Request: newAPIAccessRequest(*request),
	}
	return createdRequest, nil
}

// DeleteAccessRequest deletes an Access Request.
func (s *Handler) DeleteAccessRequest(ctx context.Context, req *api.DeleteAccessRequestRequest) (*api.EmptyResponse, error) {
	err := s.DaemonService.DeleteAccessRequest(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &api.EmptyResponse{}, nil
}

// AssumeRole reissues a certificate. This can include new RequestIds and RequestIds to drop from the cert at the same time.
func (s *Handler) AssumeRole(ctx context.Context, req *api.AssumeRoleRequest) (*api.EmptyResponse, error) {
	err := s.DaemonService.AssumeRole(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &api.EmptyResponse{}, nil
}

// ReviewAccessRequest creates a new AccessRequestReview for a given RequestId.
func (s *Handler) ReviewAccessRequest(ctx context.Context, req *api.ReviewAccessRequestRequest) (*api.ReviewAccessRequestResponse, error) {
	request, err := s.DaemonService.ReviewAccessRequest(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	response := &api.ReviewAccessRequestResponse{
		Request: newAPIAccessRequest(*request),
	}
	return response, nil
}

func newAPIAccessRequest(req clusters.AccessRequest) *api.AccessRequest {
	reviews := []*api.AccessRequestReview{}
	requestReviews := req.GetReviews()
	for _, rev := range requestReviews {
		reviews = append(reviews, &api.AccessRequestReview{
			Author:                  rev.Author,
			Roles:                   rev.Roles,
			State:                   rev.ProposedState.String(),
			Reason:                  rev.Reason,
			Created:                 timestamppb.New(rev.Created),
			PromotedAccessListTitle: rev.GetAccessListTitle(),
		})
	}

	thresholdNames := make([]string, 0, len(req.GetThresholds()))
	for _, t := range req.GetThresholds() {
		if t.Name != "" {
			thresholdNames = append(thresholdNames, t.Name)
		}
	}

	requestedResourceIDs := make([]*api.ResourceID, 0, len(req.GetRequestedResourceIDs()))
	for _, r := range req.GetRequestedResourceIDs() {
		requestedResourceIDs = append(requestedResourceIDs, &api.ResourceID{
			ClusterName:     r.ClusterName,
			Kind:            r.Kind,
			Name:            r.Name,
			SubResourceName: r.SubResourceName,
		})
	}
	resources := make([]*api.Resource, len(requestedResourceIDs))
	for i, r := range requestedResourceIDs {
		details := req.ResourceDetails[resourceIDToString(r)]

		resources[i] = &api.Resource{
			Id: &api.ResourceID{
				ClusterName:     r.ClusterName,
				Kind:            r.Kind,
				Name:            r.Name,
				SubResourceName: r.SubResourceName,
			},
			// If there are no details for this resource, the map lookup returns
			// the default value which is empty details
			Details: newAPIResourceDetails(details),
		}
	}

	return &api.AccessRequest{
		Id:                      req.GetName(),
		State:                   req.GetState().String(),
		ResolveReason:           req.GetResolveReason(),
		RequestReason:           req.GetRequestReason(),
		User:                    req.GetUser(),
		Roles:                   req.GetRoles(),
		Created:                 timestamppb.New(req.GetCreationTime()),
		Expires:                 timestamppb.New(req.GetAccessExpiry()),
		Reviews:                 reviews,
		SuggestedReviewers:      req.GetSuggestedReviewers(),
		ThresholdNames:          thresholdNames,
		ResourceIds:             requestedResourceIDs,
		Resources:               resources,
		PromotedAccessListTitle: req.GetPromotedAccessListTitle(),
	}
}

// resourceIDToString marshals a ResourceID to a string.
func resourceIDToString(id *api.ResourceID) string {
	if id.SubResourceName == "" {
		return fmt.Sprintf("/%s/%s/%s", id.ClusterName, id.Kind, id.Name)
	}
	return fmt.Sprintf("/%s/%s/%s/%s", id.ClusterName, id.Kind, id.Name, id.SubResourceName)
}

func newAPIResourceDetails(details clusters.ResourceDetails) *api.ResourceDetails {
	return &api.ResourceDetails{
		Hostname:     details.Hostname,
		FriendlyName: details.FriendlyName,
	}
}
