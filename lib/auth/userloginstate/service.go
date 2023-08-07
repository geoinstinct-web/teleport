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

package userloginstate

import (
	"context"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/emptypb"

	userloginstatev1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/userloginstate/v1"
	"github.com/gravitational/teleport/api/types"
	conv "github.com/gravitational/teleport/api/types/userloginstate/convert/v1"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/services"
)

// ServiceConfig is the service config for the Access Lists gRPC service.
type ServiceConfig struct {
	// Logger is the logger to use.
	Logger logrus.FieldLogger

	// Authorizer is the authorizer to use.
	Authorizer authz.Authorizer

	// UserLoginStates is the user login state service to use.
	UserLoginStates services.UserLoginStates

	// Clock is the clock.
	Clock clockwork.Clock
}

func (c *ServiceConfig) checkAndSetDefaults() error {
	if c.Authorizer == nil {
		return trace.BadParameter("authorizer is missing")
	}

	if c.UserLoginStates == nil {
		return trace.BadParameter("user login states service is missing")
	}

	if c.Logger == nil {
		c.Logger = logrus.New().WithField(trace.Component, "user_login_state_crud_service")
	}

	if c.Clock == nil {
		c.Clock = clockwork.NewRealClock()
	}

	return nil
}

type Service struct {
	userloginstatev1.UnimplementedUserLoginStateServiceServer

	log             logrus.FieldLogger
	authorizer      authz.Authorizer
	userLoginStates services.UserLoginStates
	clock           clockwork.Clock
}

// NewService creates a new User Login State gRPC service.
func NewService(cfg ServiceConfig) (*Service, error) {
	if err := cfg.checkAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	return &Service{
		log:             cfg.Logger,
		authorizer:      cfg.Authorizer,
		userLoginStates: cfg.UserLoginStates,
		clock:           cfg.Clock,
	}, nil
}

// GetUserLoginStates returns a list of all user login states.
func (s *Service) GetUserLoginStates(ctx context.Context, _ *userloginstatev1.GetUserLoginStatesRequest) (*userloginstatev1.GetUserLoginStatesResponse, error) {
	_, err := authz.AuthorizeWithVerbs(ctx, s.log, s.authorizer, true, types.KindUserLoginState, types.VerbRead, types.VerbList)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	results, err := s.userLoginStates.GetUserLoginStates(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	ulsList := make([]*userloginstatev1.UserLoginState, len(results))
	for i, r := range results {
		ulsList[i] = conv.ToProto(r)
	}

	return &userloginstatev1.GetUserLoginStatesResponse{
		UserLoginStates: ulsList,
	}, nil
}

// GetUserLoginState returns the specified user login state resource.
func (s *Service) GetUserLoginState(ctx context.Context, req *userloginstatev1.GetUserLoginStateRequest) (*userloginstatev1.UserLoginState, error) {
	_, err := authz.AuthorizeWithVerbs(ctx, s.log, s.authorizer, true, types.KindUserLoginState, types.VerbRead)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	result, err := s.userLoginStates.GetUserLoginState(ctx, req.GetName())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return conv.ToProto(result), nil
}

// UpsertUserLoginState creates or updates a user login state resource.
func (s *Service) UpsertUserLoginState(ctx context.Context, req *userloginstatev1.UpsertUserLoginStateRequest) (*userloginstatev1.UserLoginState, error) {
	_, err := authz.AuthorizeWithVerbs(ctx, s.log, s.authorizer, true, types.KindUserLoginState, types.VerbCreate, types.VerbUpdate)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	newUls, err := conv.FromProto(req.GetUserLoginState())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	responseUls, err := s.userLoginStates.UpsertUserLoginState(ctx, newUls)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return conv.ToProto(responseUls), nil
}

// DeleteUserLoginState removes the specified user login state resource.
func (s *Service) DeleteUserLoginState(ctx context.Context, req *userloginstatev1.DeleteUserLoginStateRequest) (*emptypb.Empty, error) {
	_, err := authz.AuthorizeWithVerbs(ctx, s.log, s.authorizer, true, types.KindUserLoginState, types.VerbDelete)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = s.userLoginStates.DeleteUserLoginState(ctx, req.GetName())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &emptypb.Empty{}, nil
}

// DeleteAllUserLoginStates removes all user login states.
func (s *Service) DeleteAllUserLoginStates(ctx context.Context, _ *userloginstatev1.DeleteAllUserLoginStatesRequest) (*emptypb.Empty, error) {
	_, err := authz.AuthorizeWithVerbs(ctx, s.log, s.authorizer, true, types.KindUserLoginState, types.VerbDelete)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = s.userLoginStates.DeleteAllUserLoginStates(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &emptypb.Empty{}, nil
}
