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

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: teleport/userpreferences/v1/userpreferences.proto

package userpreferencesv1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	UserPreferencesService_GetUserPreferences_FullMethodName    = "/teleport.userpreferences.v1.UserPreferencesService/GetUserPreferences"
	UserPreferencesService_UpsertUserPreferences_FullMethodName = "/teleport.userpreferences.v1.UserPreferencesService/UpsertUserPreferences"
)

// UserPreferencesServiceClient is the client API for UserPreferencesService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type UserPreferencesServiceClient interface {
	// GetUserPreferences returns the user preferences for a given user.
	GetUserPreferences(ctx context.Context, in *GetUserPreferencesRequest, opts ...grpc.CallOption) (*GetUserPreferencesResponse, error)
	// UpsertUserPreferences creates or updates user preferences for a given username.
	UpsertUserPreferences(ctx context.Context, in *UpsertUserPreferencesRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type userPreferencesServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewUserPreferencesServiceClient(cc grpc.ClientConnInterface) UserPreferencesServiceClient {
	return &userPreferencesServiceClient{cc}
}

func (c *userPreferencesServiceClient) GetUserPreferences(ctx context.Context, in *GetUserPreferencesRequest, opts ...grpc.CallOption) (*GetUserPreferencesResponse, error) {
	out := new(GetUserPreferencesResponse)
	err := c.cc.Invoke(ctx, UserPreferencesService_GetUserPreferences_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *userPreferencesServiceClient) UpsertUserPreferences(ctx context.Context, in *UpsertUserPreferencesRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, UserPreferencesService_UpsertUserPreferences_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UserPreferencesServiceServer is the server API for UserPreferencesService service.
// All implementations must embed UnimplementedUserPreferencesServiceServer
// for forward compatibility
type UserPreferencesServiceServer interface {
	// GetUserPreferences returns the user preferences for a given user.
	GetUserPreferences(context.Context, *GetUserPreferencesRequest) (*GetUserPreferencesResponse, error)
	// UpsertUserPreferences creates or updates user preferences for a given username.
	UpsertUserPreferences(context.Context, *UpsertUserPreferencesRequest) (*emptypb.Empty, error)
	mustEmbedUnimplementedUserPreferencesServiceServer()
}

// UnimplementedUserPreferencesServiceServer must be embedded to have forward compatible implementations.
type UnimplementedUserPreferencesServiceServer struct {
}

func (UnimplementedUserPreferencesServiceServer) GetUserPreferences(context.Context, *GetUserPreferencesRequest) (*GetUserPreferencesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUserPreferences not implemented")
}
func (UnimplementedUserPreferencesServiceServer) UpsertUserPreferences(context.Context, *UpsertUserPreferencesRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertUserPreferences not implemented")
}
func (UnimplementedUserPreferencesServiceServer) mustEmbedUnimplementedUserPreferencesServiceServer() {
}

// UnsafeUserPreferencesServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to UserPreferencesServiceServer will
// result in compilation errors.
type UnsafeUserPreferencesServiceServer interface {
	mustEmbedUnimplementedUserPreferencesServiceServer()
}

func RegisterUserPreferencesServiceServer(s grpc.ServiceRegistrar, srv UserPreferencesServiceServer) {
	s.RegisterService(&UserPreferencesService_ServiceDesc, srv)
}

func _UserPreferencesService_GetUserPreferences_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetUserPreferencesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UserPreferencesServiceServer).GetUserPreferences(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: UserPreferencesService_GetUserPreferences_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UserPreferencesServiceServer).GetUserPreferences(ctx, req.(*GetUserPreferencesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UserPreferencesService_UpsertUserPreferences_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpsertUserPreferencesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UserPreferencesServiceServer).UpsertUserPreferences(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: UserPreferencesService_UpsertUserPreferences_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UserPreferencesServiceServer).UpsertUserPreferences(ctx, req.(*UpsertUserPreferencesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// UserPreferencesService_ServiceDesc is the grpc.ServiceDesc for UserPreferencesService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var UserPreferencesService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "teleport.userpreferences.v1.UserPreferencesService",
	HandlerType: (*UserPreferencesServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetUserPreferences",
			Handler:    _UserPreferencesService_GetUserPreferences_Handler,
		},
		{
			MethodName: "UpsertUserPreferences",
			Handler:    _UserPreferencesService_UpsertUserPreferences_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "teleport/userpreferences/v1/userpreferences.proto",
}
