// Copyright 2022 Gravitational, Inc
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
// source: teleport/loginrule/v1/loginrule_service.proto

package v1

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
	LoginRuleService_CreateLoginRule_FullMethodName = "/teleport.loginrule.v1.LoginRuleService/CreateLoginRule"
	LoginRuleService_UpsertLoginRule_FullMethodName = "/teleport.loginrule.v1.LoginRuleService/UpsertLoginRule"
	LoginRuleService_GetLoginRule_FullMethodName    = "/teleport.loginrule.v1.LoginRuleService/GetLoginRule"
	LoginRuleService_ListLoginRules_FullMethodName  = "/teleport.loginrule.v1.LoginRuleService/ListLoginRules"
	LoginRuleService_DeleteLoginRule_FullMethodName = "/teleport.loginrule.v1.LoginRuleService/DeleteLoginRule"
)

// LoginRuleServiceClient is the client API for LoginRuleService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type LoginRuleServiceClient interface {
	// CreateLoginRule creates a login rule if one with the same name does not
	// already exist, else it returns an error.
	CreateLoginRule(ctx context.Context, in *CreateLoginRuleRequest, opts ...grpc.CallOption) (*LoginRule, error)
	// UpsertLoginRule creates a login rule if one with the same name does not
	// already exist, else it replaces the existing login rule.
	UpsertLoginRule(ctx context.Context, in *UpsertLoginRuleRequest, opts ...grpc.CallOption) (*LoginRule, error)
	// GetLoginRule retrieves a login rule described by the given request.
	GetLoginRule(ctx context.Context, in *GetLoginRuleRequest, opts ...grpc.CallOption) (*LoginRule, error)
	// ListLoginRules lists all login rules.
	ListLoginRules(ctx context.Context, in *ListLoginRulesRequest, opts ...grpc.CallOption) (*ListLoginRulesResponse, error)
	// DeleteLoginRule deletes an existing login rule.
	DeleteLoginRule(ctx context.Context, in *DeleteLoginRuleRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type loginRuleServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewLoginRuleServiceClient(cc grpc.ClientConnInterface) LoginRuleServiceClient {
	return &loginRuleServiceClient{cc}
}

func (c *loginRuleServiceClient) CreateLoginRule(ctx context.Context, in *CreateLoginRuleRequest, opts ...grpc.CallOption) (*LoginRule, error) {
	out := new(LoginRule)
	err := c.cc.Invoke(ctx, LoginRuleService_CreateLoginRule_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *loginRuleServiceClient) UpsertLoginRule(ctx context.Context, in *UpsertLoginRuleRequest, opts ...grpc.CallOption) (*LoginRule, error) {
	out := new(LoginRule)
	err := c.cc.Invoke(ctx, LoginRuleService_UpsertLoginRule_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *loginRuleServiceClient) GetLoginRule(ctx context.Context, in *GetLoginRuleRequest, opts ...grpc.CallOption) (*LoginRule, error) {
	out := new(LoginRule)
	err := c.cc.Invoke(ctx, LoginRuleService_GetLoginRule_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *loginRuleServiceClient) ListLoginRules(ctx context.Context, in *ListLoginRulesRequest, opts ...grpc.CallOption) (*ListLoginRulesResponse, error) {
	out := new(ListLoginRulesResponse)
	err := c.cc.Invoke(ctx, LoginRuleService_ListLoginRules_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *loginRuleServiceClient) DeleteLoginRule(ctx context.Context, in *DeleteLoginRuleRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, LoginRuleService_DeleteLoginRule_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// LoginRuleServiceServer is the server API for LoginRuleService service.
// All implementations must embed UnimplementedLoginRuleServiceServer
// for forward compatibility
type LoginRuleServiceServer interface {
	// CreateLoginRule creates a login rule if one with the same name does not
	// already exist, else it returns an error.
	CreateLoginRule(context.Context, *CreateLoginRuleRequest) (*LoginRule, error)
	// UpsertLoginRule creates a login rule if one with the same name does not
	// already exist, else it replaces the existing login rule.
	UpsertLoginRule(context.Context, *UpsertLoginRuleRequest) (*LoginRule, error)
	// GetLoginRule retrieves a login rule described by the given request.
	GetLoginRule(context.Context, *GetLoginRuleRequest) (*LoginRule, error)
	// ListLoginRules lists all login rules.
	ListLoginRules(context.Context, *ListLoginRulesRequest) (*ListLoginRulesResponse, error)
	// DeleteLoginRule deletes an existing login rule.
	DeleteLoginRule(context.Context, *DeleteLoginRuleRequest) (*emptypb.Empty, error)
	mustEmbedUnimplementedLoginRuleServiceServer()
}

// UnimplementedLoginRuleServiceServer must be embedded to have forward compatible implementations.
type UnimplementedLoginRuleServiceServer struct {
}

func (UnimplementedLoginRuleServiceServer) CreateLoginRule(context.Context, *CreateLoginRuleRequest) (*LoginRule, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateLoginRule not implemented")
}
func (UnimplementedLoginRuleServiceServer) UpsertLoginRule(context.Context, *UpsertLoginRuleRequest) (*LoginRule, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertLoginRule not implemented")
}
func (UnimplementedLoginRuleServiceServer) GetLoginRule(context.Context, *GetLoginRuleRequest) (*LoginRule, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetLoginRule not implemented")
}
func (UnimplementedLoginRuleServiceServer) ListLoginRules(context.Context, *ListLoginRulesRequest) (*ListLoginRulesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListLoginRules not implemented")
}
func (UnimplementedLoginRuleServiceServer) DeleteLoginRule(context.Context, *DeleteLoginRuleRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteLoginRule not implemented")
}
func (UnimplementedLoginRuleServiceServer) mustEmbedUnimplementedLoginRuleServiceServer() {}

// UnsafeLoginRuleServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to LoginRuleServiceServer will
// result in compilation errors.
type UnsafeLoginRuleServiceServer interface {
	mustEmbedUnimplementedLoginRuleServiceServer()
}

func RegisterLoginRuleServiceServer(s grpc.ServiceRegistrar, srv LoginRuleServiceServer) {
	s.RegisterService(&LoginRuleService_ServiceDesc, srv)
}

func _LoginRuleService_CreateLoginRule_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateLoginRuleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LoginRuleServiceServer).CreateLoginRule(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: LoginRuleService_CreateLoginRule_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LoginRuleServiceServer).CreateLoginRule(ctx, req.(*CreateLoginRuleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _LoginRuleService_UpsertLoginRule_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpsertLoginRuleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LoginRuleServiceServer).UpsertLoginRule(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: LoginRuleService_UpsertLoginRule_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LoginRuleServiceServer).UpsertLoginRule(ctx, req.(*UpsertLoginRuleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _LoginRuleService_GetLoginRule_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetLoginRuleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LoginRuleServiceServer).GetLoginRule(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: LoginRuleService_GetLoginRule_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LoginRuleServiceServer).GetLoginRule(ctx, req.(*GetLoginRuleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _LoginRuleService_ListLoginRules_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListLoginRulesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LoginRuleServiceServer).ListLoginRules(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: LoginRuleService_ListLoginRules_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LoginRuleServiceServer).ListLoginRules(ctx, req.(*ListLoginRulesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _LoginRuleService_DeleteLoginRule_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteLoginRuleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LoginRuleServiceServer).DeleteLoginRule(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: LoginRuleService_DeleteLoginRule_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LoginRuleServiceServer).DeleteLoginRule(ctx, req.(*DeleteLoginRuleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// LoginRuleService_ServiceDesc is the grpc.ServiceDesc for LoginRuleService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var LoginRuleService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "teleport.loginrule.v1.LoginRuleService",
	HandlerType: (*LoginRuleServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateLoginRule",
			Handler:    _LoginRuleService_CreateLoginRule_Handler,
		},
		{
			MethodName: "UpsertLoginRule",
			Handler:    _LoginRuleService_UpsertLoginRule_Handler,
		},
		{
			MethodName: "GetLoginRule",
			Handler:    _LoginRuleService_GetLoginRule_Handler,
		},
		{
			MethodName: "ListLoginRules",
			Handler:    _LoginRuleService_ListLoginRules_Handler,
		},
		{
			MethodName: "DeleteLoginRule",
			Handler:    _LoginRuleService_DeleteLoginRule_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "teleport/loginrule/v1/loginrule_service.proto",
}
