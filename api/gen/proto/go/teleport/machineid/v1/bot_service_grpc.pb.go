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
// source: teleport/machineid/v1/bot_service.proto

package machineidv1

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
	BotService_GetBot_FullMethodName    = "/teleport.machineid.v1.BotService/GetBot"
	BotService_ListBots_FullMethodName  = "/teleport.machineid.v1.BotService/ListBots"
	BotService_CreateBot_FullMethodName = "/teleport.machineid.v1.BotService/CreateBot"
	BotService_UpdateBot_FullMethodName = "/teleport.machineid.v1.BotService/UpdateBot"
	BotService_UpsertBot_FullMethodName = "/teleport.machineid.v1.BotService/UpsertBot"
	BotService_DeleteBot_FullMethodName = "/teleport.machineid.v1.BotService/DeleteBot"
)

// BotServiceClient is the client API for BotService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type BotServiceClient interface {
	// GetBot is used to query a Bot resource by its name.
	//
	// This will return a NotFound error if the specified Bot does not exist.
	GetBot(ctx context.Context, in *GetBotRequest, opts ...grpc.CallOption) (*Bot, error)
	// ListBots is used to query Bots.
	//
	// Follows the pagination semantics of
	// https://cloud.google.com/apis/design/standard_methods#list.
	ListBots(ctx context.Context, in *ListBotsRequest, opts ...grpc.CallOption) (*ListBotsResponse, error)
	// CreateBot is used to create a Bot.
	//
	// This will return an error if a Bot by that name already exists.
	CreateBot(ctx context.Context, in *CreateBotRequest, opts ...grpc.CallOption) (*Bot, error)
	// UpdateBot is used to modify an existing Bot.
	UpdateBot(ctx context.Context, in *UpdateBotRequest, opts ...grpc.CallOption) (*Bot, error)
	// UpsertBot is used to create or replace an existing Bot.
	//
	// Prefer using CreateBot and UpdateBot.
	UpsertBot(ctx context.Context, in *UpsertBotRequest, opts ...grpc.CallOption) (*Bot, error)
	// DeleteBot is used to delete a specific Bot.
	//
	// This will return a NotFound error if the specified Bot does not exist.
	DeleteBot(ctx context.Context, in *DeleteBotRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type botServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewBotServiceClient(cc grpc.ClientConnInterface) BotServiceClient {
	return &botServiceClient{cc}
}

func (c *botServiceClient) GetBot(ctx context.Context, in *GetBotRequest, opts ...grpc.CallOption) (*Bot, error) {
	out := new(Bot)
	err := c.cc.Invoke(ctx, BotService_GetBot_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *botServiceClient) ListBots(ctx context.Context, in *ListBotsRequest, opts ...grpc.CallOption) (*ListBotsResponse, error) {
	out := new(ListBotsResponse)
	err := c.cc.Invoke(ctx, BotService_ListBots_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *botServiceClient) CreateBot(ctx context.Context, in *CreateBotRequest, opts ...grpc.CallOption) (*Bot, error) {
	out := new(Bot)
	err := c.cc.Invoke(ctx, BotService_CreateBot_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *botServiceClient) UpdateBot(ctx context.Context, in *UpdateBotRequest, opts ...grpc.CallOption) (*Bot, error) {
	out := new(Bot)
	err := c.cc.Invoke(ctx, BotService_UpdateBot_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *botServiceClient) UpsertBot(ctx context.Context, in *UpsertBotRequest, opts ...grpc.CallOption) (*Bot, error) {
	out := new(Bot)
	err := c.cc.Invoke(ctx, BotService_UpsertBot_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *botServiceClient) DeleteBot(ctx context.Context, in *DeleteBotRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, BotService_DeleteBot_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// BotServiceServer is the server API for BotService service.
// All implementations must embed UnimplementedBotServiceServer
// for forward compatibility
type BotServiceServer interface {
	// GetBot is used to query a Bot resource by its name.
	//
	// This will return a NotFound error if the specified Bot does not exist.
	GetBot(context.Context, *GetBotRequest) (*Bot, error)
	// ListBots is used to query Bots.
	//
	// Follows the pagination semantics of
	// https://cloud.google.com/apis/design/standard_methods#list.
	ListBots(context.Context, *ListBotsRequest) (*ListBotsResponse, error)
	// CreateBot is used to create a Bot.
	//
	// This will return an error if a Bot by that name already exists.
	CreateBot(context.Context, *CreateBotRequest) (*Bot, error)
	// UpdateBot is used to modify an existing Bot.
	UpdateBot(context.Context, *UpdateBotRequest) (*Bot, error)
	// UpsertBot is used to create or replace an existing Bot.
	//
	// Prefer using CreateBot and UpdateBot.
	UpsertBot(context.Context, *UpsertBotRequest) (*Bot, error)
	// DeleteBot is used to delete a specific Bot.
	//
	// This will return a NotFound error if the specified Bot does not exist.
	DeleteBot(context.Context, *DeleteBotRequest) (*emptypb.Empty, error)
	mustEmbedUnimplementedBotServiceServer()
}

// UnimplementedBotServiceServer must be embedded to have forward compatible implementations.
type UnimplementedBotServiceServer struct {
}

func (UnimplementedBotServiceServer) GetBot(context.Context, *GetBotRequest) (*Bot, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetBot not implemented")
}
func (UnimplementedBotServiceServer) ListBots(context.Context, *ListBotsRequest) (*ListBotsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListBots not implemented")
}
func (UnimplementedBotServiceServer) CreateBot(context.Context, *CreateBotRequest) (*Bot, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateBot not implemented")
}
func (UnimplementedBotServiceServer) UpdateBot(context.Context, *UpdateBotRequest) (*Bot, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateBot not implemented")
}
func (UnimplementedBotServiceServer) UpsertBot(context.Context, *UpsertBotRequest) (*Bot, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertBot not implemented")
}
func (UnimplementedBotServiceServer) DeleteBot(context.Context, *DeleteBotRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteBot not implemented")
}
func (UnimplementedBotServiceServer) mustEmbedUnimplementedBotServiceServer() {}

// UnsafeBotServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to BotServiceServer will
// result in compilation errors.
type UnsafeBotServiceServer interface {
	mustEmbedUnimplementedBotServiceServer()
}

func RegisterBotServiceServer(s grpc.ServiceRegistrar, srv BotServiceServer) {
	s.RegisterService(&BotService_ServiceDesc, srv)
}

func _BotService_GetBot_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetBotRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BotServiceServer).GetBot(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: BotService_GetBot_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BotServiceServer).GetBot(ctx, req.(*GetBotRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _BotService_ListBots_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListBotsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BotServiceServer).ListBots(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: BotService_ListBots_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BotServiceServer).ListBots(ctx, req.(*ListBotsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _BotService_CreateBot_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateBotRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BotServiceServer).CreateBot(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: BotService_CreateBot_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BotServiceServer).CreateBot(ctx, req.(*CreateBotRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _BotService_UpdateBot_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateBotRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BotServiceServer).UpdateBot(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: BotService_UpdateBot_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BotServiceServer).UpdateBot(ctx, req.(*UpdateBotRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _BotService_UpsertBot_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpsertBotRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BotServiceServer).UpsertBot(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: BotService_UpsertBot_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BotServiceServer).UpsertBot(ctx, req.(*UpsertBotRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _BotService_DeleteBot_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteBotRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BotServiceServer).DeleteBot(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: BotService_DeleteBot_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BotServiceServer).DeleteBot(ctx, req.(*DeleteBotRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// BotService_ServiceDesc is the grpc.ServiceDesc for BotService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var BotService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "teleport.machineid.v1.BotService",
	HandlerType: (*BotServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetBot",
			Handler:    _BotService_GetBot_Handler,
		},
		{
			MethodName: "ListBots",
			Handler:    _BotService_ListBots_Handler,
		},
		{
			MethodName: "CreateBot",
			Handler:    _BotService_CreateBot_Handler,
		},
		{
			MethodName: "UpdateBot",
			Handler:    _BotService_UpdateBot_Handler,
		},
		{
			MethodName: "UpsertBot",
			Handler:    _BotService_UpsertBot_Handler,
		},
		{
			MethodName: "DeleteBot",
			Handler:    _BotService_DeleteBot_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "teleport/machineid/v1/bot_service.proto",
}
