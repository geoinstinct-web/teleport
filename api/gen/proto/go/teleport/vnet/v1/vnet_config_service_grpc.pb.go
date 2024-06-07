// Copyright 2024 Gravitational, Inc.
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
// - protoc-gen-go-grpc v1.4.0
// - protoc             (unknown)
// source: teleport/vnet/v1/vnet_config_service.proto

package vnet

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.62.0 or later.
const _ = grpc.SupportPackageIsVersion8

const (
	VnetConfigService_GetVnetConfig_FullMethodName    = "/teleport.vnet.v1.VnetConfigService/GetVnetConfig"
	VnetConfigService_CreateVnetConfig_FullMethodName = "/teleport.vnet.v1.VnetConfigService/CreateVnetConfig"
	VnetConfigService_UpdateVnetConfig_FullMethodName = "/teleport.vnet.v1.VnetConfigService/UpdateVnetConfig"
	VnetConfigService_UpsertVnetConfig_FullMethodName = "/teleport.vnet.v1.VnetConfigService/UpsertVnetConfig"
	VnetConfigService_DeleteVnetConfig_FullMethodName = "/teleport.vnet.v1.VnetConfigService/DeleteVnetConfig"
)

// VnetConfigServiceClient is the client API for VnetConfigService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// VnetConfigService provides an API to manage the singleton VnetConfig.
type VnetConfigServiceClient interface {
	// GetVnetConfig returns the specified VnetConfig.
	GetVnetConfig(ctx context.Context, in *GetVnetConfigRequest, opts ...grpc.CallOption) (*VnetConfig, error)
	// CreateVnetConfig creates a new VnetConfig.
	CreateVnetConfig(ctx context.Context, in *CreateVnetConfigRequest, opts ...grpc.CallOption) (*VnetConfig, error)
	// UpdateVnetConfig updates an existing VnetConfig.
	UpdateVnetConfig(ctx context.Context, in *UpdateVnetConfigRequest, opts ...grpc.CallOption) (*VnetConfig, error)
	// UpsertVnetConfig creates a new VnetConfig or replaces an existing VnetConfig.
	UpsertVnetConfig(ctx context.Context, in *UpsertVnetConfigRequest, opts ...grpc.CallOption) (*VnetConfig, error)
	// DeleteVnetConfig hard deletes the specified VnetConfig.
	DeleteVnetConfig(ctx context.Context, in *DeleteVnetConfigRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type vnetConfigServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewVnetConfigServiceClient(cc grpc.ClientConnInterface) VnetConfigServiceClient {
	return &vnetConfigServiceClient{cc}
}

func (c *vnetConfigServiceClient) GetVnetConfig(ctx context.Context, in *GetVnetConfigRequest, opts ...grpc.CallOption) (*VnetConfig, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(VnetConfig)
	err := c.cc.Invoke(ctx, VnetConfigService_GetVnetConfig_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *vnetConfigServiceClient) CreateVnetConfig(ctx context.Context, in *CreateVnetConfigRequest, opts ...grpc.CallOption) (*VnetConfig, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(VnetConfig)
	err := c.cc.Invoke(ctx, VnetConfigService_CreateVnetConfig_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *vnetConfigServiceClient) UpdateVnetConfig(ctx context.Context, in *UpdateVnetConfigRequest, opts ...grpc.CallOption) (*VnetConfig, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(VnetConfig)
	err := c.cc.Invoke(ctx, VnetConfigService_UpdateVnetConfig_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *vnetConfigServiceClient) UpsertVnetConfig(ctx context.Context, in *UpsertVnetConfigRequest, opts ...grpc.CallOption) (*VnetConfig, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(VnetConfig)
	err := c.cc.Invoke(ctx, VnetConfigService_UpsertVnetConfig_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *vnetConfigServiceClient) DeleteVnetConfig(ctx context.Context, in *DeleteVnetConfigRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, VnetConfigService_DeleteVnetConfig_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// VnetConfigServiceServer is the server API for VnetConfigService service.
// All implementations must embed UnimplementedVnetConfigServiceServer
// for forward compatibility
//
// VnetConfigService provides an API to manage the singleton VnetConfig.
type VnetConfigServiceServer interface {
	// GetVnetConfig returns the specified VnetConfig.
	GetVnetConfig(context.Context, *GetVnetConfigRequest) (*VnetConfig, error)
	// CreateVnetConfig creates a new VnetConfig.
	CreateVnetConfig(context.Context, *CreateVnetConfigRequest) (*VnetConfig, error)
	// UpdateVnetConfig updates an existing VnetConfig.
	UpdateVnetConfig(context.Context, *UpdateVnetConfigRequest) (*VnetConfig, error)
	// UpsertVnetConfig creates a new VnetConfig or replaces an existing VnetConfig.
	UpsertVnetConfig(context.Context, *UpsertVnetConfigRequest) (*VnetConfig, error)
	// DeleteVnetConfig hard deletes the specified VnetConfig.
	DeleteVnetConfig(context.Context, *DeleteVnetConfigRequest) (*emptypb.Empty, error)
	mustEmbedUnimplementedVnetConfigServiceServer()
}

// UnimplementedVnetConfigServiceServer must be embedded to have forward compatible implementations.
type UnimplementedVnetConfigServiceServer struct {
}

func (UnimplementedVnetConfigServiceServer) GetVnetConfig(context.Context, *GetVnetConfigRequest) (*VnetConfig, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetVnetConfig not implemented")
}
func (UnimplementedVnetConfigServiceServer) CreateVnetConfig(context.Context, *CreateVnetConfigRequest) (*VnetConfig, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateVnetConfig not implemented")
}
func (UnimplementedVnetConfigServiceServer) UpdateVnetConfig(context.Context, *UpdateVnetConfigRequest) (*VnetConfig, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateVnetConfig not implemented")
}
func (UnimplementedVnetConfigServiceServer) UpsertVnetConfig(context.Context, *UpsertVnetConfigRequest) (*VnetConfig, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertVnetConfig not implemented")
}
func (UnimplementedVnetConfigServiceServer) DeleteVnetConfig(context.Context, *DeleteVnetConfigRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteVnetConfig not implemented")
}
func (UnimplementedVnetConfigServiceServer) mustEmbedUnimplementedVnetConfigServiceServer() {}

// UnsafeVnetConfigServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to VnetConfigServiceServer will
// result in compilation errors.
type UnsafeVnetConfigServiceServer interface {
	mustEmbedUnimplementedVnetConfigServiceServer()
}

func RegisterVnetConfigServiceServer(s grpc.ServiceRegistrar, srv VnetConfigServiceServer) {
	s.RegisterService(&VnetConfigService_ServiceDesc, srv)
}

func _VnetConfigService_GetVnetConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetVnetConfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VnetConfigServiceServer).GetVnetConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: VnetConfigService_GetVnetConfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VnetConfigServiceServer).GetVnetConfig(ctx, req.(*GetVnetConfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _VnetConfigService_CreateVnetConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateVnetConfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VnetConfigServiceServer).CreateVnetConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: VnetConfigService_CreateVnetConfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VnetConfigServiceServer).CreateVnetConfig(ctx, req.(*CreateVnetConfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _VnetConfigService_UpdateVnetConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateVnetConfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VnetConfigServiceServer).UpdateVnetConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: VnetConfigService_UpdateVnetConfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VnetConfigServiceServer).UpdateVnetConfig(ctx, req.(*UpdateVnetConfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _VnetConfigService_UpsertVnetConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpsertVnetConfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VnetConfigServiceServer).UpsertVnetConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: VnetConfigService_UpsertVnetConfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VnetConfigServiceServer).UpsertVnetConfig(ctx, req.(*UpsertVnetConfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _VnetConfigService_DeleteVnetConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteVnetConfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VnetConfigServiceServer).DeleteVnetConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: VnetConfigService_DeleteVnetConfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VnetConfigServiceServer).DeleteVnetConfig(ctx, req.(*DeleteVnetConfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// VnetConfigService_ServiceDesc is the grpc.ServiceDesc for VnetConfigService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var VnetConfigService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "teleport.vnet.v1.VnetConfigService",
	HandlerType: (*VnetConfigServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetVnetConfig",
			Handler:    _VnetConfigService_GetVnetConfig_Handler,
		},
		{
			MethodName: "CreateVnetConfig",
			Handler:    _VnetConfigService_CreateVnetConfig_Handler,
		},
		{
			MethodName: "UpdateVnetConfig",
			Handler:    _VnetConfigService_UpdateVnetConfig_Handler,
		},
		{
			MethodName: "UpsertVnetConfig",
			Handler:    _VnetConfigService_UpsertVnetConfig_Handler,
		},
		{
			MethodName: "DeleteVnetConfig",
			Handler:    _VnetConfigService_DeleteVnetConfig_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "teleport/vnet/v1/vnet_config_service.proto",
}
