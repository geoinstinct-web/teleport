// Copyright 2024 Gravitational, Inc
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
// source: teleport/crownjewel/v1/crownjewel_service.proto

package crownjewelv1

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
	CrownJewelService_CreateCrownJewel_FullMethodName = "/teleport.crownjewel.v1.CrownJewelService/CreateCrownJewel"
	CrownJewelService_ListCrownJewels_FullMethodName  = "/teleport.crownjewel.v1.CrownJewelService/ListCrownJewels"
	CrownJewelService_UpdateCrownJewel_FullMethodName = "/teleport.crownjewel.v1.CrownJewelService/UpdateCrownJewel"
	CrownJewelService_DeleteCrownJewel_FullMethodName = "/teleport.crownjewel.v1.CrownJewelService/DeleteCrownJewel"
)

// CrownJewelServiceClient is the client API for CrownJewelService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CrownJewelServiceClient interface {
	// CreateCrownJewel creates a new CrownJewel.
	CreateCrownJewel(ctx context.Context, in *CreateCrownJewelRequest, opts ...grpc.CallOption) (*CrownJewel, error)
	// ListCrownJewels returns a list of CrownJewels. It supports pagination.
	ListCrownJewels(ctx context.Context, in *ListCrownJewelsRequest, opts ...grpc.CallOption) (*ListCrownJewelsResponse, error)
	// UpdateCrownJewel updates an existing CrownJewel.
	UpdateCrownJewel(ctx context.Context, in *UpdateCrownJewelRequest, opts ...grpc.CallOption) (*CrownJewel, error)
	// DeleteCrownJewel deletes a CrownJewel.
	DeleteCrownJewel(ctx context.Context, in *DeleteCrownJewelRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type crownJewelServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewCrownJewelServiceClient(cc grpc.ClientConnInterface) CrownJewelServiceClient {
	return &crownJewelServiceClient{cc}
}

func (c *crownJewelServiceClient) CreateCrownJewel(ctx context.Context, in *CreateCrownJewelRequest, opts ...grpc.CallOption) (*CrownJewel, error) {
	out := new(CrownJewel)
	err := c.cc.Invoke(ctx, CrownJewelService_CreateCrownJewel_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *crownJewelServiceClient) ListCrownJewels(ctx context.Context, in *ListCrownJewelsRequest, opts ...grpc.CallOption) (*ListCrownJewelsResponse, error) {
	out := new(ListCrownJewelsResponse)
	err := c.cc.Invoke(ctx, CrownJewelService_ListCrownJewels_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *crownJewelServiceClient) UpdateCrownJewel(ctx context.Context, in *UpdateCrownJewelRequest, opts ...grpc.CallOption) (*CrownJewel, error) {
	out := new(CrownJewel)
	err := c.cc.Invoke(ctx, CrownJewelService_UpdateCrownJewel_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *crownJewelServiceClient) DeleteCrownJewel(ctx context.Context, in *DeleteCrownJewelRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, CrownJewelService_DeleteCrownJewel_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CrownJewelServiceServer is the server API for CrownJewelService service.
// All implementations must embed UnimplementedCrownJewelServiceServer
// for forward compatibility
type CrownJewelServiceServer interface {
	// CreateCrownJewel creates a new CrownJewel.
	CreateCrownJewel(context.Context, *CreateCrownJewelRequest) (*CrownJewel, error)
	// ListCrownJewels returns a list of CrownJewels. It supports pagination.
	ListCrownJewels(context.Context, *ListCrownJewelsRequest) (*ListCrownJewelsResponse, error)
	// UpdateCrownJewel updates an existing CrownJewel.
	UpdateCrownJewel(context.Context, *UpdateCrownJewelRequest) (*CrownJewel, error)
	// DeleteCrownJewel deletes a CrownJewel.
	DeleteCrownJewel(context.Context, *DeleteCrownJewelRequest) (*emptypb.Empty, error)
	mustEmbedUnimplementedCrownJewelServiceServer()
}

// UnimplementedCrownJewelServiceServer must be embedded to have forward compatible implementations.
type UnimplementedCrownJewelServiceServer struct {
}

func (UnimplementedCrownJewelServiceServer) CreateCrownJewel(context.Context, *CreateCrownJewelRequest) (*CrownJewel, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateCrownJewel not implemented")
}
func (UnimplementedCrownJewelServiceServer) ListCrownJewels(context.Context, *ListCrownJewelsRequest) (*ListCrownJewelsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListCrownJewels not implemented")
}
func (UnimplementedCrownJewelServiceServer) UpdateCrownJewel(context.Context, *UpdateCrownJewelRequest) (*CrownJewel, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateCrownJewel not implemented")
}
func (UnimplementedCrownJewelServiceServer) DeleteCrownJewel(context.Context, *DeleteCrownJewelRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteCrownJewel not implemented")
}
func (UnimplementedCrownJewelServiceServer) mustEmbedUnimplementedCrownJewelServiceServer() {}

// UnsafeCrownJewelServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CrownJewelServiceServer will
// result in compilation errors.
type UnsafeCrownJewelServiceServer interface {
	mustEmbedUnimplementedCrownJewelServiceServer()
}

func RegisterCrownJewelServiceServer(s grpc.ServiceRegistrar, srv CrownJewelServiceServer) {
	s.RegisterService(&CrownJewelService_ServiceDesc, srv)
}

func _CrownJewelService_CreateCrownJewel_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateCrownJewelRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CrownJewelServiceServer).CreateCrownJewel(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CrownJewelService_CreateCrownJewel_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CrownJewelServiceServer).CreateCrownJewel(ctx, req.(*CreateCrownJewelRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CrownJewelService_ListCrownJewels_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListCrownJewelsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CrownJewelServiceServer).ListCrownJewels(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CrownJewelService_ListCrownJewels_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CrownJewelServiceServer).ListCrownJewels(ctx, req.(*ListCrownJewelsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CrownJewelService_UpdateCrownJewel_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateCrownJewelRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CrownJewelServiceServer).UpdateCrownJewel(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CrownJewelService_UpdateCrownJewel_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CrownJewelServiceServer).UpdateCrownJewel(ctx, req.(*UpdateCrownJewelRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CrownJewelService_DeleteCrownJewel_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteCrownJewelRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CrownJewelServiceServer).DeleteCrownJewel(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CrownJewelService_DeleteCrownJewel_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CrownJewelServiceServer).DeleteCrownJewel(ctx, req.(*DeleteCrownJewelRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// CrownJewelService_ServiceDesc is the grpc.ServiceDesc for CrownJewelService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var CrownJewelService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "teleport.crownjewel.v1.CrownJewelService",
	HandlerType: (*CrownJewelServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateCrownJewel",
			Handler:    _CrownJewelService_CreateCrownJewel_Handler,
		},
		{
			MethodName: "ListCrownJewels",
			Handler:    _CrownJewelService_ListCrownJewels_Handler,
		},
		{
			MethodName: "UpdateCrownJewel",
			Handler:    _CrownJewelService_UpdateCrownJewel_Handler,
		},
		{
			MethodName: "DeleteCrownJewel",
			Handler:    _CrownJewelService_DeleteCrownJewel_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "teleport/crownjewel/v1/crownjewel_service.proto",
}
