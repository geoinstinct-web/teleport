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
// source: accessgraph/v1alpha/query.proto

package accessgraphv1alpha

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	AccessGraphService_Query_FullMethodName        = "/accessgraph.v1alpha.AccessGraphService/Query"
	AccessGraphService_GetFile_FullMethodName      = "/accessgraph.v1alpha.AccessGraphService/GetFile"
	AccessGraphService_SendEvent_FullMethodName    = "/accessgraph.v1alpha.AccessGraphService/SendEvent"
	AccessGraphService_SendResource_FullMethodName = "/accessgraph.v1alpha.AccessGraphService/SendResource"
)

// AccessGraphServiceClient is the client API for AccessGraphService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AccessGraphServiceClient interface {
	// Query queries the access graph.
	// Currently only used by WebUI.
	Query(ctx context.Context, in *QueryRequest, opts ...grpc.CallOption) (*QueryResponse, error)
	// GetFile gets a static UI file from the access graph container.
	GetFile(ctx context.Context, in *GetFileRequest, opts ...grpc.CallOption) (*GetFileResponse, error)
	// SendEvent sends an event to the access graph service.
	SendEvent(ctx context.Context, in *SendEventRequest, opts ...grpc.CallOption) (*SendEventResponse, error)
	// SendResource sends a resource to the access graph service.
	SendResource(ctx context.Context, in *SendResourceRequest, opts ...grpc.CallOption) (*SendResourceResponse, error)
}

type accessGraphServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAccessGraphServiceClient(cc grpc.ClientConnInterface) AccessGraphServiceClient {
	return &accessGraphServiceClient{cc}
}

func (c *accessGraphServiceClient) Query(ctx context.Context, in *QueryRequest, opts ...grpc.CallOption) (*QueryResponse, error) {
	out := new(QueryResponse)
	err := c.cc.Invoke(ctx, AccessGraphService_Query_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accessGraphServiceClient) GetFile(ctx context.Context, in *GetFileRequest, opts ...grpc.CallOption) (*GetFileResponse, error) {
	out := new(GetFileResponse)
	err := c.cc.Invoke(ctx, AccessGraphService_GetFile_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accessGraphServiceClient) SendEvent(ctx context.Context, in *SendEventRequest, opts ...grpc.CallOption) (*SendEventResponse, error) {
	out := new(SendEventResponse)
	err := c.cc.Invoke(ctx, AccessGraphService_SendEvent_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accessGraphServiceClient) SendResource(ctx context.Context, in *SendResourceRequest, opts ...grpc.CallOption) (*SendResourceResponse, error) {
	out := new(SendResourceResponse)
	err := c.cc.Invoke(ctx, AccessGraphService_SendResource_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AccessGraphServiceServer is the server API for AccessGraphService service.
// All implementations must embed UnimplementedAccessGraphServiceServer
// for forward compatibility
type AccessGraphServiceServer interface {
	// Query queries the access graph.
	// Currently only used by WebUI.
	Query(context.Context, *QueryRequest) (*QueryResponse, error)
	// GetFile gets a static UI file from the access graph container.
	GetFile(context.Context, *GetFileRequest) (*GetFileResponse, error)
	// SendEvent sends an event to the access graph service.
	SendEvent(context.Context, *SendEventRequest) (*SendEventResponse, error)
	// SendResource sends a resource to the access graph service.
	SendResource(context.Context, *SendResourceRequest) (*SendResourceResponse, error)
	mustEmbedUnimplementedAccessGraphServiceServer()
}

// UnimplementedAccessGraphServiceServer must be embedded to have forward compatible implementations.
type UnimplementedAccessGraphServiceServer struct {
}

func (UnimplementedAccessGraphServiceServer) Query(context.Context, *QueryRequest) (*QueryResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Query not implemented")
}
func (UnimplementedAccessGraphServiceServer) GetFile(context.Context, *GetFileRequest) (*GetFileResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetFile not implemented")
}
func (UnimplementedAccessGraphServiceServer) SendEvent(context.Context, *SendEventRequest) (*SendEventResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendEvent not implemented")
}
func (UnimplementedAccessGraphServiceServer) SendResource(context.Context, *SendResourceRequest) (*SendResourceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendResource not implemented")
}
func (UnimplementedAccessGraphServiceServer) mustEmbedUnimplementedAccessGraphServiceServer() {}

// UnsafeAccessGraphServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AccessGraphServiceServer will
// result in compilation errors.
type UnsafeAccessGraphServiceServer interface {
	mustEmbedUnimplementedAccessGraphServiceServer()
}

func RegisterAccessGraphServiceServer(s grpc.ServiceRegistrar, srv AccessGraphServiceServer) {
	s.RegisterService(&AccessGraphService_ServiceDesc, srv)
}

func _AccessGraphService_Query_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccessGraphServiceServer).Query(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AccessGraphService_Query_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccessGraphServiceServer).Query(ctx, req.(*QueryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AccessGraphService_GetFile_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetFileRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccessGraphServiceServer).GetFile(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AccessGraphService_GetFile_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccessGraphServiceServer).GetFile(ctx, req.(*GetFileRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AccessGraphService_SendEvent_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SendEventRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccessGraphServiceServer).SendEvent(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AccessGraphService_SendEvent_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccessGraphServiceServer).SendEvent(ctx, req.(*SendEventRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AccessGraphService_SendResource_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SendResourceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccessGraphServiceServer).SendResource(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AccessGraphService_SendResource_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccessGraphServiceServer).SendResource(ctx, req.(*SendResourceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// AccessGraphService_ServiceDesc is the grpc.ServiceDesc for AccessGraphService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AccessGraphService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "accessgraph.v1alpha.AccessGraphService",
	HandlerType: (*AccessGraphServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Query",
			Handler:    _AccessGraphService_Query_Handler,
		},
		{
			MethodName: "GetFile",
			Handler:    _AccessGraphService_GetFile_Handler,
		},
		{
			MethodName: "SendEvent",
			Handler:    _AccessGraphService_SendEvent_Handler,
		},
		{
			MethodName: "SendResource",
			Handler:    _AccessGraphService_SendResource_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "accessgraph/v1alpha/query.proto",
}
