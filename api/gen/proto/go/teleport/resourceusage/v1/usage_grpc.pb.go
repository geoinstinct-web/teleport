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
// source: teleport/resourceusage/v1/usage.proto

package resourceusagev1

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
	ResourceUsageService_GetAccessRequestUsage_FullMethodName = "/teleport.resourceusage.v1.ResourceUsageService/GetAccessRequestUsage"
)

// ResourceUsageServiceClient is the client API for ResourceUsageService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ResourceUsageServiceClient interface {
	// GetAccessRequestUsage is TODO
	GetAccessRequestUsage(ctx context.Context, in *GetAccessRequestUsageRequest, opts ...grpc.CallOption) (*AccessRequestUsage, error)
}

type resourceUsageServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewResourceUsageServiceClient(cc grpc.ClientConnInterface) ResourceUsageServiceClient {
	return &resourceUsageServiceClient{cc}
}

func (c *resourceUsageServiceClient) GetAccessRequestUsage(ctx context.Context, in *GetAccessRequestUsageRequest, opts ...grpc.CallOption) (*AccessRequestUsage, error) {
	out := new(AccessRequestUsage)
	err := c.cc.Invoke(ctx, ResourceUsageService_GetAccessRequestUsage_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ResourceUsageServiceServer is the server API for ResourceUsageService service.
// All implementations must embed UnimplementedResourceUsageServiceServer
// for forward compatibility
type ResourceUsageServiceServer interface {
	// GetAccessRequestUsage is TODO
	GetAccessRequestUsage(context.Context, *GetAccessRequestUsageRequest) (*AccessRequestUsage, error)
	mustEmbedUnimplementedResourceUsageServiceServer()
}

// UnimplementedResourceUsageServiceServer must be embedded to have forward compatible implementations.
type UnimplementedResourceUsageServiceServer struct {
}

func (UnimplementedResourceUsageServiceServer) GetAccessRequestUsage(context.Context, *GetAccessRequestUsageRequest) (*AccessRequestUsage, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAccessRequestUsage not implemented")
}
func (UnimplementedResourceUsageServiceServer) mustEmbedUnimplementedResourceUsageServiceServer() {}

// UnsafeResourceUsageServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ResourceUsageServiceServer will
// result in compilation errors.
type UnsafeResourceUsageServiceServer interface {
	mustEmbedUnimplementedResourceUsageServiceServer()
}

func RegisterResourceUsageServiceServer(s grpc.ServiceRegistrar, srv ResourceUsageServiceServer) {
	s.RegisterService(&ResourceUsageService_ServiceDesc, srv)
}

func _ResourceUsageService_GetAccessRequestUsage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAccessRequestUsageRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceUsageServiceServer).GetAccessRequestUsage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceUsageService_GetAccessRequestUsage_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceUsageServiceServer).GetAccessRequestUsage(ctx, req.(*GetAccessRequestUsageRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ResourceUsageService_ServiceDesc is the grpc.ServiceDesc for ResourceUsageService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ResourceUsageService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "teleport.resourceusage.v1.ResourceUsageService",
	HandlerType: (*ResourceUsageServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetAccessRequestUsage",
			Handler:    _ResourceUsageService_GetAccessRequestUsage_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "teleport/resourceusage/v1/usage.proto",
}
