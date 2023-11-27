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
// source: teleport/trust/v1/trust_service.proto

package trustv1

import (
	context "context"
	types "github.com/gravitational/teleport/api/types"
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
	TrustService_GetCertAuthority_FullMethodName    = "/teleport.trust.v1.TrustService/GetCertAuthority"
	TrustService_GetCertAuthorities_FullMethodName  = "/teleport.trust.v1.TrustService/GetCertAuthorities"
	TrustService_DeleteCertAuthority_FullMethodName = "/teleport.trust.v1.TrustService/DeleteCertAuthority"
	TrustService_UpsertCertAuthority_FullMethodName = "/teleport.trust.v1.TrustService/UpsertCertAuthority"
	TrustService_GenerateHostCert_FullMethodName    = "/teleport.trust.v1.TrustService/GenerateHostCert"
)

// TrustServiceClient is the client API for TrustService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TrustServiceClient interface {
	// GetCertAuthority returns a cert authority by type and domain.
	GetCertAuthority(ctx context.Context, in *GetCertAuthorityRequest, opts ...grpc.CallOption) (*types.CertAuthorityV2, error)
	// GetCertAuthorities returns all cert authorities with the specified type.
	GetCertAuthorities(ctx context.Context, in *GetCertAuthoritiesRequest, opts ...grpc.CallOption) (*GetCertAuthoritiesResponse, error)
	// DeleteCertAuthority deletes the matching cert authority.
	DeleteCertAuthority(ctx context.Context, in *DeleteCertAuthorityRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	// UpsertCertAuthority creates or updates the provided cert authority.
	UpsertCertAuthority(ctx context.Context, in *UpsertCertAuthorityRequest, opts ...grpc.CallOption) (*types.CertAuthorityV2, error)
	// GenerateHostCert takes a public key in the OpenSSH `authorized_keys` format and returns a
	// a SSH certificate signed by the Host CA.
	GenerateHostCert(ctx context.Context, in *GenerateHostCertRequest, opts ...grpc.CallOption) (*GenerateHostCertResponse, error)
}

type trustServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewTrustServiceClient(cc grpc.ClientConnInterface) TrustServiceClient {
	return &trustServiceClient{cc}
}

func (c *trustServiceClient) GetCertAuthority(ctx context.Context, in *GetCertAuthorityRequest, opts ...grpc.CallOption) (*types.CertAuthorityV2, error) {
	out := new(types.CertAuthorityV2)
	err := c.cc.Invoke(ctx, TrustService_GetCertAuthority_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *trustServiceClient) GetCertAuthorities(ctx context.Context, in *GetCertAuthoritiesRequest, opts ...grpc.CallOption) (*GetCertAuthoritiesResponse, error) {
	out := new(GetCertAuthoritiesResponse)
	err := c.cc.Invoke(ctx, TrustService_GetCertAuthorities_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *trustServiceClient) DeleteCertAuthority(ctx context.Context, in *DeleteCertAuthorityRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, TrustService_DeleteCertAuthority_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *trustServiceClient) UpsertCertAuthority(ctx context.Context, in *UpsertCertAuthorityRequest, opts ...grpc.CallOption) (*types.CertAuthorityV2, error) {
	out := new(types.CertAuthorityV2)
	err := c.cc.Invoke(ctx, TrustService_UpsertCertAuthority_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *trustServiceClient) GenerateHostCert(ctx context.Context, in *GenerateHostCertRequest, opts ...grpc.CallOption) (*GenerateHostCertResponse, error) {
	out := new(GenerateHostCertResponse)
	err := c.cc.Invoke(ctx, TrustService_GenerateHostCert_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TrustServiceServer is the server API for TrustService service.
// All implementations must embed UnimplementedTrustServiceServer
// for forward compatibility
type TrustServiceServer interface {
	// GetCertAuthority returns a cert authority by type and domain.
	GetCertAuthority(context.Context, *GetCertAuthorityRequest) (*types.CertAuthorityV2, error)
	// GetCertAuthorities returns all cert authorities with the specified type.
	GetCertAuthorities(context.Context, *GetCertAuthoritiesRequest) (*GetCertAuthoritiesResponse, error)
	// DeleteCertAuthority deletes the matching cert authority.
	DeleteCertAuthority(context.Context, *DeleteCertAuthorityRequest) (*emptypb.Empty, error)
	// UpsertCertAuthority creates or updates the provided cert authority.
	UpsertCertAuthority(context.Context, *UpsertCertAuthorityRequest) (*types.CertAuthorityV2, error)
	// GenerateHostCert takes a public key in the OpenSSH `authorized_keys` format and returns a
	// a SSH certificate signed by the Host CA.
	GenerateHostCert(context.Context, *GenerateHostCertRequest) (*GenerateHostCertResponse, error)
	mustEmbedUnimplementedTrustServiceServer()
}

// UnimplementedTrustServiceServer must be embedded to have forward compatible implementations.
type UnimplementedTrustServiceServer struct {
}

func (UnimplementedTrustServiceServer) GetCertAuthority(context.Context, *GetCertAuthorityRequest) (*types.CertAuthorityV2, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCertAuthority not implemented")
}
func (UnimplementedTrustServiceServer) GetCertAuthorities(context.Context, *GetCertAuthoritiesRequest) (*GetCertAuthoritiesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCertAuthorities not implemented")
}
func (UnimplementedTrustServiceServer) DeleteCertAuthority(context.Context, *DeleteCertAuthorityRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteCertAuthority not implemented")
}
func (UnimplementedTrustServiceServer) UpsertCertAuthority(context.Context, *UpsertCertAuthorityRequest) (*types.CertAuthorityV2, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertCertAuthority not implemented")
}
func (UnimplementedTrustServiceServer) GenerateHostCert(context.Context, *GenerateHostCertRequest) (*GenerateHostCertResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GenerateHostCert not implemented")
}
func (UnimplementedTrustServiceServer) mustEmbedUnimplementedTrustServiceServer() {}

// UnsafeTrustServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to TrustServiceServer will
// result in compilation errors.
type UnsafeTrustServiceServer interface {
	mustEmbedUnimplementedTrustServiceServer()
}

func RegisterTrustServiceServer(s grpc.ServiceRegistrar, srv TrustServiceServer) {
	s.RegisterService(&TrustService_ServiceDesc, srv)
}

func _TrustService_GetCertAuthority_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetCertAuthorityRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TrustServiceServer).GetCertAuthority(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TrustService_GetCertAuthority_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TrustServiceServer).GetCertAuthority(ctx, req.(*GetCertAuthorityRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TrustService_GetCertAuthorities_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetCertAuthoritiesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TrustServiceServer).GetCertAuthorities(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TrustService_GetCertAuthorities_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TrustServiceServer).GetCertAuthorities(ctx, req.(*GetCertAuthoritiesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TrustService_DeleteCertAuthority_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteCertAuthorityRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TrustServiceServer).DeleteCertAuthority(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TrustService_DeleteCertAuthority_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TrustServiceServer).DeleteCertAuthority(ctx, req.(*DeleteCertAuthorityRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TrustService_UpsertCertAuthority_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpsertCertAuthorityRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TrustServiceServer).UpsertCertAuthority(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TrustService_UpsertCertAuthority_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TrustServiceServer).UpsertCertAuthority(ctx, req.(*UpsertCertAuthorityRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TrustService_GenerateHostCert_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GenerateHostCertRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TrustServiceServer).GenerateHostCert(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TrustService_GenerateHostCert_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TrustServiceServer).GenerateHostCert(ctx, req.(*GenerateHostCertRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// TrustService_ServiceDesc is the grpc.ServiceDesc for TrustService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var TrustService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "teleport.trust.v1.TrustService",
	HandlerType: (*TrustServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetCertAuthority",
			Handler:    _TrustService_GetCertAuthority_Handler,
		},
		{
			MethodName: "GetCertAuthorities",
			Handler:    _TrustService_GetCertAuthorities_Handler,
		},
		{
			MethodName: "DeleteCertAuthority",
			Handler:    _TrustService_DeleteCertAuthority_Handler,
		},
		{
			MethodName: "UpsertCertAuthority",
			Handler:    _TrustService_UpsertCertAuthority_Handler,
		},
		{
			MethodName: "GenerateHostCert",
			Handler:    _TrustService_GenerateHostCert_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "teleport/trust/v1/trust_service.proto",
}
