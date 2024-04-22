//
// Teleport
// Copyright (C) 2023  Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: accessgraph/v1alpha/access_graph_service.proto

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
	AccessGraphService_Query_FullMethodName              = "/accessgraph.v1alpha.AccessGraphService/Query"
	AccessGraphService_GetFile_FullMethodName            = "/accessgraph.v1alpha.AccessGraphService/GetFile"
	AccessGraphService_EventsStream_FullMethodName       = "/accessgraph.v1alpha.AccessGraphService/EventsStream"
	AccessGraphService_Register_FullMethodName           = "/accessgraph.v1alpha.AccessGraphService/Register"
	AccessGraphService_ReplaceCAs_FullMethodName         = "/accessgraph.v1alpha.AccessGraphService/ReplaceCAs"
	AccessGraphService_AWSEventsStream_FullMethodName    = "/accessgraph.v1alpha.AccessGraphService/AWSEventsStream"
	AccessGraphService_GitlabEventsStream_FullMethodName = "/accessgraph.v1alpha.AccessGraphService/GitlabEventsStream"
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
	// EventsStream is a stream of commands to the access graph service.
	// Teleport Auth server creates a stream to the access graph service
	// and pushes all resources and following events to it.
	// This stream is used to sync the access graph with the Teleport database state.
	// Once Teleport finishes syncing the current state, it sends a sync command
	// to the access graph service and resumes sending events.
	EventsStream(ctx context.Context, opts ...grpc.CallOption) (AccessGraphService_EventsStreamClient, error)
	// Register submits a new tenant representing this Teleport cluster to the TAG service,
	// identified by its HostCA certificate.
	// The method is idempotent: it succeeds if the tenant has already registered and has the specific CA associated.
	//
	// This method, unlike all others, expects the client to authenticate using a TLS certificate signed by the registration CA,
	// rather than the Teleport cluster's Host CA.
	Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*RegisterResponse, error)
	// ReplaceCAs is a request to completely replace the set of Host CAs that authenticate this tenant with the given set.
	// This accomodates Teleport Host CA rotation. In a transition from certificate authority A to authority B,
	// the client is expected to call the RPC as follows:
	// 1. Authenticate via existing authority A and call ReplaceCAs([A, B]) -- introduce the incoming CA
	// 2.a. If rotation succeeds, authenticate via the new authority B and call ReplaceCAs([B]) -- delete the previous CA
	// 2.b. If rotation is rolled back, authenticate via the old authority A and call ReplaceCAs([A]) -- delete the candidate CA
	ReplaceCAs(ctx context.Context, in *ReplaceCAsRequest, opts ...grpc.CallOption) (*ReplaceCAsResponse, error)
	// AWSEventsStream is a stream of commands to the AWS importer.
	// Teleport Discovery Service creates a stream to the access graph service
	// and pushes all AWS resources and following events to it.
	// This stream is used to sync the access graph with the AWS database state.
	AWSEventsStream(ctx context.Context, opts ...grpc.CallOption) (AccessGraphService_AWSEventsStreamClient, error)
	// GitlabEventsStream is a stream of commands to the Gitlab importer.
	GitlabEventsStream(ctx context.Context, opts ...grpc.CallOption) (AccessGraphService_GitlabEventsStreamClient, error)
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

func (c *accessGraphServiceClient) EventsStream(ctx context.Context, opts ...grpc.CallOption) (AccessGraphService_EventsStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &AccessGraphService_ServiceDesc.Streams[0], AccessGraphService_EventsStream_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &accessGraphServiceEventsStreamClient{stream}
	return x, nil
}

type AccessGraphService_EventsStreamClient interface {
	Send(*EventsStreamRequest) error
	CloseAndRecv() (*EventsStreamResponse, error)
	grpc.ClientStream
}

type accessGraphServiceEventsStreamClient struct {
	grpc.ClientStream
}

func (x *accessGraphServiceEventsStreamClient) Send(m *EventsStreamRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *accessGraphServiceEventsStreamClient) CloseAndRecv() (*EventsStreamResponse, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(EventsStreamResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *accessGraphServiceClient) Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*RegisterResponse, error) {
	out := new(RegisterResponse)
	err := c.cc.Invoke(ctx, AccessGraphService_Register_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accessGraphServiceClient) ReplaceCAs(ctx context.Context, in *ReplaceCAsRequest, opts ...grpc.CallOption) (*ReplaceCAsResponse, error) {
	out := new(ReplaceCAsResponse)
	err := c.cc.Invoke(ctx, AccessGraphService_ReplaceCAs_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accessGraphServiceClient) AWSEventsStream(ctx context.Context, opts ...grpc.CallOption) (AccessGraphService_AWSEventsStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &AccessGraphService_ServiceDesc.Streams[1], AccessGraphService_AWSEventsStream_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &accessGraphServiceAWSEventsStreamClient{stream}
	return x, nil
}

type AccessGraphService_AWSEventsStreamClient interface {
	Send(*AWSEventsStreamRequest) error
	CloseAndRecv() (*AWSEventsStreamResponse, error)
	grpc.ClientStream
}

type accessGraphServiceAWSEventsStreamClient struct {
	grpc.ClientStream
}

func (x *accessGraphServiceAWSEventsStreamClient) Send(m *AWSEventsStreamRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *accessGraphServiceAWSEventsStreamClient) CloseAndRecv() (*AWSEventsStreamResponse, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(AWSEventsStreamResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *accessGraphServiceClient) GitlabEventsStream(ctx context.Context, opts ...grpc.CallOption) (AccessGraphService_GitlabEventsStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &AccessGraphService_ServiceDesc.Streams[2], AccessGraphService_GitlabEventsStream_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &accessGraphServiceGitlabEventsStreamClient{stream}
	return x, nil
}

type AccessGraphService_GitlabEventsStreamClient interface {
	Send(*GitlabEventsStreamRequest) error
	Recv() (*GitlabEventsStreamResponse, error)
	grpc.ClientStream
}

type accessGraphServiceGitlabEventsStreamClient struct {
	grpc.ClientStream
}

func (x *accessGraphServiceGitlabEventsStreamClient) Send(m *GitlabEventsStreamRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *accessGraphServiceGitlabEventsStreamClient) Recv() (*GitlabEventsStreamResponse, error) {
	m := new(GitlabEventsStreamResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
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
	// EventsStream is a stream of commands to the access graph service.
	// Teleport Auth server creates a stream to the access graph service
	// and pushes all resources and following events to it.
	// This stream is used to sync the access graph with the Teleport database state.
	// Once Teleport finishes syncing the current state, it sends a sync command
	// to the access graph service and resumes sending events.
	EventsStream(AccessGraphService_EventsStreamServer) error
	// Register submits a new tenant representing this Teleport cluster to the TAG service,
	// identified by its HostCA certificate.
	// The method is idempotent: it succeeds if the tenant has already registered and has the specific CA associated.
	//
	// This method, unlike all others, expects the client to authenticate using a TLS certificate signed by the registration CA,
	// rather than the Teleport cluster's Host CA.
	Register(context.Context, *RegisterRequest) (*RegisterResponse, error)
	// ReplaceCAs is a request to completely replace the set of Host CAs that authenticate this tenant with the given set.
	// This accomodates Teleport Host CA rotation. In a transition from certificate authority A to authority B,
	// the client is expected to call the RPC as follows:
	// 1. Authenticate via existing authority A and call ReplaceCAs([A, B]) -- introduce the incoming CA
	// 2.a. If rotation succeeds, authenticate via the new authority B and call ReplaceCAs([B]) -- delete the previous CA
	// 2.b. If rotation is rolled back, authenticate via the old authority A and call ReplaceCAs([A]) -- delete the candidate CA
	ReplaceCAs(context.Context, *ReplaceCAsRequest) (*ReplaceCAsResponse, error)
	// AWSEventsStream is a stream of commands to the AWS importer.
	// Teleport Discovery Service creates a stream to the access graph service
	// and pushes all AWS resources and following events to it.
	// This stream is used to sync the access graph with the AWS database state.
	AWSEventsStream(AccessGraphService_AWSEventsStreamServer) error
	// GitlabEventsStream is a stream of commands to the Gitlab importer.
	GitlabEventsStream(AccessGraphService_GitlabEventsStreamServer) error
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
func (UnimplementedAccessGraphServiceServer) EventsStream(AccessGraphService_EventsStreamServer) error {
	return status.Errorf(codes.Unimplemented, "method EventsStream not implemented")
}
func (UnimplementedAccessGraphServiceServer) Register(context.Context, *RegisterRequest) (*RegisterResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Register not implemented")
}
func (UnimplementedAccessGraphServiceServer) ReplaceCAs(context.Context, *ReplaceCAsRequest) (*ReplaceCAsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReplaceCAs not implemented")
}
func (UnimplementedAccessGraphServiceServer) AWSEventsStream(AccessGraphService_AWSEventsStreamServer) error {
	return status.Errorf(codes.Unimplemented, "method AWSEventsStream not implemented")
}
func (UnimplementedAccessGraphServiceServer) GitlabEventsStream(AccessGraphService_GitlabEventsStreamServer) error {
	return status.Errorf(codes.Unimplemented, "method GitlabEventsStream not implemented")
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

func _AccessGraphService_EventsStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(AccessGraphServiceServer).EventsStream(&accessGraphServiceEventsStreamServer{stream})
}

type AccessGraphService_EventsStreamServer interface {
	SendAndClose(*EventsStreamResponse) error
	Recv() (*EventsStreamRequest, error)
	grpc.ServerStream
}

type accessGraphServiceEventsStreamServer struct {
	grpc.ServerStream
}

func (x *accessGraphServiceEventsStreamServer) SendAndClose(m *EventsStreamResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *accessGraphServiceEventsStreamServer) Recv() (*EventsStreamRequest, error) {
	m := new(EventsStreamRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _AccessGraphService_Register_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccessGraphServiceServer).Register(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AccessGraphService_Register_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccessGraphServiceServer).Register(ctx, req.(*RegisterRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AccessGraphService_ReplaceCAs_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReplaceCAsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccessGraphServiceServer).ReplaceCAs(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AccessGraphService_ReplaceCAs_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccessGraphServiceServer).ReplaceCAs(ctx, req.(*ReplaceCAsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AccessGraphService_AWSEventsStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(AccessGraphServiceServer).AWSEventsStream(&accessGraphServiceAWSEventsStreamServer{stream})
}

type AccessGraphService_AWSEventsStreamServer interface {
	SendAndClose(*AWSEventsStreamResponse) error
	Recv() (*AWSEventsStreamRequest, error)
	grpc.ServerStream
}

type accessGraphServiceAWSEventsStreamServer struct {
	grpc.ServerStream
}

func (x *accessGraphServiceAWSEventsStreamServer) SendAndClose(m *AWSEventsStreamResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *accessGraphServiceAWSEventsStreamServer) Recv() (*AWSEventsStreamRequest, error) {
	m := new(AWSEventsStreamRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _AccessGraphService_GitlabEventsStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(AccessGraphServiceServer).GitlabEventsStream(&accessGraphServiceGitlabEventsStreamServer{stream})
}

type AccessGraphService_GitlabEventsStreamServer interface {
	Send(*GitlabEventsStreamResponse) error
	Recv() (*GitlabEventsStreamRequest, error)
	grpc.ServerStream
}

type accessGraphServiceGitlabEventsStreamServer struct {
	grpc.ServerStream
}

func (x *accessGraphServiceGitlabEventsStreamServer) Send(m *GitlabEventsStreamResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *accessGraphServiceGitlabEventsStreamServer) Recv() (*GitlabEventsStreamRequest, error) {
	m := new(GitlabEventsStreamRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
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
			MethodName: "Register",
			Handler:    _AccessGraphService_Register_Handler,
		},
		{
			MethodName: "ReplaceCAs",
			Handler:    _AccessGraphService_ReplaceCAs_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "EventsStream",
			Handler:       _AccessGraphService_EventsStream_Handler,
			ClientStreams: true,
		},
		{
			StreamName:    "AWSEventsStream",
			Handler:       _AccessGraphService_AWSEventsStream_Handler,
			ClientStreams: true,
		},
		{
			StreamName:    "GitlabEventsStream",
			Handler:       _AccessGraphService_GitlabEventsStream_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "accessgraph/v1alpha/access_graph_service.proto",
}
