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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        (unknown)
// source: v1/tshd_events_service.proto

package v1

import (
	context "context"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type TestRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Foo string `protobuf:"bytes,1,opt,name=foo,proto3" json:"foo,omitempty"`
}

func (x *TestRequest) Reset() {
	*x = TestRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_v1_tshd_events_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TestRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TestRequest) ProtoMessage() {}

func (x *TestRequest) ProtoReflect() protoreflect.Message {
	mi := &file_v1_tshd_events_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TestRequest.ProtoReflect.Descriptor instead.
func (*TestRequest) Descriptor() ([]byte, []int) {
	return file_v1_tshd_events_service_proto_rawDescGZIP(), []int{0}
}

func (x *TestRequest) GetFoo() string {
	if x != nil {
		return x.Foo
	}
	return ""
}

type TestResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *TestResponse) Reset() {
	*x = TestResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_v1_tshd_events_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TestResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TestResponse) ProtoMessage() {}

func (x *TestResponse) ProtoReflect() protoreflect.Message {
	mi := &file_v1_tshd_events_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TestResponse.ProtoReflect.Descriptor instead.
func (*TestResponse) Descriptor() ([]byte, []int) {
	return file_v1_tshd_events_service_proto_rawDescGZIP(), []int{1}
}

var File_v1_tshd_events_service_proto protoreflect.FileDescriptor

var file_v1_tshd_events_service_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x76, 0x31, 0x2f, 0x74, 0x73, 0x68, 0x64, 0x5f, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x73,
	0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x14,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x74, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x61,
	0x6c, 0x2e, 0x76, 0x31, 0x22, 0x1f, 0x0a, 0x0b, 0x54, 0x65, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x66, 0x6f, 0x6f, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x03, 0x66, 0x6f, 0x6f, 0x22, 0x0e, 0x0a, 0x0c, 0x54, 0x65, 0x73, 0x74, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x32, 0x62, 0x0a, 0x11, 0x54, 0x73, 0x68, 0x64, 0x45, 0x76, 0x65,
	0x6e, 0x74, 0x73, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x4d, 0x0a, 0x04, 0x54, 0x65,
	0x73, 0x74, 0x12, 0x21, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x74, 0x65,
	0x72, 0x6d, 0x69, 0x6e, 0x61, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x65, 0x73, 0x74, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x22, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74,
	0x2e, 0x74, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x61, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x65, 0x73,
	0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x33, 0x5a, 0x31, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6c,
	0x69, 0x62, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x72, 0x6d, 0x2f, 0x76, 0x31, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_v1_tshd_events_service_proto_rawDescOnce sync.Once
	file_v1_tshd_events_service_proto_rawDescData = file_v1_tshd_events_service_proto_rawDesc
)

func file_v1_tshd_events_service_proto_rawDescGZIP() []byte {
	file_v1_tshd_events_service_proto_rawDescOnce.Do(func() {
		file_v1_tshd_events_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_v1_tshd_events_service_proto_rawDescData)
	})
	return file_v1_tshd_events_service_proto_rawDescData
}

var file_v1_tshd_events_service_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_v1_tshd_events_service_proto_goTypes = []interface{}{
	(*TestRequest)(nil),  // 0: teleport.terminal.v1.TestRequest
	(*TestResponse)(nil), // 1: teleport.terminal.v1.TestResponse
}
var file_v1_tshd_events_service_proto_depIdxs = []int32{
	0, // 0: teleport.terminal.v1.TshdEventsService.Test:input_type -> teleport.terminal.v1.TestRequest
	1, // 1: teleport.terminal.v1.TshdEventsService.Test:output_type -> teleport.terminal.v1.TestResponse
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_v1_tshd_events_service_proto_init() }
func file_v1_tshd_events_service_proto_init() {
	if File_v1_tshd_events_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_v1_tshd_events_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TestRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_v1_tshd_events_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TestResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_v1_tshd_events_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_v1_tshd_events_service_proto_goTypes,
		DependencyIndexes: file_v1_tshd_events_service_proto_depIdxs,
		MessageInfos:      file_v1_tshd_events_service_proto_msgTypes,
	}.Build()
	File_v1_tshd_events_service_proto = out.File
	file_v1_tshd_events_service_proto_rawDesc = nil
	file_v1_tshd_events_service_proto_goTypes = nil
	file_v1_tshd_events_service_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// TshdEventsServiceClient is the client API for TshdEventsService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type TshdEventsServiceClient interface {
	// Test is an RPC that's used to demonstrate how the implementation of a tshd event may look like
	// from the beginning till the end.
	// TODO(ravicious): Remove this once we add an actual RPC to tshd events service.
	Test(ctx context.Context, in *TestRequest, opts ...grpc.CallOption) (*TestResponse, error)
}

type tshdEventsServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewTshdEventsServiceClient(cc grpc.ClientConnInterface) TshdEventsServiceClient {
	return &tshdEventsServiceClient{cc}
}

func (c *tshdEventsServiceClient) Test(ctx context.Context, in *TestRequest, opts ...grpc.CallOption) (*TestResponse, error) {
	out := new(TestResponse)
	err := c.cc.Invoke(ctx, "/teleport.terminal.v1.TshdEventsService/Test", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TshdEventsServiceServer is the server API for TshdEventsService service.
type TshdEventsServiceServer interface {
	// Test is an RPC that's used to demonstrate how the implementation of a tshd event may look like
	// from the beginning till the end.
	// TODO(ravicious): Remove this once we add an actual RPC to tshd events service.
	Test(context.Context, *TestRequest) (*TestResponse, error)
}

// UnimplementedTshdEventsServiceServer can be embedded to have forward compatible implementations.
type UnimplementedTshdEventsServiceServer struct {
}

func (*UnimplementedTshdEventsServiceServer) Test(context.Context, *TestRequest) (*TestResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Test not implemented")
}

func RegisterTshdEventsServiceServer(s *grpc.Server, srv TshdEventsServiceServer) {
	s.RegisterService(&_TshdEventsService_serviceDesc, srv)
}

func _TshdEventsService_Test_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TestRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TshdEventsServiceServer).Test(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/teleport.terminal.v1.TshdEventsService/Test",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TshdEventsServiceServer).Test(ctx, req.(*TestRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _TshdEventsService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "teleport.terminal.v1.TshdEventsService",
	HandlerType: (*TshdEventsServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Test",
			Handler:    _TshdEventsService_Test_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "v1/tshd_events_service.proto",
}
