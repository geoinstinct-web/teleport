// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.17.3
// source: teleport/terminal/v1/gateway.proto

package v1

import (
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

type Gateway struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// User-friendly name.
	// Optional.
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	// Eg: "/clusters/{id}".
	TargetCluster string `protobuf:"bytes,3,opt,name=target_cluster,json=targetCluster,proto3" json:"target_cluster,omitempty"`
	// Eg: "/databases/{id}".
	TargetResource string `protobuf:"bytes,4,opt,name=target_resource,json=targetResource,proto3" json:"target_resource,omitempty"`
	// Protocol and port to connect, available for most gateway types.
	// If supplied during gateway creation the service will try to bind (with best
	// effort) the request address.
	// Eg: "psql://localhost:12345/...".
	// TODO(codingllama): Better document for the various gateways types.
	LocalAddress string `protobuf:"bytes,5,opt,name=local_address,json=localAddress,proto3" json:"local_address,omitempty"`
	// If true, StreamGateway may be used with this gateway.
	// Only supported for SSH nodes.
	AllowStreaming bool `protobuf:"varint,6,opt,name=allow_streaming,json=allowStreaming,proto3" json:"allow_streaming,omitempty"`
}

func (x *Gateway) Reset() {
	*x = Gateway{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_terminal_v1_gateway_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Gateway) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Gateway) ProtoMessage() {}

func (x *Gateway) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_terminal_v1_gateway_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Gateway.ProtoReflect.Descriptor instead.
func (*Gateway) Descriptor() ([]byte, []int) {
	return file_teleport_terminal_v1_gateway_proto_rawDescGZIP(), []int{0}
}

func (x *Gateway) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Gateway) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Gateway) GetTargetCluster() string {
	if x != nil {
		return x.TargetCluster
	}
	return ""
}

func (x *Gateway) GetTargetResource() string {
	if x != nil {
		return x.TargetResource
	}
	return ""
}

func (x *Gateway) GetLocalAddress() string {
	if x != nil {
		return x.LocalAddress
	}
	return ""
}

func (x *Gateway) GetAllowStreaming() bool {
	if x != nil {
		return x.AllowStreaming
	}
	return false
}

var File_teleport_terminal_v1_gateway_proto protoreflect.FileDescriptor

var file_teleport_terminal_v1_gateway_proto_rawDesc = []byte{
	0x0a, 0x22, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x74, 0x65, 0x72, 0x6d, 0x69,
	0x6e, 0x61, 0x6c, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x14, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x74,
	0x65, 0x72, 0x6d, 0x69, 0x6e, 0x61, 0x6c, 0x2e, 0x76, 0x31, 0x22, 0xcb, 0x01, 0x0a, 0x07, 0x47,
	0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x25, 0x0a, 0x0e, 0x74, 0x61,
	0x72, 0x67, 0x65, 0x74, 0x5f, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0d, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65,
	0x72, 0x12, 0x27, 0x0a, 0x0f, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x72, 0x65, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x74, 0x61, 0x72, 0x67,
	0x65, 0x74, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x23, 0x0a, 0x0d, 0x6c, 0x6f,
	0x63, 0x61, 0x6c, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0c, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12,
	0x27, 0x0a, 0x0f, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x5f, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x69,
	0x6e, 0x67, 0x18, 0x06, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0e, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x53,
	0x74, 0x72, 0x65, 0x61, 0x6d, 0x69, 0x6e, 0x67, 0x42, 0x41, 0x5a, 0x3f, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x67, 0x65, 0x6e, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f,
	0x74, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x61, 0x6c, 0x2f, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_teleport_terminal_v1_gateway_proto_rawDescOnce sync.Once
	file_teleport_terminal_v1_gateway_proto_rawDescData = file_teleport_terminal_v1_gateway_proto_rawDesc
)

func file_teleport_terminal_v1_gateway_proto_rawDescGZIP() []byte {
	file_teleport_terminal_v1_gateway_proto_rawDescOnce.Do(func() {
		file_teleport_terminal_v1_gateway_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_terminal_v1_gateway_proto_rawDescData)
	})
	return file_teleport_terminal_v1_gateway_proto_rawDescData
}

var file_teleport_terminal_v1_gateway_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_teleport_terminal_v1_gateway_proto_goTypes = []interface{}{
	(*Gateway)(nil), // 0: teleport.terminal.v1.Gateway
}
var file_teleport_terminal_v1_gateway_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_teleport_terminal_v1_gateway_proto_init() }
func file_teleport_terminal_v1_gateway_proto_init() {
	if File_teleport_terminal_v1_gateway_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleport_terminal_v1_gateway_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Gateway); i {
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
			RawDescriptor: file_teleport_terminal_v1_gateway_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_terminal_v1_gateway_proto_goTypes,
		DependencyIndexes: file_teleport_terminal_v1_gateway_proto_depIdxs,
		MessageInfos:      file_teleport_terminal_v1_gateway_proto_msgTypes,
	}.Build()
	File_teleport_terminal_v1_gateway_proto = out.File
	file_teleport_terminal_v1_gateway_proto_rawDesc = nil
	file_teleport_terminal_v1_gateway_proto_goTypes = nil
	file_teleport_terminal_v1_gateway_proto_depIdxs = nil
}
