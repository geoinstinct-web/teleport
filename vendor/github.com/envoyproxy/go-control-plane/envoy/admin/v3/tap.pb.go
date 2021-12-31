// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.14.0
// source: envoy/admin/v3/tap.proto

package envoy_admin_v3

import (
	_ "github.com/cncf/xds/go/udpa/annotations"
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/tap/v3"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	proto "github.com/golang/protobuf/proto"
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

// The /tap admin request body that is used to configure an active tap session.
type TapRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The opaque configuration ID used to match the configuration to a loaded extension.
	// A tap extension configures a similar opaque ID that is used to match.
	ConfigId string `protobuf:"bytes,1,opt,name=config_id,json=configId,proto3" json:"config_id,omitempty"`
	// The tap configuration to load.
	TapConfig *v3.TapConfig `protobuf:"bytes,2,opt,name=tap_config,json=tapConfig,proto3" json:"tap_config,omitempty"`
}

func (x *TapRequest) Reset() {
	*x = TapRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_admin_v3_tap_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TapRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TapRequest) ProtoMessage() {}

func (x *TapRequest) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_admin_v3_tap_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TapRequest.ProtoReflect.Descriptor instead.
func (*TapRequest) Descriptor() ([]byte, []int) {
	return file_envoy_admin_v3_tap_proto_rawDescGZIP(), []int{0}
}

func (x *TapRequest) GetConfigId() string {
	if x != nil {
		return x.ConfigId
	}
	return ""
}

func (x *TapRequest) GetTapConfig() *v3.TapConfig {
	if x != nil {
		return x.TapConfig
	}
	return nil
}

var File_envoy_admin_v3_tap_proto protoreflect.FileDescriptor

var file_envoy_admin_v3_tap_proto_rawDesc = []byte{
	0x0a, 0x18, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2f, 0x76, 0x33,
	0x2f, 0x74, 0x61, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x65, 0x6e, 0x76, 0x6f,
	0x79, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x33, 0x1a, 0x20, 0x65, 0x6e, 0x76, 0x6f,
	0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x74, 0x61, 0x70, 0x2f, 0x76, 0x33, 0x2f,
	0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x75, 0x64,
	0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x21, 0x75, 0x64, 0x70,
	0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17,
	0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa2, 0x01, 0x0a, 0x0a, 0x54, 0x61, 0x70, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x24, 0x0a, 0x09, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02,
	0x10, 0x01, 0x52, 0x08, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x49, 0x64, 0x12, 0x47, 0x0a, 0x0a,
	0x74, 0x61, 0x70, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1e, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e,
	0x74, 0x61, 0x70, 0x2e, 0x76, 0x33, 0x2e, 0x54, 0x61, 0x70, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x42, 0x08, 0xfa, 0x42, 0x05, 0x8a, 0x01, 0x02, 0x10, 0x01, 0x52, 0x09, 0x74, 0x61, 0x70, 0x43,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x3a, 0x25, 0x9a, 0xc5, 0x88, 0x1e, 0x20, 0x0a, 0x1e, 0x65, 0x6e,
	0x76, 0x6f, 0x79, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x32, 0x61, 0x6c, 0x70, 0x68,
	0x61, 0x2e, 0x54, 0x61, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x42, 0x32, 0x0a, 0x1c,
	0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e,
	0x76, 0x6f, 0x79, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x33, 0x42, 0x08, 0x54, 0x61,
	0x70, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02, 0x10, 0x02,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_admin_v3_tap_proto_rawDescOnce sync.Once
	file_envoy_admin_v3_tap_proto_rawDescData = file_envoy_admin_v3_tap_proto_rawDesc
)

func file_envoy_admin_v3_tap_proto_rawDescGZIP() []byte {
	file_envoy_admin_v3_tap_proto_rawDescOnce.Do(func() {
		file_envoy_admin_v3_tap_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_admin_v3_tap_proto_rawDescData)
	})
	return file_envoy_admin_v3_tap_proto_rawDescData
}

var file_envoy_admin_v3_tap_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_envoy_admin_v3_tap_proto_goTypes = []interface{}{
	(*TapRequest)(nil),   // 0: envoy.admin.v3.TapRequest
	(*v3.TapConfig)(nil), // 1: envoy.config.tap.v3.TapConfig
}
var file_envoy_admin_v3_tap_proto_depIdxs = []int32{
	1, // 0: envoy.admin.v3.TapRequest.tap_config:type_name -> envoy.config.tap.v3.TapConfig
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_envoy_admin_v3_tap_proto_init() }
func file_envoy_admin_v3_tap_proto_init() {
	if File_envoy_admin_v3_tap_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_admin_v3_tap_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TapRequest); i {
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
			RawDescriptor: file_envoy_admin_v3_tap_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_admin_v3_tap_proto_goTypes,
		DependencyIndexes: file_envoy_admin_v3_tap_proto_depIdxs,
		MessageInfos:      file_envoy_admin_v3_tap_proto_msgTypes,
	}.Build()
	File_envoy_admin_v3_tap_proto = out.File
	file_envoy_admin_v3_tap_proto_rawDesc = nil
	file_envoy_admin_v3_tap_proto_goTypes = nil
	file_envoy_admin_v3_tap_proto_depIdxs = nil
}
