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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        (unknown)
// source: teleport/header/v1/resourceheader.proto

package headerv1

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

// ResourceHeader is a shared resource header.
type ResourceHeader struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// kind is a resource kind.
	Kind string `protobuf:"bytes,1,opt,name=kind,proto3" json:"kind,omitempty"`
	// sub_kind is an optional resource sub kind, used in some resources.
	SubKind string `protobuf:"bytes,2,opt,name=sub_kind,json=subKind,proto3" json:"sub_kind,omitempty"`
	// Version is the API version used to create the resource. It must be
	// specified. Based on this version, Teleport will apply different defaults on
	// resource creation or deletion. It must be an integer prefixed by "v".
	// For example: `v1`
	Version string `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"`
	// metadata is resource metadata.
	Metadata *Metadata `protobuf:"bytes,4,opt,name=metadata,proto3" json:"metadata,omitempty"`
}

func (x *ResourceHeader) Reset() {
	*x = ResourceHeader{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_header_v1_resourceheader_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ResourceHeader) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResourceHeader) ProtoMessage() {}

func (x *ResourceHeader) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_header_v1_resourceheader_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ResourceHeader.ProtoReflect.Descriptor instead.
func (*ResourceHeader) Descriptor() ([]byte, []int) {
	return file_teleport_header_v1_resourceheader_proto_rawDescGZIP(), []int{0}
}

func (x *ResourceHeader) GetKind() string {
	if x != nil {
		return x.Kind
	}
	return ""
}

func (x *ResourceHeader) GetSubKind() string {
	if x != nil {
		return x.SubKind
	}
	return ""
}

func (x *ResourceHeader) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *ResourceHeader) GetMetadata() *Metadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

var File_teleport_header_v1_resourceheader_proto protoreflect.FileDescriptor

var file_teleport_header_v1_resourceheader_proto_rawDesc = []byte{
	0x0a, 0x27, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x68, 0x65, 0x61, 0x64, 0x65,
	0x72, 0x2f, 0x76, 0x31, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x68, 0x65, 0x61,
	0x64, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x12, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x1a, 0x21, 0x74,
	0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x2f, 0x76,
	0x31, 0x2f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0x93, 0x01, 0x0a, 0x0e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x48, 0x65, 0x61,
	0x64, 0x65, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x75, 0x62, 0x5f, 0x6b,
	0x69, 0x6e, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x75, 0x62, 0x4b, 0x69,
	0x6e, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x38, 0x0a, 0x08,
	0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c,
	0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
	0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x08, 0x6d, 0x65,
	0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x42, 0x50, 0x5a, 0x4e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f,
	0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x2f, 0x76, 0x31, 0x3b,
	0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_header_v1_resourceheader_proto_rawDescOnce sync.Once
	file_teleport_header_v1_resourceheader_proto_rawDescData = file_teleport_header_v1_resourceheader_proto_rawDesc
)

func file_teleport_header_v1_resourceheader_proto_rawDescGZIP() []byte {
	file_teleport_header_v1_resourceheader_proto_rawDescOnce.Do(func() {
		file_teleport_header_v1_resourceheader_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_header_v1_resourceheader_proto_rawDescData)
	})
	return file_teleport_header_v1_resourceheader_proto_rawDescData
}

var file_teleport_header_v1_resourceheader_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_teleport_header_v1_resourceheader_proto_goTypes = []any{
	(*ResourceHeader)(nil), // 0: teleport.header.v1.ResourceHeader
	(*Metadata)(nil),       // 1: teleport.header.v1.Metadata
}
var file_teleport_header_v1_resourceheader_proto_depIdxs = []int32{
	1, // 0: teleport.header.v1.ResourceHeader.metadata:type_name -> teleport.header.v1.Metadata
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_teleport_header_v1_resourceheader_proto_init() }
func file_teleport_header_v1_resourceheader_proto_init() {
	if File_teleport_header_v1_resourceheader_proto != nil {
		return
	}
	file_teleport_header_v1_metadata_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_teleport_header_v1_resourceheader_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*ResourceHeader); i {
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
			RawDescriptor: file_teleport_header_v1_resourceheader_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_header_v1_resourceheader_proto_goTypes,
		DependencyIndexes: file_teleport_header_v1_resourceheader_proto_depIdxs,
		MessageInfos:      file_teleport_header_v1_resourceheader_proto_msgTypes,
	}.Build()
	File_teleport_header_v1_resourceheader_proto = out.File
	file_teleport_header_v1_resourceheader_proto_rawDesc = nil
	file_teleport_header_v1_resourceheader_proto_goTypes = nil
	file_teleport_header_v1_resourceheader_proto_depIdxs = nil
}
