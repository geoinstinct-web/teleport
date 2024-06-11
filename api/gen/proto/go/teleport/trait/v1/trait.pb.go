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
// source: teleport/trait/v1/trait.proto

package traitv1

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

// Trait is a trait that can be use in various resources.
type Trait struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// key is the name of the trait.
	Key string `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	// values is the list of trait values.
	Values []string `protobuf:"bytes,2,rep,name=values,proto3" json:"values,omitempty"`
}

func (x *Trait) Reset() {
	*x = Trait{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_trait_v1_trait_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Trait) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Trait) ProtoMessage() {}

func (x *Trait) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_trait_v1_trait_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Trait.ProtoReflect.Descriptor instead.
func (*Trait) Descriptor() ([]byte, []int) {
	return file_teleport_trait_v1_trait_proto_rawDescGZIP(), []int{0}
}

func (x *Trait) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *Trait) GetValues() []string {
	if x != nil {
		return x.Values
	}
	return nil
}

var File_teleport_trait_v1_trait_proto protoreflect.FileDescriptor

var file_teleport_trait_v1_trait_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x74, 0x72, 0x61, 0x69, 0x74,
	0x2f, 0x76, 0x31, 0x2f, 0x74, 0x72, 0x61, 0x69, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x11, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x74, 0x72, 0x61, 0x69, 0x74, 0x2e,
	0x76, 0x31, 0x22, 0x31, 0x0a, 0x05, 0x54, 0x72, 0x61, 0x69, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x6b,
	0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x16, 0x0a,
	0x06, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x06, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x73, 0x42, 0x4e, 0x5a, 0x4c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61,
	0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67,
	0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2f, 0x74, 0x72, 0x61, 0x69, 0x74, 0x2f, 0x76, 0x31, 0x3b, 0x74, 0x72,
	0x61, 0x69, 0x74, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_trait_v1_trait_proto_rawDescOnce sync.Once
	file_teleport_trait_v1_trait_proto_rawDescData = file_teleport_trait_v1_trait_proto_rawDesc
)

func file_teleport_trait_v1_trait_proto_rawDescGZIP() []byte {
	file_teleport_trait_v1_trait_proto_rawDescOnce.Do(func() {
		file_teleport_trait_v1_trait_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_trait_v1_trait_proto_rawDescData)
	})
	return file_teleport_trait_v1_trait_proto_rawDescData
}

var file_teleport_trait_v1_trait_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_teleport_trait_v1_trait_proto_goTypes = []any{
	(*Trait)(nil), // 0: teleport.trait.v1.Trait
}
var file_teleport_trait_v1_trait_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_teleport_trait_v1_trait_proto_init() }
func file_teleport_trait_v1_trait_proto_init() {
	if File_teleport_trait_v1_trait_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleport_trait_v1_trait_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*Trait); i {
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
			RawDescriptor: file_teleport_trait_v1_trait_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_trait_v1_trait_proto_goTypes,
		DependencyIndexes: file_teleport_trait_v1_trait_proto_depIdxs,
		MessageInfos:      file_teleport_trait_v1_trait_proto_msgTypes,
	}.Build()
	File_teleport_trait_v1_trait_proto = out.File
	file_teleport_trait_v1_trait_proto_rawDesc = nil
	file_teleport_trait_v1_trait_proto_goTypes = nil
	file_teleport_trait_v1_trait_proto_depIdxs = nil
}
