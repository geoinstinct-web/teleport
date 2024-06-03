// Copyright 2024 Gravitational, Inc.
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
// 	protoc-gen-go v1.34.1
// 	protoc        (unknown)
// source: teleport/vnet/v1/vnet_config.proto

package vnet

import (
	v1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
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

// VnetConfig is a resource that holds configuration parameters for Teleport VNet.
type VnetConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Kind     string          `protobuf:"bytes,1,opt,name=kind,proto3" json:"kind,omitempty"`
	SubKind  string          `protobuf:"bytes,2,opt,name=sub_kind,json=subKind,proto3" json:"sub_kind,omitempty"`
	Version  string          `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"`
	Metadata *v1.Metadata    `protobuf:"bytes,4,opt,name=metadata,proto3" json:"metadata,omitempty"`
	Spec     *VnetConfigSpec `protobuf:"bytes,5,opt,name=spec,proto3" json:"spec,omitempty"`
}

func (x *VnetConfig) Reset() {
	*x = VnetConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_vnet_v1_vnet_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VnetConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VnetConfig) ProtoMessage() {}

func (x *VnetConfig) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_vnet_v1_vnet_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VnetConfig.ProtoReflect.Descriptor instead.
func (*VnetConfig) Descriptor() ([]byte, []int) {
	return file_teleport_vnet_v1_vnet_config_proto_rawDescGZIP(), []int{0}
}

func (x *VnetConfig) GetKind() string {
	if x != nil {
		return x.Kind
	}
	return ""
}

func (x *VnetConfig) GetSubKind() string {
	if x != nil {
		return x.SubKind
	}
	return ""
}

func (x *VnetConfig) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *VnetConfig) GetMetadata() *v1.Metadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

func (x *VnetConfig) GetSpec() *VnetConfigSpec {
	if x != nil {
		return x.Spec
	}
	return nil
}

// VnetConfigSpec defines configuration parameters for VNet.
type VnetConfigSpec struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Ipv4CidrRange defines the IPv4 CIDR range that all IPv4 addresses for VNet
	// apps in this cluster will be assigned from. The default is "100.64.0.0/10".
	Ipv4CidrRange string `protobuf:"bytes,1,opt,name=ipv4_cidr_range,json=ipv4CidrRange,proto3" json:"ipv4_cidr_range,omitempty"`
	// CustomDnsZones defines a list of DNS zones that VNet should resolve requests for in addition to the
	// cluster's public proxy address.
	CustomDnsZones []*CustomDNSZone `protobuf:"bytes,2,rep,name=custom_dns_zones,json=customDnsZones,proto3" json:"custom_dns_zones,omitempty"`
}

func (x *VnetConfigSpec) Reset() {
	*x = VnetConfigSpec{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_vnet_v1_vnet_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VnetConfigSpec) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VnetConfigSpec) ProtoMessage() {}

func (x *VnetConfigSpec) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_vnet_v1_vnet_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VnetConfigSpec.ProtoReflect.Descriptor instead.
func (*VnetConfigSpec) Descriptor() ([]byte, []int) {
	return file_teleport_vnet_v1_vnet_config_proto_rawDescGZIP(), []int{1}
}

func (x *VnetConfigSpec) GetIpv4CidrRange() string {
	if x != nil {
		return x.Ipv4CidrRange
	}
	return ""
}

func (x *VnetConfigSpec) GetCustomDnsZones() []*CustomDNSZone {
	if x != nil {
		return x.CustomDnsZones
	}
	return nil
}

// CustomDNSZone defines parameters for custom DNS zones.
type CustomDNSZone struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Suffix is the hostname suffix that defines this zone.
	Suffix string `protobuf:"bytes,1,opt,name=suffix,proto3" json:"suffix,omitempty"`
}

func (x *CustomDNSZone) Reset() {
	*x = CustomDNSZone{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_vnet_v1_vnet_config_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CustomDNSZone) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CustomDNSZone) ProtoMessage() {}

func (x *CustomDNSZone) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_vnet_v1_vnet_config_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CustomDNSZone.ProtoReflect.Descriptor instead.
func (*CustomDNSZone) Descriptor() ([]byte, []int) {
	return file_teleport_vnet_v1_vnet_config_proto_rawDescGZIP(), []int{2}
}

func (x *CustomDNSZone) GetSuffix() string {
	if x != nil {
		return x.Suffix
	}
	return ""
}

var File_teleport_vnet_v1_vnet_config_proto protoreflect.FileDescriptor

var file_teleport_vnet_v1_vnet_config_proto_rawDesc = []byte{
	0x0a, 0x22, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x76, 0x6e, 0x65, 0x74, 0x2f,
	0x76, 0x31, 0x2f, 0x76, 0x6e, 0x65, 0x74, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x10, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x76,
	0x6e, 0x65, 0x74, 0x2e, 0x76, 0x31, 0x1a, 0x21, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74,
	0x2f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x2f, 0x76, 0x31, 0x2f, 0x6d, 0x65, 0x74, 0x61, 0x64,
	0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc5, 0x01, 0x0a, 0x0a, 0x56, 0x6e,
	0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x12, 0x0a, 0x04, 0x6b, 0x69, 0x6e, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x12, 0x19, 0x0a, 0x08,
	0x73, 0x75, 0x62, 0x5f, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07,
	0x73, 0x75, 0x62, 0x4b, 0x69, 0x6e, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x12, 0x38, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x68,
	0x65, 0x61, 0x64, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x34, 0x0a, 0x04, 0x73,
	0x70, 0x65, 0x63, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x76, 0x6e, 0x65, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x56, 0x6e, 0x65,
	0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x53, 0x70, 0x65, 0x63, 0x52, 0x04, 0x73, 0x70, 0x65,
	0x63, 0x22, 0x83, 0x01, 0x0a, 0x0e, 0x56, 0x6e, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x53, 0x70, 0x65, 0x63, 0x12, 0x26, 0x0a, 0x0f, 0x69, 0x70, 0x76, 0x34, 0x5f, 0x63, 0x69, 0x64,
	0x72, 0x5f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x69,
	0x70, 0x76, 0x34, 0x43, 0x69, 0x64, 0x72, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x12, 0x49, 0x0a, 0x10,
	0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x64, 0x6e, 0x73, 0x5f, 0x7a, 0x6f, 0x6e, 0x65, 0x73,
	0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x76, 0x6e, 0x65, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d,
	0x44, 0x4e, 0x53, 0x5a, 0x6f, 0x6e, 0x65, 0x52, 0x0e, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x44,
	0x6e, 0x73, 0x5a, 0x6f, 0x6e, 0x65, 0x73, 0x22, 0x27, 0x0a, 0x0d, 0x43, 0x75, 0x73, 0x74, 0x6f,
	0x6d, 0x44, 0x4e, 0x53, 0x5a, 0x6f, 0x6e, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x75, 0x66, 0x66,
	0x69, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x75, 0x66, 0x66, 0x69, 0x78,
	0x42, 0x4a, 0x5a, 0x48, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67,
	0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f,
	0x76, 0x6e, 0x65, 0x74, 0x2f, 0x76, 0x31, 0x3b, 0x76, 0x6e, 0x65, 0x74, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_vnet_v1_vnet_config_proto_rawDescOnce sync.Once
	file_teleport_vnet_v1_vnet_config_proto_rawDescData = file_teleport_vnet_v1_vnet_config_proto_rawDesc
)

func file_teleport_vnet_v1_vnet_config_proto_rawDescGZIP() []byte {
	file_teleport_vnet_v1_vnet_config_proto_rawDescOnce.Do(func() {
		file_teleport_vnet_v1_vnet_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_vnet_v1_vnet_config_proto_rawDescData)
	})
	return file_teleport_vnet_v1_vnet_config_proto_rawDescData
}

var file_teleport_vnet_v1_vnet_config_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_teleport_vnet_v1_vnet_config_proto_goTypes = []interface{}{
	(*VnetConfig)(nil),     // 0: teleport.vnet.v1.VnetConfig
	(*VnetConfigSpec)(nil), // 1: teleport.vnet.v1.VnetConfigSpec
	(*CustomDNSZone)(nil),  // 2: teleport.vnet.v1.CustomDNSZone
	(*v1.Metadata)(nil),    // 3: teleport.header.v1.Metadata
}
var file_teleport_vnet_v1_vnet_config_proto_depIdxs = []int32{
	3, // 0: teleport.vnet.v1.VnetConfig.metadata:type_name -> teleport.header.v1.Metadata
	1, // 1: teleport.vnet.v1.VnetConfig.spec:type_name -> teleport.vnet.v1.VnetConfigSpec
	2, // 2: teleport.vnet.v1.VnetConfigSpec.custom_dns_zones:type_name -> teleport.vnet.v1.CustomDNSZone
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_teleport_vnet_v1_vnet_config_proto_init() }
func file_teleport_vnet_v1_vnet_config_proto_init() {
	if File_teleport_vnet_v1_vnet_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleport_vnet_v1_vnet_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VnetConfig); i {
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
		file_teleport_vnet_v1_vnet_config_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VnetConfigSpec); i {
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
		file_teleport_vnet_v1_vnet_config_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CustomDNSZone); i {
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
			RawDescriptor: file_teleport_vnet_v1_vnet_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_vnet_v1_vnet_config_proto_goTypes,
		DependencyIndexes: file_teleport_vnet_v1_vnet_config_proto_depIdxs,
		MessageInfos:      file_teleport_vnet_v1_vnet_config_proto_msgTypes,
	}.Build()
	File_teleport_vnet_v1_vnet_config_proto = out.File
	file_teleport_vnet_v1_vnet_config_proto_rawDesc = nil
	file_teleport_vnet_v1_vnet_config_proto_goTypes = nil
	file_teleport_vnet_v1_vnet_config_proto_depIdxs = nil
}
