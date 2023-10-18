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
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: teleport/devicetrust/v1/os_type.proto

package devicetrustv1

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

// OSType represents the operating system of a device.
type OSType int32

const (
	OSType_OS_TYPE_UNSPECIFIED OSType = 0
	// Linux.
	OSType_OS_TYPE_LINUX OSType = 1
	// macOS.
	OSType_OS_TYPE_MACOS OSType = 2
	// Windows.
	OSType_OS_TYPE_WINDOWS OSType = 3
)

// Enum value maps for OSType.
var (
	OSType_name = map[int32]string{
		0: "OS_TYPE_UNSPECIFIED",
		1: "OS_TYPE_LINUX",
		2: "OS_TYPE_MACOS",
		3: "OS_TYPE_WINDOWS",
	}
	OSType_value = map[string]int32{
		"OS_TYPE_UNSPECIFIED": 0,
		"OS_TYPE_LINUX":       1,
		"OS_TYPE_MACOS":       2,
		"OS_TYPE_WINDOWS":     3,
	}
)

func (x OSType) Enum() *OSType {
	p := new(OSType)
	*p = x
	return p
}

func (x OSType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (OSType) Descriptor() protoreflect.EnumDescriptor {
	return file_teleport_devicetrust_v1_os_type_proto_enumTypes[0].Descriptor()
}

func (OSType) Type() protoreflect.EnumType {
	return &file_teleport_devicetrust_v1_os_type_proto_enumTypes[0]
}

func (x OSType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use OSType.Descriptor instead.
func (OSType) EnumDescriptor() ([]byte, []int) {
	return file_teleport_devicetrust_v1_os_type_proto_rawDescGZIP(), []int{0}
}

var File_teleport_devicetrust_v1_os_type_proto protoreflect.FileDescriptor

var file_teleport_devicetrust_v1_os_type_proto_rawDesc = []byte{
	0x0a, 0x25, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x64, 0x65, 0x76, 0x69, 0x63,
	0x65, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2f, 0x76, 0x31, 0x2f, 0x6f, 0x73, 0x5f, 0x74, 0x79, 0x70,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x17, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x76, 0x31,
	0x2a, 0x5c, 0x0a, 0x06, 0x4f, 0x53, 0x54, 0x79, 0x70, 0x65, 0x12, 0x17, 0x0a, 0x13, 0x4f, 0x53,
	0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45,
	0x44, 0x10, 0x00, 0x12, 0x11, 0x0a, 0x0d, 0x4f, 0x53, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x4c,
	0x49, 0x4e, 0x55, 0x58, 0x10, 0x01, 0x12, 0x11, 0x0a, 0x0d, 0x4f, 0x53, 0x5f, 0x54, 0x59, 0x50,
	0x45, 0x5f, 0x4d, 0x41, 0x43, 0x4f, 0x53, 0x10, 0x02, 0x12, 0x13, 0x0a, 0x0f, 0x4f, 0x53, 0x5f,
	0x54, 0x59, 0x50, 0x45, 0x5f, 0x57, 0x49, 0x4e, 0x44, 0x4f, 0x57, 0x53, 0x10, 0x03, 0x42, 0x5a,
	0x5a, 0x58, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61,
	0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x64, 0x65,
	0x76, 0x69, 0x63, 0x65, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2f, 0x76, 0x31, 0x3b, 0x64, 0x65, 0x76,
	0x69, 0x63, 0x65, 0x74, 0x72, 0x75, 0x73, 0x74, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_teleport_devicetrust_v1_os_type_proto_rawDescOnce sync.Once
	file_teleport_devicetrust_v1_os_type_proto_rawDescData = file_teleport_devicetrust_v1_os_type_proto_rawDesc
)

func file_teleport_devicetrust_v1_os_type_proto_rawDescGZIP() []byte {
	file_teleport_devicetrust_v1_os_type_proto_rawDescOnce.Do(func() {
		file_teleport_devicetrust_v1_os_type_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_devicetrust_v1_os_type_proto_rawDescData)
	})
	return file_teleport_devicetrust_v1_os_type_proto_rawDescData
}

var file_teleport_devicetrust_v1_os_type_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_teleport_devicetrust_v1_os_type_proto_goTypes = []interface{}{
	(OSType)(0), // 0: teleport.devicetrust.v1.OSType
}
var file_teleport_devicetrust_v1_os_type_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_teleport_devicetrust_v1_os_type_proto_init() }
func file_teleport_devicetrust_v1_os_type_proto_init() {
	if File_teleport_devicetrust_v1_os_type_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_teleport_devicetrust_v1_os_type_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_devicetrust_v1_os_type_proto_goTypes,
		DependencyIndexes: file_teleport_devicetrust_v1_os_type_proto_depIdxs,
		EnumInfos:         file_teleport_devicetrust_v1_os_type_proto_enumTypes,
	}.Build()
	File_teleport_devicetrust_v1_os_type_proto = out.File
	file_teleport_devicetrust_v1_os_type_proto_rawDesc = nil
	file_teleport_devicetrust_v1_os_type_proto_goTypes = nil
	file_teleport_devicetrust_v1_os_type_proto_depIdxs = nil
}
