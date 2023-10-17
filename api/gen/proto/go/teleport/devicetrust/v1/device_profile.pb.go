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
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: teleport/devicetrust/v1/device_profile.proto

package devicetrustv1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Device profile information acquired from an external source.
// If present, it's used to further validate collected data.
type DeviceProfile struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Latest profile update time.
	// System managed.
	UpdateTime *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty"`
	// Non-descriptive model identifier.
	// Example: "MacBookPro9,2".
	ModelIdentifier string `protobuf:"bytes,2,opt,name=model_identifier,json=modelIdentifier,proto3" json:"model_identifier,omitempty"`
	// OS version number, without the leading 'v'.
	// See the Device's os_type for the general OS category.
	// Example: "13.2.1".
	OsVersion string `protobuf:"bytes,3,opt,name=os_version,json=osVersion,proto3" json:"os_version,omitempty"`
	// OS build identifier. Augments the os_version.
	// Example: "22D68".
	OsBuild string `protobuf:"bytes,4,opt,name=os_build,json=osBuild,proto3" json:"os_build,omitempty"`
	// Known OS users (distinct from the Teleport user).
	OsUsernames []string `protobuf:"bytes,5,rep,name=os_usernames,json=osUsernames,proto3" json:"os_usernames,omitempty"`
	// Jamf binary version, without the leading 'v'.
	// Example: "9.27" or "10.44.1-t1677509507".
	JamfBinaryVersion string `protobuf:"bytes,6,opt,name=jamf_binary_version,json=jamfBinaryVersion,proto3" json:"jamf_binary_version,omitempty"`
	// External device identifier, for example the Jamf or Intune ID.
	ExternalId string `protobuf:"bytes,7,opt,name=external_id,json=externalId,proto3" json:"external_id,omitempty"`
	// OS build supplemental number.
	// May match `sw_vers` BuildVersion more closely in certain situations, like
	// macOS rapid security response builds.
	// Example: "22F770820d".
	OsBuildSupplemental string `protobuf:"bytes,8,opt,name=os_build_supplemental,json=osBuildSupplemental,proto3" json:"os_build_supplemental,omitempty"`
}

func (x *DeviceProfile) Reset() {
	*x = DeviceProfile{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_devicetrust_v1_device_profile_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeviceProfile) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeviceProfile) ProtoMessage() {}

func (x *DeviceProfile) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_devicetrust_v1_device_profile_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeviceProfile.ProtoReflect.Descriptor instead.
func (*DeviceProfile) Descriptor() ([]byte, []int) {
	return file_teleport_devicetrust_v1_device_profile_proto_rawDescGZIP(), []int{0}
}

func (x *DeviceProfile) GetUpdateTime() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

func (x *DeviceProfile) GetModelIdentifier() string {
	if x != nil {
		return x.ModelIdentifier
	}
	return ""
}

func (x *DeviceProfile) GetOsVersion() string {
	if x != nil {
		return x.OsVersion
	}
	return ""
}

func (x *DeviceProfile) GetOsBuild() string {
	if x != nil {
		return x.OsBuild
	}
	return ""
}

func (x *DeviceProfile) GetOsUsernames() []string {
	if x != nil {
		return x.OsUsernames
	}
	return nil
}

func (x *DeviceProfile) GetJamfBinaryVersion() string {
	if x != nil {
		return x.JamfBinaryVersion
	}
	return ""
}

func (x *DeviceProfile) GetExternalId() string {
	if x != nil {
		return x.ExternalId
	}
	return ""
}

func (x *DeviceProfile) GetOsBuildSupplemental() string {
	if x != nil {
		return x.OsBuildSupplemental
	}
	return ""
}

var File_teleport_devicetrust_v1_device_profile_proto protoreflect.FileDescriptor

var file_teleport_devicetrust_v1_device_profile_proto_rawDesc = []byte{
	0x0a, 0x2c, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x64, 0x65, 0x76, 0x69, 0x63,
	0x65, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2f, 0x76, 0x31, 0x2f, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65,
	0x5f, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x17,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x74,
	0x72, 0x75, 0x73, 0x74, 0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xd9, 0x02, 0x0a, 0x0d, 0x44, 0x65, 0x76,
	0x69, 0x63, 0x65, 0x50, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x12, 0x3b, 0x0a, 0x0b, 0x75, 0x70,
	0x64, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x75, 0x70, 0x64,
	0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x29, 0x0a, 0x10, 0x6d, 0x6f, 0x64, 0x65, 0x6c,
	0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0f, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69,
	0x65, 0x72, 0x12, 0x1d, 0x0a, 0x0a, 0x6f, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6f, 0x73, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x12, 0x19, 0x0a, 0x08, 0x6f, 0x73, 0x5f, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x6f, 0x73, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x12, 0x21, 0x0a, 0x0c,
	0x6f, 0x73, 0x5f, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x18, 0x05, 0x20, 0x03,
	0x28, 0x09, 0x52, 0x0b, 0x6f, 0x73, 0x55, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x12,
	0x2e, 0x0a, 0x13, 0x6a, 0x61, 0x6d, 0x66, 0x5f, 0x62, 0x69, 0x6e, 0x61, 0x72, 0x79, 0x5f, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x6a, 0x61,
	0x6d, 0x66, 0x42, 0x69, 0x6e, 0x61, 0x72, 0x79, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12,
	0x1f, 0x0a, 0x0b, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x5f, 0x69, 0x64, 0x18, 0x07,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x49, 0x64,
	0x12, 0x32, 0x0a, 0x15, 0x6f, 0x73, 0x5f, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x5f, 0x73, 0x75, 0x70,
	0x70, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x6c, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x13, 0x6f, 0x73, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x53, 0x75, 0x70, 0x70, 0x6c, 0x65, 0x6d, 0x65,
	0x6e, 0x74, 0x61, 0x6c, 0x42, 0x5a, 0x5a, 0x58, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c,
	0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65,
	0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2f, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2f,
	0x76, 0x31, 0x3b, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x74, 0x72, 0x75, 0x73, 0x74, 0x76, 0x31,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_devicetrust_v1_device_profile_proto_rawDescOnce sync.Once
	file_teleport_devicetrust_v1_device_profile_proto_rawDescData = file_teleport_devicetrust_v1_device_profile_proto_rawDesc
)

func file_teleport_devicetrust_v1_device_profile_proto_rawDescGZIP() []byte {
	file_teleport_devicetrust_v1_device_profile_proto_rawDescOnce.Do(func() {
		file_teleport_devicetrust_v1_device_profile_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_devicetrust_v1_device_profile_proto_rawDescData)
	})
	return file_teleport_devicetrust_v1_device_profile_proto_rawDescData
}

var file_teleport_devicetrust_v1_device_profile_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_teleport_devicetrust_v1_device_profile_proto_goTypes = []interface{}{
	(*DeviceProfile)(nil),         // 0: teleport.devicetrust.v1.DeviceProfile
	(*timestamppb.Timestamp)(nil), // 1: google.protobuf.Timestamp
}
var file_teleport_devicetrust_v1_device_profile_proto_depIdxs = []int32{
	1, // 0: teleport.devicetrust.v1.DeviceProfile.update_time:type_name -> google.protobuf.Timestamp
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_teleport_devicetrust_v1_device_profile_proto_init() }
func file_teleport_devicetrust_v1_device_profile_proto_init() {
	if File_teleport_devicetrust_v1_device_profile_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleport_devicetrust_v1_device_profile_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeviceProfile); i {
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
			RawDescriptor: file_teleport_devicetrust_v1_device_profile_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_devicetrust_v1_device_profile_proto_goTypes,
		DependencyIndexes: file_teleport_devicetrust_v1_device_profile_proto_depIdxs,
		MessageInfos:      file_teleport_devicetrust_v1_device_profile_proto_msgTypes,
	}.Build()
	File_teleport_devicetrust_v1_device_profile_proto = out.File
	file_teleport_devicetrust_v1_device_profile_proto_rawDesc = nil
	file_teleport_devicetrust_v1_device_profile_proto_goTypes = nil
	file_teleport_devicetrust_v1_device_profile_proto_depIdxs = nil
}
