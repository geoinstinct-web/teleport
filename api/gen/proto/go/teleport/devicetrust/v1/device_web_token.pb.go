// Copyright 2024 Gravitational, Inc
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
// 	protoc-gen-go v1.33.0
// 	protoc        (unknown)
// source: teleport/devicetrust/v1/device_web_token.proto

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

// A device web token is a token used to device-authenticate a Web UI session.
//
// Tokens are generally acquired on login and exchanged for a single
// on-behalf-of device authentication attempt, performed by Connect.
//
// See
// https://github.com/gravitational/teleport.e/blob/master/rfd/0009e-device-trust-web-support.md#device-web-token.
type DeviceWebToken struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Opaque token identifier.
	// Required for token usage.
	// System-generated.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// Opaque device web token, in plaintext, encoded in base64.RawURLEncoding
	// (so it is inherently safe for URl use).
	// Required for token usage.
	// System-generated.
	Token string `protobuf:"bytes,2,opt,name=token,proto3" json:"token,omitempty"`
	// Identifier for the Web Session being device-authorized.
	// Required for creation.
	WebSessionId string `protobuf:"bytes,3,opt,name=web_session_id,json=webSessionId,proto3" json:"web_session_id,omitempty"`
	// Browser user agent, as acquired from the Web UI browser.
	// Used as part of expected device checks.
	// Required for creation.
	BrowserUserAgent string `protobuf:"bytes,4,opt,name=browser_user_agent,json=browserUserAgent,proto3" json:"browser_user_agent,omitempty"`
	// Browser public IP, as acquired from the Web UI browser.
	// Used as part of expected device checks.
	// Required for creation.
	BrowserIp string `protobuf:"bytes,5,opt,name=browser_ip,json=browserIp,proto3" json:"browser_ip,omitempty"`
	// Owner of the Web Session and trusted device.
	// Used internally by the Device Trust system.
	// Transient.
	User string `protobuf:"bytes,6,opt,name=user,proto3" json:"user,omitempty"`
	// ID of the devices allowed to perform on-behalf-of device authentication.
	// Used internally by the Device Trust system.
	// Transient.
	ExpectedDeviceIds []string `protobuf:"bytes,7,rep,name=expected_device_ids,json=expectedDeviceIds,proto3" json:"expected_device_ids,omitempty"`
}

func (x *DeviceWebToken) Reset() {
	*x = DeviceWebToken{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_devicetrust_v1_device_web_token_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeviceWebToken) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeviceWebToken) ProtoMessage() {}

func (x *DeviceWebToken) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_devicetrust_v1_device_web_token_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeviceWebToken.ProtoReflect.Descriptor instead.
func (*DeviceWebToken) Descriptor() ([]byte, []int) {
	return file_teleport_devicetrust_v1_device_web_token_proto_rawDescGZIP(), []int{0}
}

func (x *DeviceWebToken) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *DeviceWebToken) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

func (x *DeviceWebToken) GetWebSessionId() string {
	if x != nil {
		return x.WebSessionId
	}
	return ""
}

func (x *DeviceWebToken) GetBrowserUserAgent() string {
	if x != nil {
		return x.BrowserUserAgent
	}
	return ""
}

func (x *DeviceWebToken) GetBrowserIp() string {
	if x != nil {
		return x.BrowserIp
	}
	return ""
}

func (x *DeviceWebToken) GetUser() string {
	if x != nil {
		return x.User
	}
	return ""
}

func (x *DeviceWebToken) GetExpectedDeviceIds() []string {
	if x != nil {
		return x.ExpectedDeviceIds
	}
	return nil
}

var File_teleport_devicetrust_v1_device_web_token_proto protoreflect.FileDescriptor

var file_teleport_devicetrust_v1_device_web_token_proto_rawDesc = []byte{
	0x0a, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x64, 0x65, 0x76, 0x69, 0x63,
	0x65, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2f, 0x76, 0x31, 0x2f, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65,
	0x5f, 0x77, 0x65, 0x62, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x17, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x65, 0x76, 0x69, 0x63,
	0x65, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x76, 0x31, 0x22, 0xed, 0x01, 0x0a, 0x0e, 0x44, 0x65,
	0x76, 0x69, 0x63, 0x65, 0x57, 0x65, 0x62, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x0e, 0x0a, 0x02,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x14, 0x0a, 0x05,
	0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x6f, 0x6b,
	0x65, 0x6e, 0x12, 0x24, 0x0a, 0x0e, 0x77, 0x65, 0x62, 0x5f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f,
	0x6e, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x77, 0x65, 0x62, 0x53,
	0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x2c, 0x0a, 0x12, 0x62, 0x72, 0x6f, 0x77,
	0x73, 0x65, 0x72, 0x5f, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x62, 0x72, 0x6f, 0x77, 0x73, 0x65, 0x72, 0x55, 0x73, 0x65,
	0x72, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x62, 0x72, 0x6f, 0x77, 0x73, 0x65,
	0x72, 0x5f, 0x69, 0x70, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x62, 0x72, 0x6f, 0x77,
	0x73, 0x65, 0x72, 0x49, 0x70, 0x12, 0x12, 0x0a, 0x04, 0x75, 0x73, 0x65, 0x72, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x75, 0x73, 0x65, 0x72, 0x12, 0x2e, 0x0a, 0x13, 0x65, 0x78, 0x70,
	0x65, 0x63, 0x74, 0x65, 0x64, 0x5f, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x5f, 0x69, 0x64, 0x73,
	0x18, 0x07, 0x20, 0x03, 0x28, 0x09, 0x52, 0x11, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x65, 0x64,
	0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x49, 0x64, 0x73, 0x42, 0x5a, 0x5a, 0x58, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61,
	0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x74,
	0x72, 0x75, 0x73, 0x74, 0x2f, 0x76, 0x31, 0x3b, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x74, 0x72,
	0x75, 0x73, 0x74, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_devicetrust_v1_device_web_token_proto_rawDescOnce sync.Once
	file_teleport_devicetrust_v1_device_web_token_proto_rawDescData = file_teleport_devicetrust_v1_device_web_token_proto_rawDesc
)

func file_teleport_devicetrust_v1_device_web_token_proto_rawDescGZIP() []byte {
	file_teleport_devicetrust_v1_device_web_token_proto_rawDescOnce.Do(func() {
		file_teleport_devicetrust_v1_device_web_token_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_devicetrust_v1_device_web_token_proto_rawDescData)
	})
	return file_teleport_devicetrust_v1_device_web_token_proto_rawDescData
}

var file_teleport_devicetrust_v1_device_web_token_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_teleport_devicetrust_v1_device_web_token_proto_goTypes = []interface{}{
	(*DeviceWebToken)(nil), // 0: teleport.devicetrust.v1.DeviceWebToken
}
var file_teleport_devicetrust_v1_device_web_token_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_teleport_devicetrust_v1_device_web_token_proto_init() }
func file_teleport_devicetrust_v1_device_web_token_proto_init() {
	if File_teleport_devicetrust_v1_device_web_token_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleport_devicetrust_v1_device_web_token_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeviceWebToken); i {
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
			RawDescriptor: file_teleport_devicetrust_v1_device_web_token_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_devicetrust_v1_device_web_token_proto_goTypes,
		DependencyIndexes: file_teleport_devicetrust_v1_device_web_token_proto_depIdxs,
		MessageInfos:      file_teleport_devicetrust_v1_device_web_token_proto_msgTypes,
	}.Build()
	File_teleport_devicetrust_v1_device_web_token_proto = out.File
	file_teleport_devicetrust_v1_device_web_token_proto_rawDesc = nil
	file_teleport_devicetrust_v1_device_web_token_proto_goTypes = nil
	file_teleport_devicetrust_v1_device_web_token_proto_depIdxs = nil
}
