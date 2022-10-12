// Copyright 2021 Gravitational, Inc
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
// 	protoc-gen-go v1.26.0
// 	protoc        (unknown)
// source: v1/app.proto

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

// App describes connected Application
type App struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// uri is the app resource URI
	Uri string `protobuf:"bytes,1,opt,name=uri,proto3" json:"uri,omitempty"`
	// name is the app name
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	// description is the app description.
	Description string `protobuf:"bytes,3,opt,name=description,proto3" json:"description,omitempty"`
	// uri is the internal address the application is available at.
	AppUri string `protobuf:"bytes,4,opt,name=app_uri,json=appUri,proto3" json:"app_uri,omitempty"`
	// public_addr is the public address the application is accessible at.
	PublicAddr string `protobuf:"bytes,5,opt,name=public_addr,json=publicAddr,proto3" json:"public_addr,omitempty"`
	// fqdn is a fully qualified domain name of the application (app.example.com)
	Fqdn string `protobuf:"bytes,6,opt,name=fqdn,proto3" json:"fqdn,omitempty"`
	// labels is a map of static labels associated with an application.
	Labels []*Label `protobuf:"bytes,7,rep,name=labels,proto3" json:"labels,omitempty"`
	// aws_console if true, indicates that the app represents AWS management console.
	AwsConsole bool `protobuf:"varint,8,opt,name=aws_console,json=awsConsole,proto3" json:"aws_console,omitempty"`
	// aws_roles is a list of AWS IAM roles for the application representing AWS console.
	AwsRoles []*App_AWSRole `protobuf:"bytes,9,rep,name=aws_roles,json=awsRoles,proto3" json:"aws_roles,omitempty"`
}

func (x *App) Reset() {
	*x = App{}
	if protoimpl.UnsafeEnabled {
		mi := &file_v1_app_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *App) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*App) ProtoMessage() {}

func (x *App) ProtoReflect() protoreflect.Message {
	mi := &file_v1_app_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use App.ProtoReflect.Descriptor instead.
func (*App) Descriptor() ([]byte, []int) {
	return file_v1_app_proto_rawDescGZIP(), []int{0}
}

func (x *App) GetUri() string {
	if x != nil {
		return x.Uri
	}
	return ""
}

func (x *App) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *App) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *App) GetAppUri() string {
	if x != nil {
		return x.AppUri
	}
	return ""
}

func (x *App) GetPublicAddr() string {
	if x != nil {
		return x.PublicAddr
	}
	return ""
}

func (x *App) GetFqdn() string {
	if x != nil {
		return x.Fqdn
	}
	return ""
}

func (x *App) GetLabels() []*Label {
	if x != nil {
		return x.Labels
	}
	return nil
}

func (x *App) GetAwsConsole() bool {
	if x != nil {
		return x.AwsConsole
	}
	return false
}

func (x *App) GetAwsRoles() []*App_AWSRole {
	if x != nil {
		return x.AwsRoles
	}
	return nil
}

type App_AWSRole struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// display is the role display name.
	Display string `protobuf:"bytes,1,opt,name=display,proto3" json:"display,omitempty"`
	// arn is the full role ARN.
	Arn string `protobuf:"bytes,2,opt,name=arn,proto3" json:"arn,omitempty"`
}

func (x *App_AWSRole) Reset() {
	*x = App_AWSRole{}
	if protoimpl.UnsafeEnabled {
		mi := &file_v1_app_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *App_AWSRole) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*App_AWSRole) ProtoMessage() {}

func (x *App_AWSRole) ProtoReflect() protoreflect.Message {
	mi := &file_v1_app_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use App_AWSRole.ProtoReflect.Descriptor instead.
func (*App_AWSRole) Descriptor() ([]byte, []int) {
	return file_v1_app_proto_rawDescGZIP(), []int{0, 0}
}

func (x *App_AWSRole) GetDisplay() string {
	if x != nil {
		return x.Display
	}
	return ""
}

func (x *App_AWSRole) GetArn() string {
	if x != nil {
		return x.Arn
	}
	return ""
}

var File_v1_app_proto protoreflect.FileDescriptor

var file_v1_app_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x76, 0x31, 0x2f, 0x61, 0x70, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x14,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x74, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x61,
	0x6c, 0x2e, 0x76, 0x31, 0x1a, 0x0e, 0x76, 0x31, 0x2f, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xe8, 0x02, 0x0a, 0x03, 0x41, 0x70, 0x70, 0x12, 0x10, 0x0a, 0x03,
	0x75, 0x72, 0x69, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x75, 0x72, 0x69, 0x12, 0x12,
	0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x12, 0x17, 0x0a, 0x07, 0x61, 0x70, 0x70, 0x5f, 0x75, 0x72, 0x69, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x61, 0x70, 0x70, 0x55, 0x72, 0x69, 0x12, 0x1f, 0x0a,
	0x0b, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x41, 0x64, 0x64, 0x72, 0x12, 0x12,
	0x0a, 0x04, 0x66, 0x71, 0x64, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x66, 0x71,
	0x64, 0x6e, 0x12, 0x33, 0x0a, 0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x18, 0x07, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x74, 0x65,
	0x72, 0x6d, 0x69, 0x6e, 0x61, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x52,
	0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x12, 0x1f, 0x0a, 0x0b, 0x61, 0x77, 0x73, 0x5f, 0x63,
	0x6f, 0x6e, 0x73, 0x6f, 0x6c, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x61, 0x77,
	0x73, 0x43, 0x6f, 0x6e, 0x73, 0x6f, 0x6c, 0x65, 0x12, 0x3e, 0x0a, 0x09, 0x61, 0x77, 0x73, 0x5f,
	0x72, 0x6f, 0x6c, 0x65, 0x73, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x74, 0x65,
	0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x74, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x61, 0x6c, 0x2e,
	0x76, 0x31, 0x2e, 0x41, 0x70, 0x70, 0x2e, 0x41, 0x57, 0x53, 0x52, 0x6f, 0x6c, 0x65, 0x52, 0x08,
	0x61, 0x77, 0x73, 0x52, 0x6f, 0x6c, 0x65, 0x73, 0x1a, 0x35, 0x0a, 0x07, 0x41, 0x57, 0x53, 0x52,
	0x6f, 0x6c, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x12, 0x10, 0x0a,
	0x03, 0x61, 0x72, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x61, 0x72, 0x6e, 0x42,
	0x33, 0x5a, 0x31, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72,
	0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6c, 0x69, 0x62, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x72,
	0x6d, 0x2f, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_v1_app_proto_rawDescOnce sync.Once
	file_v1_app_proto_rawDescData = file_v1_app_proto_rawDesc
)

func file_v1_app_proto_rawDescGZIP() []byte {
	file_v1_app_proto_rawDescOnce.Do(func() {
		file_v1_app_proto_rawDescData = protoimpl.X.CompressGZIP(file_v1_app_proto_rawDescData)
	})
	return file_v1_app_proto_rawDescData
}

var file_v1_app_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_v1_app_proto_goTypes = []interface{}{
	(*App)(nil),         // 0: teleport.terminal.v1.App
	(*App_AWSRole)(nil), // 1: teleport.terminal.v1.App.AWSRole
	(*Label)(nil),       // 2: teleport.terminal.v1.Label
}
var file_v1_app_proto_depIdxs = []int32{
	2, // 0: teleport.terminal.v1.App.labels:type_name -> teleport.terminal.v1.Label
	1, // 1: teleport.terminal.v1.App.aws_roles:type_name -> teleport.terminal.v1.App.AWSRole
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_v1_app_proto_init() }
func file_v1_app_proto_init() {
	if File_v1_app_proto != nil {
		return
	}
	file_v1_label_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_v1_app_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*App); i {
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
		file_v1_app_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*App_AWSRole); i {
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
			RawDescriptor: file_v1_app_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_v1_app_proto_goTypes,
		DependencyIndexes: file_v1_app_proto_depIdxs,
		MessageInfos:      file_v1_app_proto_msgTypes,
	}.Build()
	File_v1_app_proto = out.File
	file_v1_app_proto_rawDesc = nil
	file_v1_app_proto_goTypes = nil
	file_v1_app_proto_depIdxs = nil
}
