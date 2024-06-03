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
// 	protoc-gen-go v1.34.1
// 	protoc        (unknown)
// source: teleport/machineid/v1/bot.proto

package machineidv1

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

// A Bot is a Teleport identity intended to be used by Machines. The Bot
// resource defines a Bot and configures its properties.
type Bot struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The kind of resource represented.
	Kind string `protobuf:"bytes,1,opt,name=kind,proto3" json:"kind,omitempty"`
	// Differentiates variations of the same kind. All resources should
	// contain one, even if it is never populated.
	SubKind string `protobuf:"bytes,2,opt,name=sub_kind,json=subKind,proto3" json:"sub_kind,omitempty"`
	// The version of the resource being represented.
	Version string `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"`
	// Common metadata that all resources share.
	Metadata *v1.Metadata `protobuf:"bytes,4,opt,name=metadata,proto3" json:"metadata,omitempty"`
	// The configured properties of a Bot.
	Spec *BotSpec `protobuf:"bytes,5,opt,name=spec,proto3" json:"spec,omitempty"`
	// Fields that are set by the server as results of operations. These should
	// not be modified by users.
	Status *BotStatus `protobuf:"bytes,6,opt,name=status,proto3" json:"status,omitempty"`
}

func (x *Bot) Reset() {
	*x = Bot{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_machineid_v1_bot_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Bot) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Bot) ProtoMessage() {}

func (x *Bot) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_machineid_v1_bot_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Bot.ProtoReflect.Descriptor instead.
func (*Bot) Descriptor() ([]byte, []int) {
	return file_teleport_machineid_v1_bot_proto_rawDescGZIP(), []int{0}
}

func (x *Bot) GetKind() string {
	if x != nil {
		return x.Kind
	}
	return ""
}

func (x *Bot) GetSubKind() string {
	if x != nil {
		return x.SubKind
	}
	return ""
}

func (x *Bot) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *Bot) GetMetadata() *v1.Metadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

func (x *Bot) GetSpec() *BotSpec {
	if x != nil {
		return x.Spec
	}
	return nil
}

func (x *Bot) GetStatus() *BotStatus {
	if x != nil {
		return x.Status
	}
	return nil
}

// Trait is an individual trait that will be applied to the bot user.
type Trait struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The name of the trait. This is what allows the trait to be queried in
	// role templates.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// The values associated with the named trait.
	Values []string `protobuf:"bytes,2,rep,name=values,proto3" json:"values,omitempty"`
}

func (x *Trait) Reset() {
	*x = Trait{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_machineid_v1_bot_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Trait) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Trait) ProtoMessage() {}

func (x *Trait) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_machineid_v1_bot_proto_msgTypes[1]
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
	return file_teleport_machineid_v1_bot_proto_rawDescGZIP(), []int{1}
}

func (x *Trait) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Trait) GetValues() []string {
	if x != nil {
		return x.Values
	}
	return nil
}

// The configured properties of a Bot.
type BotSpec struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The roles that the bot should be able to impersonate.
	Roles []string `protobuf:"bytes,1,rep,name=roles,proto3" json:"roles,omitempty"`
	// The traits that will be associated with the bot for the purposes of role
	// templating.
	//
	// Where multiple specified with the same name, these will be merged by the
	// server.
	Traits []*Trait `protobuf:"bytes,2,rep,name=traits,proto3" json:"traits,omitempty"`
}

func (x *BotSpec) Reset() {
	*x = BotSpec{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_machineid_v1_bot_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BotSpec) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BotSpec) ProtoMessage() {}

func (x *BotSpec) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_machineid_v1_bot_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BotSpec.ProtoReflect.Descriptor instead.
func (*BotSpec) Descriptor() ([]byte, []int) {
	return file_teleport_machineid_v1_bot_proto_rawDescGZIP(), []int{2}
}

func (x *BotSpec) GetRoles() []string {
	if x != nil {
		return x.Roles
	}
	return nil
}

func (x *BotSpec) GetTraits() []*Trait {
	if x != nil {
		return x.Traits
	}
	return nil
}

// Fields that are set by the server as results of operations. These should not
// be modified by users.
type BotStatus struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The name of the user associated with the bot.
	UserName string `protobuf:"bytes,1,opt,name=user_name,json=userName,proto3" json:"user_name,omitempty"`
	// The name of the role associated with the bot.
	RoleName string `protobuf:"bytes,3,opt,name=role_name,json=roleName,proto3" json:"role_name,omitempty"`
}

func (x *BotStatus) Reset() {
	*x = BotStatus{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_machineid_v1_bot_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BotStatus) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BotStatus) ProtoMessage() {}

func (x *BotStatus) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_machineid_v1_bot_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BotStatus.ProtoReflect.Descriptor instead.
func (*BotStatus) Descriptor() ([]byte, []int) {
	return file_teleport_machineid_v1_bot_proto_rawDescGZIP(), []int{3}
}

func (x *BotStatus) GetUserName() string {
	if x != nil {
		return x.UserName
	}
	return ""
}

func (x *BotStatus) GetRoleName() string {
	if x != nil {
		return x.RoleName
	}
	return ""
}

var File_teleport_machineid_v1_bot_proto protoreflect.FileDescriptor

var file_teleport_machineid_v1_bot_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6d, 0x61, 0x63, 0x68, 0x69,
	0x6e, 0x65, 0x69, 0x64, 0x2f, 0x76, 0x31, 0x2f, 0x62, 0x6f, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x15, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6d, 0x61, 0x63, 0x68,
	0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e, 0x76, 0x31, 0x1a, 0x21, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x2f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x2f, 0x76, 0x31, 0x2f, 0x6d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xf6, 0x01, 0x0a, 0x03,
	0x42, 0x6f, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x75, 0x62, 0x5f, 0x6b,
	0x69, 0x6e, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x75, 0x62, 0x4b, 0x69,
	0x6e, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x38, 0x0a, 0x08,
	0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c,
	0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
	0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x08, 0x6d, 0x65,
	0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x32, 0x0a, 0x04, 0x73, 0x70, 0x65, 0x63, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e,
	0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e, 0x76, 0x31, 0x2e, 0x42, 0x6f, 0x74,
	0x53, 0x70, 0x65, 0x63, 0x52, 0x04, 0x73, 0x70, 0x65, 0x63, 0x12, 0x38, 0x0a, 0x06, 0x73, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e,
	0x76, 0x31, 0x2e, 0x42, 0x6f, 0x74, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x06, 0x73, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x22, 0x33, 0x0a, 0x05, 0x54, 0x72, 0x61, 0x69, 0x74, 0x12, 0x12, 0x0a,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x16, 0x0a, 0x06, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28,
	0x09, 0x52, 0x06, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x22, 0x55, 0x0a, 0x07, 0x42, 0x6f, 0x74,
	0x53, 0x70, 0x65, 0x63, 0x12, 0x14, 0x0a, 0x05, 0x72, 0x6f, 0x6c, 0x65, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x09, 0x52, 0x05, 0x72, 0x6f, 0x6c, 0x65, 0x73, 0x12, 0x34, 0x0a, 0x06, 0x74, 0x72,
	0x61, 0x69, 0x74, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e,
	0x76, 0x31, 0x2e, 0x54, 0x72, 0x61, 0x69, 0x74, 0x52, 0x06, 0x74, 0x72, 0x61, 0x69, 0x74, 0x73,
	0x22, 0x56, 0x0a, 0x09, 0x42, 0x6f, 0x74, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x1b, 0x0a,
	0x09, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x72, 0x6f,
	0x6c, 0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x72,
	0x6f, 0x6c, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x4a, 0x04, 0x08, 0x02, 0x10, 0x03, 0x52, 0x09, 0x72,
	0x6f, 0x6c, 0x65, 0x5f, 0x72, 0x6f, 0x6c, 0x65, 0x42, 0x56, 0x5a, 0x54, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70,
	0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74,
	0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x69,
	0x64, 0x2f, 0x76, 0x31, 0x3b, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x69, 0x64, 0x76, 0x31,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_machineid_v1_bot_proto_rawDescOnce sync.Once
	file_teleport_machineid_v1_bot_proto_rawDescData = file_teleport_machineid_v1_bot_proto_rawDesc
)

func file_teleport_machineid_v1_bot_proto_rawDescGZIP() []byte {
	file_teleport_machineid_v1_bot_proto_rawDescOnce.Do(func() {
		file_teleport_machineid_v1_bot_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_machineid_v1_bot_proto_rawDescData)
	})
	return file_teleport_machineid_v1_bot_proto_rawDescData
}

var file_teleport_machineid_v1_bot_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_teleport_machineid_v1_bot_proto_goTypes = []interface{}{
	(*Bot)(nil),         // 0: teleport.machineid.v1.Bot
	(*Trait)(nil),       // 1: teleport.machineid.v1.Trait
	(*BotSpec)(nil),     // 2: teleport.machineid.v1.BotSpec
	(*BotStatus)(nil),   // 3: teleport.machineid.v1.BotStatus
	(*v1.Metadata)(nil), // 4: teleport.header.v1.Metadata
}
var file_teleport_machineid_v1_bot_proto_depIdxs = []int32{
	4, // 0: teleport.machineid.v1.Bot.metadata:type_name -> teleport.header.v1.Metadata
	2, // 1: teleport.machineid.v1.Bot.spec:type_name -> teleport.machineid.v1.BotSpec
	3, // 2: teleport.machineid.v1.Bot.status:type_name -> teleport.machineid.v1.BotStatus
	1, // 3: teleport.machineid.v1.BotSpec.traits:type_name -> teleport.machineid.v1.Trait
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_teleport_machineid_v1_bot_proto_init() }
func file_teleport_machineid_v1_bot_proto_init() {
	if File_teleport_machineid_v1_bot_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleport_machineid_v1_bot_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Bot); i {
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
		file_teleport_machineid_v1_bot_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
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
		file_teleport_machineid_v1_bot_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BotSpec); i {
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
		file_teleport_machineid_v1_bot_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BotStatus); i {
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
			RawDescriptor: file_teleport_machineid_v1_bot_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_machineid_v1_bot_proto_goTypes,
		DependencyIndexes: file_teleport_machineid_v1_bot_proto_depIdxs,
		MessageInfos:      file_teleport_machineid_v1_bot_proto_msgTypes,
	}.Build()
	File_teleport_machineid_v1_bot_proto = out.File
	file_teleport_machineid_v1_bot_proto_rawDesc = nil
	file_teleport_machineid_v1_bot_proto_goTypes = nil
	file_teleport_machineid_v1_bot_proto_depIdxs = nil
}
