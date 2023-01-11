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
// 	protoc-gen-go v1.28.1
// 	protoc        (unknown)
// source: teleterm/v1/usage_events.proto

package v1

import (
	v1alpha "github.com/gravitational/teleport/lib/prehog/gen/proto/go/prehog/v1alpha"
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

type ReportUsageEventRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AuthClusterId string                             `protobuf:"bytes,1,opt,name=auth_cluster_id,json=authClusterId,proto3" json:"auth_cluster_id,omitempty"`
	PrehogReq     *v1alpha.SubmitConnectEventRequest `protobuf:"bytes,2,opt,name=prehog_req,json=prehogReq,proto3" json:"prehog_req,omitempty"`
}

func (x *ReportUsageEventRequest) Reset() {
	*x = ReportUsageEventRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleterm_v1_usage_events_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReportUsageEventRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReportUsageEventRequest) ProtoMessage() {}

func (x *ReportUsageEventRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleterm_v1_usage_events_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReportUsageEventRequest.ProtoReflect.Descriptor instead.
func (*ReportUsageEventRequest) Descriptor() ([]byte, []int) {
	return file_teleterm_v1_usage_events_proto_rawDescGZIP(), []int{0}
}

func (x *ReportUsageEventRequest) GetAuthClusterId() string {
	if x != nil {
		return x.AuthClusterId
	}
	return ""
}

func (x *ReportUsageEventRequest) GetPrehogReq() *v1alpha.SubmitConnectEventRequest {
	if x != nil {
		return x.PrehogReq
	}
	return nil
}

var File_teleterm_v1_usage_events_proto protoreflect.FileDescriptor

var file_teleterm_v1_usage_events_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x74, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x72, 0x6d, 0x2f, 0x76, 0x31, 0x2f, 0x75, 0x73,
	0x61, 0x67, 0x65, 0x5f, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x0b, 0x74, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x72, 0x6d, 0x2e, 0x76, 0x31, 0x1a, 0x1c, 0x70,
	0x72, 0x65, 0x68, 0x6f, 0x67, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x63, 0x6f,
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x8b, 0x01, 0x0a, 0x17,
	0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x55, 0x73, 0x61, 0x67, 0x65, 0x45, 0x76, 0x65, 0x6e, 0x74,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x26, 0x0a, 0x0f, 0x61, 0x75, 0x74, 0x68, 0x5f,
	0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0d, 0x61, 0x75, 0x74, 0x68, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x49, 0x64, 0x12,
	0x48, 0x0a, 0x0a, 0x70, 0x72, 0x65, 0x68, 0x6f, 0x67, 0x5f, 0x72, 0x65, 0x71, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x29, 0x2e, 0x70, 0x72, 0x65, 0x68, 0x6f, 0x67, 0x2e, 0x76, 0x31, 0x61,
	0x6c, 0x70, 0x68, 0x61, 0x2e, 0x53, 0x75, 0x62, 0x6d, 0x69, 0x74, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
	0x63, 0x74, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x09,
	0x70, 0x72, 0x65, 0x68, 0x6f, 0x67, 0x52, 0x65, 0x71, 0x42, 0x4d, 0x5a, 0x4b, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6c,
	0x69, 0x62, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x72, 0x6d, 0x2f, 0x61, 0x70, 0x69, 0x2f,
	0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74, 0x65, 0x6c,
	0x65, 0x74, 0x65, 0x72, 0x6d, 0x2f, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleterm_v1_usage_events_proto_rawDescOnce sync.Once
	file_teleterm_v1_usage_events_proto_rawDescData = file_teleterm_v1_usage_events_proto_rawDesc
)

func file_teleterm_v1_usage_events_proto_rawDescGZIP() []byte {
	file_teleterm_v1_usage_events_proto_rawDescOnce.Do(func() {
		file_teleterm_v1_usage_events_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleterm_v1_usage_events_proto_rawDescData)
	})
	return file_teleterm_v1_usage_events_proto_rawDescData
}

var file_teleterm_v1_usage_events_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_teleterm_v1_usage_events_proto_goTypes = []interface{}{
	(*ReportUsageEventRequest)(nil),           // 0: teleterm.v1.ReportUsageEventRequest
	(*v1alpha.SubmitConnectEventRequest)(nil), // 1: prehog.v1alpha.SubmitConnectEventRequest
}
var file_teleterm_v1_usage_events_proto_depIdxs = []int32{
	1, // 0: teleterm.v1.ReportUsageEventRequest.prehog_req:type_name -> prehog.v1alpha.SubmitConnectEventRequest
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_teleterm_v1_usage_events_proto_init() }
func file_teleterm_v1_usage_events_proto_init() {
	if File_teleterm_v1_usage_events_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleterm_v1_usage_events_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReportUsageEventRequest); i {
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
			RawDescriptor: file_teleterm_v1_usage_events_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleterm_v1_usage_events_proto_goTypes,
		DependencyIndexes: file_teleterm_v1_usage_events_proto_depIdxs,
		MessageInfos:      file_teleterm_v1_usage_events_proto_msgTypes,
	}.Build()
	File_teleterm_v1_usage_events_proto = out.File
	file_teleterm_v1_usage_events_proto_rawDesc = nil
	file_teleterm_v1_usage_events_proto_goTypes = nil
	file_teleterm_v1_usage_events_proto_depIdxs = nil
}
