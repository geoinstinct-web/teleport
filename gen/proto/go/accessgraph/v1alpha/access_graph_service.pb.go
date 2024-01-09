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
// source: accessgraph/v1alpha/access_graph_service.proto

package accessgraphv1alpha

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

// QueryRequest is a request to query the access graph.
type QueryRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// query is a SQL query.
	Query string `protobuf:"bytes,1,opt,name=query,proto3" json:"query,omitempty"`
}

func (x *QueryRequest) Reset() {
	*x = QueryRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryRequest) ProtoMessage() {}

func (x *QueryRequest) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryRequest.ProtoReflect.Descriptor instead.
func (*QueryRequest) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_access_graph_service_proto_rawDescGZIP(), []int{0}
}

func (x *QueryRequest) GetQuery() string {
	if x != nil {
		return x.Query
	}
	return ""
}

// QueryResponse is a response to a query.
type QueryResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// nodes is a list of nodes returned by the query. The response may contain only nodes.
	Nodes []*Node `protobuf:"bytes,1,rep,name=nodes,proto3" json:"nodes,omitempty"`
	// edges is a list of edges returned by the query.
	Edges []*Edge `protobuf:"bytes,2,rep,name=edges,proto3" json:"edges,omitempty"`
}

func (x *QueryResponse) Reset() {
	*x = QueryResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryResponse) ProtoMessage() {}

func (x *QueryResponse) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryResponse.ProtoReflect.Descriptor instead.
func (*QueryResponse) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_access_graph_service_proto_rawDescGZIP(), []int{1}
}

func (x *QueryResponse) GetNodes() []*Node {
	if x != nil {
		return x.Nodes
	}
	return nil
}

func (x *QueryResponse) GetEdges() []*Edge {
	if x != nil {
		return x.Edges
	}
	return nil
}

// GetFileRequest is a request to get a file.
type GetFileRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// filepath is a path to the file.
	Filepath string `protobuf:"bytes,1,opt,name=filepath,proto3" json:"filepath,omitempty"`
}

func (x *GetFileRequest) Reset() {
	*x = GetFileRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetFileRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetFileRequest) ProtoMessage() {}

func (x *GetFileRequest) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetFileRequest.ProtoReflect.Descriptor instead.
func (*GetFileRequest) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_access_graph_service_proto_rawDescGZIP(), []int{2}
}

func (x *GetFileRequest) GetFilepath() string {
	if x != nil {
		return x.Filepath
	}
	return ""
}

// GetFileResponse is a response to a file request.
type GetFileResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// data is a raw file content.
	Data []byte `protobuf:"bytes,1,opt,name=data,proto3" json:"data,omitempty"`
}

func (x *GetFileResponse) Reset() {
	*x = GetFileResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetFileResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetFileResponse) ProtoMessage() {}

func (x *GetFileResponse) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetFileResponse.ProtoReflect.Descriptor instead.
func (*GetFileResponse) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_access_graph_service_proto_rawDescGZIP(), []int{3}
}

func (x *GetFileResponse) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

// EventsStreamRequest is a request to send commands to the access graph.
// This command is used to sync the access graph with the Teleport database state.
type EventsStreamRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// operation contains the desired operation
	//
	// Types that are assignable to Operation:
	//
	//	*EventsStreamRequest_Sync
	//	*EventsStreamRequest_Upsert
	//	*EventsStreamRequest_Delete
	//	*EventsStreamRequest_AccessListsMembers
	//	*EventsStreamRequest_ExcludeAccessListMembers
	Operation isEventsStreamRequest_Operation `protobuf_oneof:"operation"`
}

func (x *EventsStreamRequest) Reset() {
	*x = EventsStreamRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EventsStreamRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EventsStreamRequest) ProtoMessage() {}

func (x *EventsStreamRequest) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EventsStreamRequest.ProtoReflect.Descriptor instead.
func (*EventsStreamRequest) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_access_graph_service_proto_rawDescGZIP(), []int{4}
}

func (m *EventsStreamRequest) GetOperation() isEventsStreamRequest_Operation {
	if m != nil {
		return m.Operation
	}
	return nil
}

func (x *EventsStreamRequest) GetSync() *SyncOperation {
	if x, ok := x.GetOperation().(*EventsStreamRequest_Sync); ok {
		return x.Sync
	}
	return nil
}

func (x *EventsStreamRequest) GetUpsert() *ResourceList {
	if x, ok := x.GetOperation().(*EventsStreamRequest_Upsert); ok {
		return x.Upsert
	}
	return nil
}

func (x *EventsStreamRequest) GetDelete() *ResourceHeaderList {
	if x, ok := x.GetOperation().(*EventsStreamRequest_Delete); ok {
		return x.Delete
	}
	return nil
}

func (x *EventsStreamRequest) GetAccessListsMembers() *AccessListsMembers {
	if x, ok := x.GetOperation().(*EventsStreamRequest_AccessListsMembers); ok {
		return x.AccessListsMembers
	}
	return nil
}

func (x *EventsStreamRequest) GetExcludeAccessListMembers() *ExcludeAccessListsMembers {
	if x, ok := x.GetOperation().(*EventsStreamRequest_ExcludeAccessListMembers); ok {
		return x.ExcludeAccessListMembers
	}
	return nil
}

type isEventsStreamRequest_Operation interface {
	isEventsStreamRequest_Operation()
}

type EventsStreamRequest_Sync struct {
	// sync is a command to sync the access graph with the Teleport database state.
	// it's issued once Teleport finishes syncing all resources with the database.
	Sync *SyncOperation `protobuf:"bytes,1,opt,name=sync,proto3,oneof"`
}

type EventsStreamRequest_Upsert struct {
	// upsert is a command to put a resource into the access graph or update it.
	Upsert *ResourceList `protobuf:"bytes,2,opt,name=upsert,proto3,oneof"`
}

type EventsStreamRequest_Delete struct {
	// delete is a command to delete a resource from the access graph when it's deleted from Teleport.
	Delete *ResourceHeaderList `protobuf:"bytes,3,opt,name=delete,proto3,oneof"`
}

type EventsStreamRequest_AccessListsMembers struct {
	// access_lists_members is a command to upsert access lists members.
	// It's issued when a user is added to an access list or when their membership is updated.
	// It's also issued when a user membership expires but the user remains in the access list.
	// In that case, the state of the user reflects the expiration reason.
	AccessListsMembers *AccessListsMembers `protobuf:"bytes,4,opt,name=access_lists_members,json=accessListsMembers,proto3,oneof"`
}

type EventsStreamRequest_ExcludeAccessListMembers struct {
	// exclude_access_list_members is a command to exclude access lists members
	// when they are manually removed from the access list.
	// If their membership remains but it's expired, they are not excluded
	// from the access list but they don't receive any access - in that case,
	// the request is [access_lists_members].
	ExcludeAccessListMembers *ExcludeAccessListsMembers `protobuf:"bytes,5,opt,name=exclude_access_list_members,json=excludeAccessListMembers,proto3,oneof"`
}

func (*EventsStreamRequest_Sync) isEventsStreamRequest_Operation() {}

func (*EventsStreamRequest_Upsert) isEventsStreamRequest_Operation() {}

func (*EventsStreamRequest_Delete) isEventsStreamRequest_Operation() {}

func (*EventsStreamRequest_AccessListsMembers) isEventsStreamRequest_Operation() {}

func (*EventsStreamRequest_ExcludeAccessListMembers) isEventsStreamRequest_Operation() {}

// SyncOperation is a command that Teleport sends to the access graph service
// at the end of the sync process.
type SyncOperation struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *SyncOperation) Reset() {
	*x = SyncOperation{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SyncOperation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SyncOperation) ProtoMessage() {}

func (x *SyncOperation) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SyncOperation.ProtoReflect.Descriptor instead.
func (*SyncOperation) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_access_graph_service_proto_rawDescGZIP(), []int{5}
}

// EventsStreamResponse is the response from EventsStream.
type EventsStreamResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *EventsStreamResponse) Reset() {
	*x = EventsStreamResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EventsStreamResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EventsStreamResponse) ProtoMessage() {}

func (x *EventsStreamResponse) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EventsStreamResponse.ProtoReflect.Descriptor instead.
func (*EventsStreamResponse) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_access_graph_service_proto_rawDescGZIP(), []int{6}
}

// RegisterRequest is the request for Register.
type RegisterRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	HostCaPem []byte `protobuf:"bytes,1,opt,name=host_ca_pem,json=hostCaPem,proto3" json:"host_ca_pem,omitempty"`
	// ClusterName is the self-submitted name of the Teleport cluster (usually a FQDN).
	// This may not uniquely identify the cluster, and is only used to make identification easier for debugging purposes.
	ClusterName string `protobuf:"bytes,2,opt,name=cluster_name,json=clusterName,proto3" json:"cluster_name,omitempty"`
}

func (x *RegisterRequest) Reset() {
	*x = RegisterRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RegisterRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RegisterRequest) ProtoMessage() {}

func (x *RegisterRequest) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RegisterRequest.ProtoReflect.Descriptor instead.
func (*RegisterRequest) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_access_graph_service_proto_rawDescGZIP(), []int{7}
}

func (x *RegisterRequest) GetHostCaPem() []byte {
	if x != nil {
		return x.HostCaPem
	}
	return nil
}

func (x *RegisterRequest) GetClusterName() string {
	if x != nil {
		return x.ClusterName
	}
	return ""
}

// RegisterResponse is the response for Register.
type RegisterResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *RegisterResponse) Reset() {
	*x = RegisterResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RegisterResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RegisterResponse) ProtoMessage() {}

func (x *RegisterResponse) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RegisterResponse.ProtoReflect.Descriptor instead.
func (*RegisterResponse) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_access_graph_service_proto_rawDescGZIP(), []int{8}
}

// ReplaceCAsRequest is the request for ReplaceCAs.
type ReplaceCAsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	HostCaPem [][]byte `protobuf:"bytes,1,rep,name=host_ca_pem,json=hostCaPem,proto3" json:"host_ca_pem,omitempty"`
}

func (x *ReplaceCAsRequest) Reset() {
	*x = ReplaceCAsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReplaceCAsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReplaceCAsRequest) ProtoMessage() {}

func (x *ReplaceCAsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReplaceCAsRequest.ProtoReflect.Descriptor instead.
func (*ReplaceCAsRequest) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_access_graph_service_proto_rawDescGZIP(), []int{9}
}

func (x *ReplaceCAsRequest) GetHostCaPem() [][]byte {
	if x != nil {
		return x.HostCaPem
	}
	return nil
}

// ReplaceCAsResponse is the response for ReplaceCAs.
type ReplaceCAsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *ReplaceCAsResponse) Reset() {
	*x = ReplaceCAsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReplaceCAsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReplaceCAsResponse) ProtoMessage() {}

func (x *ReplaceCAsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReplaceCAsResponse.ProtoReflect.Descriptor instead.
func (*ReplaceCAsResponse) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_access_graph_service_proto_rawDescGZIP(), []int{10}
}

var File_accessgraph_v1alpha_access_graph_service_proto protoreflect.FileDescriptor

var file_accessgraph_v1alpha_access_graph_service_proto_rawDesc = []byte{
	0x0a, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2f, 0x76, 0x31,
	0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x67, 0x72, 0x61,
	0x70, 0x68, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x13, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31,
	0x61, 0x6c, 0x70, 0x68, 0x61, 0x1a, 0x1f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61,
	0x70, 0x68, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x67, 0x72, 0x61, 0x70, 0x68,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x23, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72,
	0x61, 0x70, 0x68, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x72, 0x65, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x24, 0x0a, 0x0c, 0x51,
	0x75, 0x65, 0x72, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x71,
	0x75, 0x65, 0x72, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x71, 0x75, 0x65, 0x72,
	0x79, 0x22, 0x71, 0x0a, 0x0d, 0x51, 0x75, 0x65, 0x72, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x2f, 0x0a, 0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x19, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e,
	0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x52, 0x05, 0x6e, 0x6f,
	0x64, 0x65, 0x73, 0x12, 0x2f, 0x0a, 0x05, 0x65, 0x64, 0x67, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x19, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68,
	0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x45, 0x64, 0x67, 0x65, 0x52, 0x05, 0x65,
	0x64, 0x67, 0x65, 0x73, 0x22, 0x2c, 0x0a, 0x0e, 0x47, 0x65, 0x74, 0x46, 0x69, 0x6c, 0x65, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x66, 0x69, 0x6c, 0x65, 0x70, 0x61,
	0x74, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x66, 0x69, 0x6c, 0x65, 0x70, 0x61,
	0x74, 0x68, 0x22, 0x25, 0x0a, 0x0f, 0x47, 0x65, 0x74, 0x46, 0x69, 0x6c, 0x65, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x22, 0xaa, 0x03, 0x0a, 0x13, 0x45, 0x76,
	0x65, 0x6e, 0x74, 0x73, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x38, 0x0a, 0x04, 0x73, 0x79, 0x6e, 0x63, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x22, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31,
	0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x53, 0x79, 0x6e, 0x63, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x48, 0x00, 0x52, 0x04, 0x73, 0x79, 0x6e, 0x63, 0x12, 0x3b, 0x0a, 0x06, 0x75,
	0x70, 0x73, 0x65, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x61, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68,
	0x61, 0x2e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x48, 0x00,
	0x52, 0x06, 0x75, 0x70, 0x73, 0x65, 0x72, 0x74, 0x12, 0x41, 0x0a, 0x06, 0x64, 0x65, 0x6c, 0x65,
	0x74, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x52,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x4c, 0x69, 0x73,
	0x74, 0x48, 0x00, 0x52, 0x06, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x12, 0x5b, 0x0a, 0x14, 0x61,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x73, 0x5f, 0x6d, 0x65, 0x6d, 0x62,
	0x65, 0x72, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x61, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e,
	0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x73, 0x4d, 0x65, 0x6d, 0x62, 0x65,
	0x72, 0x73, 0x48, 0x00, 0x52, 0x12, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c, 0x69, 0x73, 0x74,
	0x73, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x73, 0x12, 0x6f, 0x0a, 0x1b, 0x65, 0x78, 0x63, 0x6c,
	0x75, 0x64, 0x65, 0x5f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x5f,
	0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2e, 0x2e,
	0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c,
	0x70, 0x68, 0x61, 0x2e, 0x45, 0x78, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x4c, 0x69, 0x73, 0x74, 0x73, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x73, 0x48, 0x00, 0x52,
	0x18, 0x65, 0x78, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c, 0x69,
	0x73, 0x74, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x73, 0x42, 0x0b, 0x0a, 0x09, 0x6f, 0x70, 0x65,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x0f, 0x0a, 0x0d, 0x53, 0x79, 0x6e, 0x63, 0x4f, 0x70,
	0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x16, 0x0a, 0x14, 0x45, 0x76, 0x65, 0x6e, 0x74,
	0x73, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22,
	0x54, 0x0a, 0x0f, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x1e, 0x0a, 0x0b, 0x68, 0x6f, 0x73, 0x74, 0x5f, 0x63, 0x61, 0x5f, 0x70, 0x65,
	0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x68, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x50,
	0x65, 0x6d, 0x12, 0x21, 0x0a, 0x0c, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x5f, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65,
	0x72, 0x4e, 0x61, 0x6d, 0x65, 0x22, 0x12, 0x0a, 0x10, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65,
	0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x33, 0x0a, 0x11, 0x52, 0x65, 0x70,
	0x6c, 0x61, 0x63, 0x65, 0x43, 0x41, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1e,
	0x0a, 0x0b, 0x68, 0x6f, 0x73, 0x74, 0x5f, 0x63, 0x61, 0x5f, 0x70, 0x65, 0x6d, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x0c, 0x52, 0x09, 0x68, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x50, 0x65, 0x6d, 0x22, 0x14,
	0x0a, 0x12, 0x52, 0x65, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x43, 0x41, 0x73, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x32, 0xd9, 0x03, 0x0a, 0x12, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x47,
	0x72, 0x61, 0x70, 0x68, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x4e, 0x0a, 0x05, 0x51,
	0x75, 0x65, 0x72, 0x79, 0x12, 0x21, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61,
	0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x22, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73,
	0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x51, 0x75,
	0x65, 0x72, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x54, 0x0a, 0x07, 0x47,
	0x65, 0x74, 0x46, 0x69, 0x6c, 0x65, 0x12, 0x23, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67,
	0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x47, 0x65, 0x74,
	0x46, 0x69, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x24, 0x2e, 0x61, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68,
	0x61, 0x2e, 0x47, 0x65, 0x74, 0x46, 0x69, 0x6c, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x65, 0x0a, 0x0c, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x53, 0x74, 0x72, 0x65, 0x61,
	0x6d, 0x12, 0x28, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e,
	0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x53, 0x74,
	0x72, 0x65, 0x61, 0x6d, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x29, 0x2e, 0x61, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68,
	0x61, 0x2e, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x28, 0x01, 0x12, 0x57, 0x0a, 0x08, 0x52, 0x65, 0x67, 0x69,
	0x73, 0x74, 0x65, 0x72, 0x12, 0x24, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61,
	0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x52, 0x65, 0x67, 0x69, 0x73,
	0x74, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x25, 0x2e, 0x61, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61,
	0x2e, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x5d, 0x0a, 0x0a, 0x52, 0x65, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x43, 0x41, 0x73, 0x12,
	0x26, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31,
	0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x52, 0x65, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x43, 0x41, 0x73,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x27, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73,
	0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x52, 0x65,
	0x70, 0x6c, 0x61, 0x63, 0x65, 0x43, 0x41, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x42, 0x57, 0x5a, 0x55, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67,
	0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x67, 0x6f, 0x2f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2f, 0x76,
	0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x3b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61,
	0x70, 0x68, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_accessgraph_v1alpha_access_graph_service_proto_rawDescOnce sync.Once
	file_accessgraph_v1alpha_access_graph_service_proto_rawDescData = file_accessgraph_v1alpha_access_graph_service_proto_rawDesc
)

func file_accessgraph_v1alpha_access_graph_service_proto_rawDescGZIP() []byte {
	file_accessgraph_v1alpha_access_graph_service_proto_rawDescOnce.Do(func() {
		file_accessgraph_v1alpha_access_graph_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_accessgraph_v1alpha_access_graph_service_proto_rawDescData)
	})
	return file_accessgraph_v1alpha_access_graph_service_proto_rawDescData
}

var file_accessgraph_v1alpha_access_graph_service_proto_msgTypes = make([]protoimpl.MessageInfo, 11)
var file_accessgraph_v1alpha_access_graph_service_proto_goTypes = []interface{}{
	(*QueryRequest)(nil),              // 0: accessgraph.v1alpha.QueryRequest
	(*QueryResponse)(nil),             // 1: accessgraph.v1alpha.QueryResponse
	(*GetFileRequest)(nil),            // 2: accessgraph.v1alpha.GetFileRequest
	(*GetFileResponse)(nil),           // 3: accessgraph.v1alpha.GetFileResponse
	(*EventsStreamRequest)(nil),       // 4: accessgraph.v1alpha.EventsStreamRequest
	(*SyncOperation)(nil),             // 5: accessgraph.v1alpha.SyncOperation
	(*EventsStreamResponse)(nil),      // 6: accessgraph.v1alpha.EventsStreamResponse
	(*RegisterRequest)(nil),           // 7: accessgraph.v1alpha.RegisterRequest
	(*RegisterResponse)(nil),          // 8: accessgraph.v1alpha.RegisterResponse
	(*ReplaceCAsRequest)(nil),         // 9: accessgraph.v1alpha.ReplaceCAsRequest
	(*ReplaceCAsResponse)(nil),        // 10: accessgraph.v1alpha.ReplaceCAsResponse
	(*Node)(nil),                      // 11: accessgraph.v1alpha.Node
	(*Edge)(nil),                      // 12: accessgraph.v1alpha.Edge
	(*ResourceList)(nil),              // 13: accessgraph.v1alpha.ResourceList
	(*ResourceHeaderList)(nil),        // 14: accessgraph.v1alpha.ResourceHeaderList
	(*AccessListsMembers)(nil),        // 15: accessgraph.v1alpha.AccessListsMembers
	(*ExcludeAccessListsMembers)(nil), // 16: accessgraph.v1alpha.ExcludeAccessListsMembers
}
var file_accessgraph_v1alpha_access_graph_service_proto_depIdxs = []int32{
	11, // 0: accessgraph.v1alpha.QueryResponse.nodes:type_name -> accessgraph.v1alpha.Node
	12, // 1: accessgraph.v1alpha.QueryResponse.edges:type_name -> accessgraph.v1alpha.Edge
	5,  // 2: accessgraph.v1alpha.EventsStreamRequest.sync:type_name -> accessgraph.v1alpha.SyncOperation
	13, // 3: accessgraph.v1alpha.EventsStreamRequest.upsert:type_name -> accessgraph.v1alpha.ResourceList
	14, // 4: accessgraph.v1alpha.EventsStreamRequest.delete:type_name -> accessgraph.v1alpha.ResourceHeaderList
	15, // 5: accessgraph.v1alpha.EventsStreamRequest.access_lists_members:type_name -> accessgraph.v1alpha.AccessListsMembers
	16, // 6: accessgraph.v1alpha.EventsStreamRequest.exclude_access_list_members:type_name -> accessgraph.v1alpha.ExcludeAccessListsMembers
	0,  // 7: accessgraph.v1alpha.AccessGraphService.Query:input_type -> accessgraph.v1alpha.QueryRequest
	2,  // 8: accessgraph.v1alpha.AccessGraphService.GetFile:input_type -> accessgraph.v1alpha.GetFileRequest
	4,  // 9: accessgraph.v1alpha.AccessGraphService.EventsStream:input_type -> accessgraph.v1alpha.EventsStreamRequest
	7,  // 10: accessgraph.v1alpha.AccessGraphService.Register:input_type -> accessgraph.v1alpha.RegisterRequest
	9,  // 11: accessgraph.v1alpha.AccessGraphService.ReplaceCAs:input_type -> accessgraph.v1alpha.ReplaceCAsRequest
	1,  // 12: accessgraph.v1alpha.AccessGraphService.Query:output_type -> accessgraph.v1alpha.QueryResponse
	3,  // 13: accessgraph.v1alpha.AccessGraphService.GetFile:output_type -> accessgraph.v1alpha.GetFileResponse
	6,  // 14: accessgraph.v1alpha.AccessGraphService.EventsStream:output_type -> accessgraph.v1alpha.EventsStreamResponse
	8,  // 15: accessgraph.v1alpha.AccessGraphService.Register:output_type -> accessgraph.v1alpha.RegisterResponse
	10, // 16: accessgraph.v1alpha.AccessGraphService.ReplaceCAs:output_type -> accessgraph.v1alpha.ReplaceCAsResponse
	12, // [12:17] is the sub-list for method output_type
	7,  // [7:12] is the sub-list for method input_type
	7,  // [7:7] is the sub-list for extension type_name
	7,  // [7:7] is the sub-list for extension extendee
	0,  // [0:7] is the sub-list for field type_name
}

func init() { file_accessgraph_v1alpha_access_graph_service_proto_init() }
func file_accessgraph_v1alpha_access_graph_service_proto_init() {
	if File_accessgraph_v1alpha_access_graph_service_proto != nil {
		return
	}
	file_accessgraph_v1alpha_graph_proto_init()
	file_accessgraph_v1alpha_resources_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryRequest); i {
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
		file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryResponse); i {
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
		file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetFileRequest); i {
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
		file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetFileResponse); i {
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
		file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EventsStreamRequest); i {
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
		file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SyncOperation); i {
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
		file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EventsStreamResponse); i {
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
		file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RegisterRequest); i {
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
		file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RegisterResponse); i {
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
		file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReplaceCAsRequest); i {
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
		file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReplaceCAsResponse); i {
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
	file_accessgraph_v1alpha_access_graph_service_proto_msgTypes[4].OneofWrappers = []interface{}{
		(*EventsStreamRequest_Sync)(nil),
		(*EventsStreamRequest_Upsert)(nil),
		(*EventsStreamRequest_Delete)(nil),
		(*EventsStreamRequest_AccessListsMembers)(nil),
		(*EventsStreamRequest_ExcludeAccessListMembers)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_accessgraph_v1alpha_access_graph_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   11,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_accessgraph_v1alpha_access_graph_service_proto_goTypes,
		DependencyIndexes: file_accessgraph_v1alpha_access_graph_service_proto_depIdxs,
		MessageInfos:      file_accessgraph_v1alpha_access_graph_service_proto_msgTypes,
	}.Build()
	File_accessgraph_v1alpha_access_graph_service_proto = out.File
	file_accessgraph_v1alpha_access_graph_service_proto_rawDesc = nil
	file_accessgraph_v1alpha_access_graph_service_proto_goTypes = nil
	file_accessgraph_v1alpha_access_graph_service_proto_depIdxs = nil
}
