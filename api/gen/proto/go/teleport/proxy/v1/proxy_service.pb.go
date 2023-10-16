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
// source: teleport/proxy/v1/proxy_service.proto

package proxyv1

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

// Request for ProxySSH
//
// In order for proxying to begin the client must send a request with the
// TargetHost populated. Creating the stream doesn't actually open the SSH connection.
// Any attempts to exchange frames prior to the client sending a TargetHost message will
// result in the stream being terminated.
type ProxySSHRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Contains the information required to dial the target.
	// Must be populated on the initial request so that SSH connection can be established.
	DialTarget *TargetHost `protobuf:"bytes,1,opt,name=dial_target,json=dialTarget,proto3" json:"dial_target,omitempty"`
	// Payload from SSH/SSH Agent Protocols
	//
	// Types that are assignable to Frame:
	//
	//	*ProxySSHRequest_Ssh
	//	*ProxySSHRequest_Agent
	Frame isProxySSHRequest_Frame `protobuf_oneof:"frame"`
}

func (x *ProxySSHRequest) Reset() {
	*x = ProxySSHRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_proxy_v1_proxy_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProxySSHRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProxySSHRequest) ProtoMessage() {}

func (x *ProxySSHRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_proxy_v1_proxy_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProxySSHRequest.ProtoReflect.Descriptor instead.
func (*ProxySSHRequest) Descriptor() ([]byte, []int) {
	return file_teleport_proxy_v1_proxy_service_proto_rawDescGZIP(), []int{0}
}

func (x *ProxySSHRequest) GetDialTarget() *TargetHost {
	if x != nil {
		return x.DialTarget
	}
	return nil
}

func (m *ProxySSHRequest) GetFrame() isProxySSHRequest_Frame {
	if m != nil {
		return m.Frame
	}
	return nil
}

func (x *ProxySSHRequest) GetSsh() *Frame {
	if x, ok := x.GetFrame().(*ProxySSHRequest_Ssh); ok {
		return x.Ssh
	}
	return nil
}

func (x *ProxySSHRequest) GetAgent() *Frame {
	if x, ok := x.GetFrame().(*ProxySSHRequest_Agent); ok {
		return x.Agent
	}
	return nil
}

type isProxySSHRequest_Frame interface {
	isProxySSHRequest_Frame()
}

type ProxySSHRequest_Ssh struct {
	// Raw SSH payload
	Ssh *Frame `protobuf:"bytes,2,opt,name=ssh,proto3,oneof"`
}

type ProxySSHRequest_Agent struct {
	// Raw SSH Agent payload, populated for agent forwarding
	Agent *Frame `protobuf:"bytes,3,opt,name=agent,proto3,oneof"`
}

func (*ProxySSHRequest_Ssh) isProxySSHRequest_Frame() {}

func (*ProxySSHRequest_Agent) isProxySSHRequest_Frame() {}

// Response for ProxySSH
//
// The first response from the server will contain ClusterDetails
// so that clients may get information about a particular cluster
// without needing to call GetClusterDetails first. All subsequent
// response will only contain Frames.
type ProxySSHResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Cluster information returned *ONLY* with the first frame
	Details *ClusterDetails `protobuf:"bytes,1,opt,name=details,proto3" json:"details,omitempty"`
	// Payload from SSH/SSH Agent Protocols
	//
	// Types that are assignable to Frame:
	//
	//	*ProxySSHResponse_Ssh
	//	*ProxySSHResponse_Agent
	Frame isProxySSHResponse_Frame `protobuf_oneof:"frame"`
}

func (x *ProxySSHResponse) Reset() {
	*x = ProxySSHResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_proxy_v1_proxy_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProxySSHResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProxySSHResponse) ProtoMessage() {}

func (x *ProxySSHResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_proxy_v1_proxy_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProxySSHResponse.ProtoReflect.Descriptor instead.
func (*ProxySSHResponse) Descriptor() ([]byte, []int) {
	return file_teleport_proxy_v1_proxy_service_proto_rawDescGZIP(), []int{1}
}

func (x *ProxySSHResponse) GetDetails() *ClusterDetails {
	if x != nil {
		return x.Details
	}
	return nil
}

func (m *ProxySSHResponse) GetFrame() isProxySSHResponse_Frame {
	if m != nil {
		return m.Frame
	}
	return nil
}

func (x *ProxySSHResponse) GetSsh() *Frame {
	if x, ok := x.GetFrame().(*ProxySSHResponse_Ssh); ok {
		return x.Ssh
	}
	return nil
}

func (x *ProxySSHResponse) GetAgent() *Frame {
	if x, ok := x.GetFrame().(*ProxySSHResponse_Agent); ok {
		return x.Agent
	}
	return nil
}

type isProxySSHResponse_Frame interface {
	isProxySSHResponse_Frame()
}

type ProxySSHResponse_Ssh struct {
	// SSH payload
	Ssh *Frame `protobuf:"bytes,2,opt,name=ssh,proto3,oneof"`
}

type ProxySSHResponse_Agent struct {
	// SSH Agent payload, populated for agent forwarding
	Agent *Frame `protobuf:"bytes,3,opt,name=agent,proto3,oneof"`
}

func (*ProxySSHResponse_Ssh) isProxySSHResponse_Frame() {}

func (*ProxySSHResponse_Agent) isProxySSHResponse_Frame() {}

// Request for ProxyCluster
//
// In order for proxying to begin the client must send a request with the
// cluster name populated. Creating the stream doesn't actually open the connection.
// Any attempts to exchange frames prior to the client sending a cluster name will
// result in the stream being terminated. All subsequent messages only need to
// provide a Frame.
type ProxyClusterRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Name of the cluster to connect to. Must
	// be sent first so the connection can be established.
	Cluster string `protobuf:"bytes,1,opt,name=cluster,proto3" json:"cluster,omitempty"`
	// Raw payload
	Frame *Frame `protobuf:"bytes,2,opt,name=frame,proto3" json:"frame,omitempty"`
}

func (x *ProxyClusterRequest) Reset() {
	*x = ProxyClusterRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_proxy_v1_proxy_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProxyClusterRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProxyClusterRequest) ProtoMessage() {}

func (x *ProxyClusterRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_proxy_v1_proxy_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProxyClusterRequest.ProtoReflect.Descriptor instead.
func (*ProxyClusterRequest) Descriptor() ([]byte, []int) {
	return file_teleport_proxy_v1_proxy_service_proto_rawDescGZIP(), []int{2}
}

func (x *ProxyClusterRequest) GetCluster() string {
	if x != nil {
		return x.Cluster
	}
	return ""
}

func (x *ProxyClusterRequest) GetFrame() *Frame {
	if x != nil {
		return x.Frame
	}
	return nil
}

// Response for ProxyCluster
type ProxyClusterResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Raw payload
	Frame *Frame `protobuf:"bytes,1,opt,name=frame,proto3" json:"frame,omitempty"`
}

func (x *ProxyClusterResponse) Reset() {
	*x = ProxyClusterResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_proxy_v1_proxy_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProxyClusterResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProxyClusterResponse) ProtoMessage() {}

func (x *ProxyClusterResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_proxy_v1_proxy_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProxyClusterResponse.ProtoReflect.Descriptor instead.
func (*ProxyClusterResponse) Descriptor() ([]byte, []int) {
	return file_teleport_proxy_v1_proxy_service_proto_rawDescGZIP(), []int{3}
}

func (x *ProxyClusterResponse) GetFrame() *Frame {
	if x != nil {
		return x.Frame
	}
	return nil
}

// Encapsulates protocol specific payloads
type Frame struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The raw packet of data
	Payload []byte `protobuf:"bytes,1,opt,name=payload,proto3" json:"payload,omitempty"`
}

func (x *Frame) Reset() {
	*x = Frame{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_proxy_v1_proxy_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Frame) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Frame) ProtoMessage() {}

func (x *Frame) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_proxy_v1_proxy_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Frame.ProtoReflect.Descriptor instead.
func (*Frame) Descriptor() ([]byte, []int) {
	return file_teleport_proxy_v1_proxy_service_proto_rawDescGZIP(), []int{4}
}

func (x *Frame) GetPayload() []byte {
	if x != nil {
		return x.Payload
	}
	return nil
}

// TargetHost indicates which server the connection is for
type TargetHost struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The hostname/ip/uuid:port of the remote host.
	HostPort string `protobuf:"bytes,1,opt,name=host_port,json=hostPort,proto3" json:"host_port,omitempty"`
	// The cluster the server is a member of
	Cluster string `protobuf:"bytes,2,opt,name=cluster,proto3" json:"cluster,omitempty"`
}

func (x *TargetHost) Reset() {
	*x = TargetHost{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_proxy_v1_proxy_service_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TargetHost) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TargetHost) ProtoMessage() {}

func (x *TargetHost) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_proxy_v1_proxy_service_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TargetHost.ProtoReflect.Descriptor instead.
func (*TargetHost) Descriptor() ([]byte, []int) {
	return file_teleport_proxy_v1_proxy_service_proto_rawDescGZIP(), []int{5}
}

func (x *TargetHost) GetHostPort() string {
	if x != nil {
		return x.HostPort
	}
	return ""
}

func (x *TargetHost) GetCluster() string {
	if x != nil {
		return x.Cluster
	}
	return ""
}

// Request for GetClusterDetails.
type GetClusterDetailsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetClusterDetailsRequest) Reset() {
	*x = GetClusterDetailsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_proxy_v1_proxy_service_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetClusterDetailsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetClusterDetailsRequest) ProtoMessage() {}

func (x *GetClusterDetailsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_proxy_v1_proxy_service_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetClusterDetailsRequest.ProtoReflect.Descriptor instead.
func (*GetClusterDetailsRequest) Descriptor() ([]byte, []int) {
	return file_teleport_proxy_v1_proxy_service_proto_rawDescGZIP(), []int{6}
}

// Response for GetClusterDetails.
type GetClusterDetailsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Cluster configuration details
	Details *ClusterDetails `protobuf:"bytes,1,opt,name=details,proto3" json:"details,omitempty"`
}

func (x *GetClusterDetailsResponse) Reset() {
	*x = GetClusterDetailsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_proxy_v1_proxy_service_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetClusterDetailsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetClusterDetailsResponse) ProtoMessage() {}

func (x *GetClusterDetailsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_proxy_v1_proxy_service_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetClusterDetailsResponse.ProtoReflect.Descriptor instead.
func (*GetClusterDetailsResponse) Descriptor() ([]byte, []int) {
	return file_teleport_proxy_v1_proxy_service_proto_rawDescGZIP(), []int{7}
}

func (x *GetClusterDetailsResponse) GetDetails() *ClusterDetails {
	if x != nil {
		return x.Details
	}
	return nil
}

// ClusterDetails contains cluster configuration information
type ClusterDetails struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// If the cluster is running in FIPS mode
	FipsEnabled bool `protobuf:"varint,1,opt,name=fips_enabled,json=fipsEnabled,proto3" json:"fips_enabled,omitempty"`
}

func (x *ClusterDetails) Reset() {
	*x = ClusterDetails{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_proxy_v1_proxy_service_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClusterDetails) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClusterDetails) ProtoMessage() {}

func (x *ClusterDetails) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_proxy_v1_proxy_service_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClusterDetails.ProtoReflect.Descriptor instead.
func (*ClusterDetails) Descriptor() ([]byte, []int) {
	return file_teleport_proxy_v1_proxy_service_proto_rawDescGZIP(), []int{8}
}

func (x *ClusterDetails) GetFipsEnabled() bool {
	if x != nil {
		return x.FipsEnabled
	}
	return false
}

var File_teleport_proxy_v1_proxy_service_proto protoreflect.FileDescriptor

var file_teleport_proxy_v1_proxy_service_proto_rawDesc = []byte{
	0x0a, 0x25, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x70, 0x72, 0x6f, 0x78, 0x79,
	0x2f, 0x76, 0x31, 0x2f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x11, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x22, 0xba, 0x01, 0x0a, 0x0f, 0x50,
	0x72, 0x6f, 0x78, 0x79, 0x53, 0x53, 0x48, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x3e,
	0x0a, 0x0b, 0x64, 0x69, 0x61, 0x6c, 0x5f, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70,
	0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x48, 0x6f,
	0x73, 0x74, 0x52, 0x0a, 0x64, 0x69, 0x61, 0x6c, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x12, 0x2c,
	0x0a, 0x03, 0x73, 0x73, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x74, 0x65,
	0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e,
	0x46, 0x72, 0x61, 0x6d, 0x65, 0x48, 0x00, 0x52, 0x03, 0x73, 0x73, 0x68, 0x12, 0x30, 0x0a, 0x05,
	0x61, 0x67, 0x65, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x74, 0x65,
	0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e,
	0x46, 0x72, 0x61, 0x6d, 0x65, 0x48, 0x00, 0x52, 0x05, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x42, 0x07,
	0x0a, 0x05, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x22, 0xb8, 0x01, 0x0a, 0x10, 0x50, 0x72, 0x6f, 0x78,
	0x79, 0x53, 0x53, 0x48, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3b, 0x0a, 0x07,
	0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x21, 0x2e,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76,
	0x31, 0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73,
	0x52, 0x07, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x12, 0x2c, 0x0a, 0x03, 0x73, 0x73, 0x68,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x46, 0x72, 0x61, 0x6d, 0x65,
	0x48, 0x00, 0x52, 0x03, 0x73, 0x73, 0x68, 0x12, 0x30, 0x0a, 0x05, 0x61, 0x67, 0x65, 0x6e, 0x74,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x46, 0x72, 0x61, 0x6d, 0x65,
	0x48, 0x00, 0x52, 0x05, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x42, 0x07, 0x0a, 0x05, 0x66, 0x72, 0x61,
	0x6d, 0x65, 0x22, 0x5f, 0x0a, 0x13, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x43, 0x6c, 0x75, 0x73, 0x74,
	0x65, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x6c, 0x75,
	0x73, 0x74, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x6c, 0x75, 0x73,
	0x74, 0x65, 0x72, 0x12, 0x2e, 0x0a, 0x05, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x18, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x72,
	0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x46, 0x72, 0x61, 0x6d, 0x65, 0x52, 0x05, 0x66, 0x72,
	0x61, 0x6d, 0x65, 0x22, 0x46, 0x0a, 0x14, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x43, 0x6c, 0x75, 0x73,
	0x74, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2e, 0x0a, 0x05, 0x66,
	0x72, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x46,
	0x72, 0x61, 0x6d, 0x65, 0x52, 0x05, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x22, 0x21, 0x0a, 0x05, 0x46,
	0x72, 0x61, 0x6d, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x22, 0x43,
	0x0a, 0x0a, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x48, 0x6f, 0x73, 0x74, 0x12, 0x1b, 0x0a, 0x09,
	0x68, 0x6f, 0x73, 0x74, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x08, 0x68, 0x6f, 0x73, 0x74, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x6c, 0x75,
	0x73, 0x74, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x6c, 0x75, 0x73,
	0x74, 0x65, 0x72, 0x22, 0x1a, 0x0a, 0x18, 0x47, 0x65, 0x74, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65,
	0x72, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22,
	0x58, 0x0a, 0x19, 0x47, 0x65, 0x74, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x44, 0x65, 0x74,
	0x61, 0x69, 0x6c, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3b, 0x0a, 0x07,
	0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x21, 0x2e,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76,
	0x31, 0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73,
	0x52, 0x07, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x22, 0x33, 0x0a, 0x0e, 0x43, 0x6c, 0x75,
	0x73, 0x74, 0x65, 0x72, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x12, 0x21, 0x0a, 0x0c, 0x66,
	0x69, 0x70, 0x73, 0x5f, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x0b, 0x66, 0x69, 0x70, 0x73, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x32, 0xbc,
	0x02, 0x0a, 0x0c, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12,
	0x6e, 0x0a, 0x11, 0x47, 0x65, 0x74, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x44, 0x65, 0x74,
	0x61, 0x69, 0x6c, 0x73, 0x12, 0x2b, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e,
	0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x6c, 0x75, 0x73,
	0x74, 0x65, 0x72, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x2c, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f,
	0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72,
	0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x57, 0x0a, 0x08, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x53, 0x53, 0x48, 0x12, 0x22, 0x2e, 0x74, 0x65,
	0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e,
	0x50, 0x72, 0x6f, 0x78, 0x79, 0x53, 0x53, 0x48, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x23, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79,
	0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x53, 0x53, 0x48, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x28, 0x01, 0x30, 0x01, 0x12, 0x63, 0x0a, 0x0c, 0x50, 0x72, 0x6f, 0x78,
	0x79, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x12, 0x26, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72, 0x6f,
	0x78, 0x79, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x27, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x78,
	0x79, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65,
	0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x28, 0x01, 0x30, 0x01, 0x42, 0x4e, 0x5a,
	0x4c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76,
	0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2f, 0x67, 0x6f, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x70, 0x72, 0x6f,
	0x78, 0x79, 0x2f, 0x76, 0x31, 0x3b, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x76, 0x31, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_proxy_v1_proxy_service_proto_rawDescOnce sync.Once
	file_teleport_proxy_v1_proxy_service_proto_rawDescData = file_teleport_proxy_v1_proxy_service_proto_rawDesc
)

func file_teleport_proxy_v1_proxy_service_proto_rawDescGZIP() []byte {
	file_teleport_proxy_v1_proxy_service_proto_rawDescOnce.Do(func() {
		file_teleport_proxy_v1_proxy_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_proxy_v1_proxy_service_proto_rawDescData)
	})
	return file_teleport_proxy_v1_proxy_service_proto_rawDescData
}

var file_teleport_proxy_v1_proxy_service_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_teleport_proxy_v1_proxy_service_proto_goTypes = []interface{}{
	(*ProxySSHRequest)(nil),           // 0: teleport.proxy.v1.ProxySSHRequest
	(*ProxySSHResponse)(nil),          // 1: teleport.proxy.v1.ProxySSHResponse
	(*ProxyClusterRequest)(nil),       // 2: teleport.proxy.v1.ProxyClusterRequest
	(*ProxyClusterResponse)(nil),      // 3: teleport.proxy.v1.ProxyClusterResponse
	(*Frame)(nil),                     // 4: teleport.proxy.v1.Frame
	(*TargetHost)(nil),                // 5: teleport.proxy.v1.TargetHost
	(*GetClusterDetailsRequest)(nil),  // 6: teleport.proxy.v1.GetClusterDetailsRequest
	(*GetClusterDetailsResponse)(nil), // 7: teleport.proxy.v1.GetClusterDetailsResponse
	(*ClusterDetails)(nil),            // 8: teleport.proxy.v1.ClusterDetails
}
var file_teleport_proxy_v1_proxy_service_proto_depIdxs = []int32{
	5,  // 0: teleport.proxy.v1.ProxySSHRequest.dial_target:type_name -> teleport.proxy.v1.TargetHost
	4,  // 1: teleport.proxy.v1.ProxySSHRequest.ssh:type_name -> teleport.proxy.v1.Frame
	4,  // 2: teleport.proxy.v1.ProxySSHRequest.agent:type_name -> teleport.proxy.v1.Frame
	8,  // 3: teleport.proxy.v1.ProxySSHResponse.details:type_name -> teleport.proxy.v1.ClusterDetails
	4,  // 4: teleport.proxy.v1.ProxySSHResponse.ssh:type_name -> teleport.proxy.v1.Frame
	4,  // 5: teleport.proxy.v1.ProxySSHResponse.agent:type_name -> teleport.proxy.v1.Frame
	4,  // 6: teleport.proxy.v1.ProxyClusterRequest.frame:type_name -> teleport.proxy.v1.Frame
	4,  // 7: teleport.proxy.v1.ProxyClusterResponse.frame:type_name -> teleport.proxy.v1.Frame
	8,  // 8: teleport.proxy.v1.GetClusterDetailsResponse.details:type_name -> teleport.proxy.v1.ClusterDetails
	6,  // 9: teleport.proxy.v1.ProxyService.GetClusterDetails:input_type -> teleport.proxy.v1.GetClusterDetailsRequest
	0,  // 10: teleport.proxy.v1.ProxyService.ProxySSH:input_type -> teleport.proxy.v1.ProxySSHRequest
	2,  // 11: teleport.proxy.v1.ProxyService.ProxyCluster:input_type -> teleport.proxy.v1.ProxyClusterRequest
	7,  // 12: teleport.proxy.v1.ProxyService.GetClusterDetails:output_type -> teleport.proxy.v1.GetClusterDetailsResponse
	1,  // 13: teleport.proxy.v1.ProxyService.ProxySSH:output_type -> teleport.proxy.v1.ProxySSHResponse
	3,  // 14: teleport.proxy.v1.ProxyService.ProxyCluster:output_type -> teleport.proxy.v1.ProxyClusterResponse
	12, // [12:15] is the sub-list for method output_type
	9,  // [9:12] is the sub-list for method input_type
	9,  // [9:9] is the sub-list for extension type_name
	9,  // [9:9] is the sub-list for extension extendee
	0,  // [0:9] is the sub-list for field type_name
}

func init() { file_teleport_proxy_v1_proxy_service_proto_init() }
func file_teleport_proxy_v1_proxy_service_proto_init() {
	if File_teleport_proxy_v1_proxy_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleport_proxy_v1_proxy_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProxySSHRequest); i {
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
		file_teleport_proxy_v1_proxy_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProxySSHResponse); i {
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
		file_teleport_proxy_v1_proxy_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProxyClusterRequest); i {
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
		file_teleport_proxy_v1_proxy_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProxyClusterResponse); i {
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
		file_teleport_proxy_v1_proxy_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Frame); i {
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
		file_teleport_proxy_v1_proxy_service_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TargetHost); i {
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
		file_teleport_proxy_v1_proxy_service_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetClusterDetailsRequest); i {
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
		file_teleport_proxy_v1_proxy_service_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetClusterDetailsResponse); i {
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
		file_teleport_proxy_v1_proxy_service_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ClusterDetails); i {
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
	file_teleport_proxy_v1_proxy_service_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*ProxySSHRequest_Ssh)(nil),
		(*ProxySSHRequest_Agent)(nil),
	}
	file_teleport_proxy_v1_proxy_service_proto_msgTypes[1].OneofWrappers = []interface{}{
		(*ProxySSHResponse_Ssh)(nil),
		(*ProxySSHResponse_Agent)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_teleport_proxy_v1_proxy_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_teleport_proxy_v1_proxy_service_proto_goTypes,
		DependencyIndexes: file_teleport_proxy_v1_proxy_service_proto_depIdxs,
		MessageInfos:      file_teleport_proxy_v1_proxy_service_proto_msgTypes,
	}.Build()
	File_teleport_proxy_v1_proxy_service_proto = out.File
	file_teleport_proxy_v1_proxy_service_proto_rawDesc = nil
	file_teleport_proxy_v1_proxy_service_proto_goTypes = nil
	file_teleport_proxy_v1_proxy_service_proto_depIdxs = nil
}
