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
// source: teleport/lib/teleterm/v1/tshd_events_service.proto

package teletermv1

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

type ReloginRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RootClusterUri string `protobuf:"bytes,1,opt,name=root_cluster_uri,json=rootClusterUri,proto3" json:"root_cluster_uri,omitempty"`
	// Types that are assignable to Reason:
	//
	//	*ReloginRequest_GatewayCertExpired
	Reason isReloginRequest_Reason `protobuf_oneof:"reason"`
}

func (x *ReloginRequest) Reset() {
	*x = ReloginRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReloginRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReloginRequest) ProtoMessage() {}

func (x *ReloginRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReloginRequest.ProtoReflect.Descriptor instead.
func (*ReloginRequest) Descriptor() ([]byte, []int) {
	return file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDescGZIP(), []int{0}
}

func (x *ReloginRequest) GetRootClusterUri() string {
	if x != nil {
		return x.RootClusterUri
	}
	return ""
}

func (m *ReloginRequest) GetReason() isReloginRequest_Reason {
	if m != nil {
		return m.Reason
	}
	return nil
}

func (x *ReloginRequest) GetGatewayCertExpired() *GatewayCertExpired {
	if x, ok := x.GetReason().(*ReloginRequest_GatewayCertExpired); ok {
		return x.GatewayCertExpired
	}
	return nil
}

type isReloginRequest_Reason interface {
	isReloginRequest_Reason()
}

type ReloginRequest_GatewayCertExpired struct {
	GatewayCertExpired *GatewayCertExpired `protobuf:"bytes,2,opt,name=gateway_cert_expired,json=gatewayCertExpired,proto3,oneof"`
}

func (*ReloginRequest_GatewayCertExpired) isReloginRequest_Reason() {}

// GatewayCertExpired is given as the reason when a database client attempts to make a connection
// through the gateway, the gateway middleware notices that the db cert has expired and tries to
// connect to the cluster to reissue the cert, but fails because the user cert has expired as well.
//
// At that point in order to let the connection through, tshd needs the Electron app to refresh the
// user cert by asking the user to log in again.
type GatewayCertExpired struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GatewayUri string `protobuf:"bytes,1,opt,name=gateway_uri,json=gatewayUri,proto3" json:"gateway_uri,omitempty"`
	TargetUri  string `protobuf:"bytes,2,opt,name=target_uri,json=targetUri,proto3" json:"target_uri,omitempty"`
}

func (x *GatewayCertExpired) Reset() {
	*x = GatewayCertExpired{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GatewayCertExpired) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GatewayCertExpired) ProtoMessage() {}

func (x *GatewayCertExpired) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GatewayCertExpired.ProtoReflect.Descriptor instead.
func (*GatewayCertExpired) Descriptor() ([]byte, []int) {
	return file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDescGZIP(), []int{1}
}

func (x *GatewayCertExpired) GetGatewayUri() string {
	if x != nil {
		return x.GatewayUri
	}
	return ""
}

func (x *GatewayCertExpired) GetTargetUri() string {
	if x != nil {
		return x.TargetUri
	}
	return ""
}

type ReloginResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *ReloginResponse) Reset() {
	*x = ReloginResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReloginResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReloginResponse) ProtoMessage() {}

func (x *ReloginResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReloginResponse.ProtoReflect.Descriptor instead.
func (*ReloginResponse) Descriptor() ([]byte, []int) {
	return file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDescGZIP(), []int{2}
}

type SendNotificationRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Subject:
	//
	//	*SendNotificationRequest_CannotProxyGatewayConnection
	Subject isSendNotificationRequest_Subject `protobuf_oneof:"subject"`
}

func (x *SendNotificationRequest) Reset() {
	*x = SendNotificationRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SendNotificationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SendNotificationRequest) ProtoMessage() {}

func (x *SendNotificationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SendNotificationRequest.ProtoReflect.Descriptor instead.
func (*SendNotificationRequest) Descriptor() ([]byte, []int) {
	return file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDescGZIP(), []int{3}
}

func (m *SendNotificationRequest) GetSubject() isSendNotificationRequest_Subject {
	if m != nil {
		return m.Subject
	}
	return nil
}

func (x *SendNotificationRequest) GetCannotProxyGatewayConnection() *CannotProxyGatewayConnection {
	if x, ok := x.GetSubject().(*SendNotificationRequest_CannotProxyGatewayConnection); ok {
		return x.CannotProxyGatewayConnection
	}
	return nil
}

type isSendNotificationRequest_Subject interface {
	isSendNotificationRequest_Subject()
}

type SendNotificationRequest_CannotProxyGatewayConnection struct {
	CannotProxyGatewayConnection *CannotProxyGatewayConnection `protobuf:"bytes,1,opt,name=cannot_proxy_gateway_connection,json=cannotProxyGatewayConnection,proto3,oneof"`
}

func (*SendNotificationRequest_CannotProxyGatewayConnection) isSendNotificationRequest_Subject() {}

// CannotProxyGatewayConnection is the subject when the middleware used by the gateway encounters an
// unrecoverable error and cannot let the connection through. The middleware code is executed within
// a separate goroutine so if the error wasn't passed to the Electron app, it would have been
// visible only in the logs.
type CannotProxyGatewayConnection struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GatewayUri string `protobuf:"bytes,1,opt,name=gateway_uri,json=gatewayUri,proto3" json:"gateway_uri,omitempty"`
	TargetUri  string `protobuf:"bytes,2,opt,name=target_uri,json=targetUri,proto3" json:"target_uri,omitempty"`
	Error      string `protobuf:"bytes,3,opt,name=error,proto3" json:"error,omitempty"`
}

func (x *CannotProxyGatewayConnection) Reset() {
	*x = CannotProxyGatewayConnection{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CannotProxyGatewayConnection) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CannotProxyGatewayConnection) ProtoMessage() {}

func (x *CannotProxyGatewayConnection) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CannotProxyGatewayConnection.ProtoReflect.Descriptor instead.
func (*CannotProxyGatewayConnection) Descriptor() ([]byte, []int) {
	return file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDescGZIP(), []int{4}
}

func (x *CannotProxyGatewayConnection) GetGatewayUri() string {
	if x != nil {
		return x.GatewayUri
	}
	return ""
}

func (x *CannotProxyGatewayConnection) GetTargetUri() string {
	if x != nil {
		return x.TargetUri
	}
	return ""
}

func (x *CannotProxyGatewayConnection) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

type SendNotificationResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *SendNotificationResponse) Reset() {
	*x = SendNotificationResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SendNotificationResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SendNotificationResponse) ProtoMessage() {}

func (x *SendNotificationResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SendNotificationResponse.ProtoReflect.Descriptor instead.
func (*SendNotificationResponse) Descriptor() ([]byte, []int) {
	return file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDescGZIP(), []int{5}
}

type SendPendingHeadlessAuthenticationRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RootClusterUri                 string `protobuf:"bytes,1,opt,name=root_cluster_uri,json=rootClusterUri,proto3" json:"root_cluster_uri,omitempty"`
	HeadlessAuthenticationId       string `protobuf:"bytes,2,opt,name=headless_authentication_id,json=headlessAuthenticationId,proto3" json:"headless_authentication_id,omitempty"`
	HeadlessAuthenticationClientIp string `protobuf:"bytes,3,opt,name=headless_authentication_client_ip,json=headlessAuthenticationClientIp,proto3" json:"headless_authentication_client_ip,omitempty"`
}

func (x *SendPendingHeadlessAuthenticationRequest) Reset() {
	*x = SendPendingHeadlessAuthenticationRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SendPendingHeadlessAuthenticationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SendPendingHeadlessAuthenticationRequest) ProtoMessage() {}

func (x *SendPendingHeadlessAuthenticationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SendPendingHeadlessAuthenticationRequest.ProtoReflect.Descriptor instead.
func (*SendPendingHeadlessAuthenticationRequest) Descriptor() ([]byte, []int) {
	return file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDescGZIP(), []int{6}
}

func (x *SendPendingHeadlessAuthenticationRequest) GetRootClusterUri() string {
	if x != nil {
		return x.RootClusterUri
	}
	return ""
}

func (x *SendPendingHeadlessAuthenticationRequest) GetHeadlessAuthenticationId() string {
	if x != nil {
		return x.HeadlessAuthenticationId
	}
	return ""
}

func (x *SendPendingHeadlessAuthenticationRequest) GetHeadlessAuthenticationClientIp() string {
	if x != nil {
		return x.HeadlessAuthenticationClientIp
	}
	return ""
}

type SendPendingHeadlessAuthenticationResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *SendPendingHeadlessAuthenticationResponse) Reset() {
	*x = SendPendingHeadlessAuthenticationResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SendPendingHeadlessAuthenticationResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SendPendingHeadlessAuthenticationResponse) ProtoMessage() {}

func (x *SendPendingHeadlessAuthenticationResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SendPendingHeadlessAuthenticationResponse.ProtoReflect.Descriptor instead.
func (*SendPendingHeadlessAuthenticationResponse) Descriptor() ([]byte, []int) {
	return file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDescGZIP(), []int{7}
}

type PromptMFARequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RootClusterUri string `protobuf:"bytes,1,opt,name=root_cluster_uri,json=rootClusterUri,proto3" json:"root_cluster_uri,omitempty"`
	Reason         string `protobuf:"bytes,2,opt,name=reason,proto3" json:"reason,omitempty"`
	Totp           bool   `protobuf:"varint,3,opt,name=totp,proto3" json:"totp,omitempty"`
	Webauthn       bool   `protobuf:"varint,4,opt,name=webauthn,proto3" json:"webauthn,omitempty"`
}

func (x *PromptMFARequest) Reset() {
	*x = PromptMFARequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PromptMFARequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PromptMFARequest) ProtoMessage() {}

func (x *PromptMFARequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PromptMFARequest.ProtoReflect.Descriptor instead.
func (*PromptMFARequest) Descriptor() ([]byte, []int) {
	return file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDescGZIP(), []int{8}
}

func (x *PromptMFARequest) GetRootClusterUri() string {
	if x != nil {
		return x.RootClusterUri
	}
	return ""
}

func (x *PromptMFARequest) GetReason() string {
	if x != nil {
		return x.Reason
	}
	return ""
}

func (x *PromptMFARequest) GetTotp() bool {
	if x != nil {
		return x.Totp
	}
	return false
}

func (x *PromptMFARequest) GetWebauthn() bool {
	if x != nil {
		return x.Webauthn
	}
	return false
}

type PromptMFAResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TotpCode string `protobuf:"bytes,1,opt,name=totp_code,json=totpCode,proto3" json:"totp_code,omitempty"`
}

func (x *PromptMFAResponse) Reset() {
	*x = PromptMFAResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PromptMFAResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PromptMFAResponse) ProtoMessage() {}

func (x *PromptMFAResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PromptMFAResponse.ProtoReflect.Descriptor instead.
func (*PromptMFAResponse) Descriptor() ([]byte, []int) {
	return file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDescGZIP(), []int{9}
}

func (x *PromptMFAResponse) GetTotpCode() string {
	if x != nil {
		return x.TotpCode
	}
	return ""
}

var File_teleport_lib_teleterm_v1_tshd_events_service_proto protoreflect.FileDescriptor

var file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDesc = []byte{
	0x0a, 0x32, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6c, 0x69, 0x62, 0x2f, 0x74,
	0x65, 0x6c, 0x65, 0x74, 0x65, 0x72, 0x6d, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x73, 0x68, 0x64, 0x5f,
	0x65, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x18, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c,
	0x69, 0x62, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x72, 0x6d, 0x2e, 0x76, 0x31, 0x22, 0xa6,
	0x01, 0x0a, 0x0e, 0x52, 0x65, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x28, 0x0a, 0x10, 0x72, 0x6f, 0x6f, 0x74, 0x5f, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65,
	0x72, 0x5f, 0x75, 0x72, 0x69, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x72, 0x6f, 0x6f,
	0x74, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x55, 0x72, 0x69, 0x12, 0x60, 0x0a, 0x14, 0x67,
	0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x5f, 0x65, 0x78, 0x70, 0x69,
	0x72, 0x65, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2c, 0x2e, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x69, 0x62, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x72,
	0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x43, 0x65, 0x72, 0x74,
	0x45, 0x78, 0x70, 0x69, 0x72, 0x65, 0x64, 0x48, 0x00, 0x52, 0x12, 0x67, 0x61, 0x74, 0x65, 0x77,
	0x61, 0x79, 0x43, 0x65, 0x72, 0x74, 0x45, 0x78, 0x70, 0x69, 0x72, 0x65, 0x64, 0x42, 0x08, 0x0a,
	0x06, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x22, 0x54, 0x0a, 0x12, 0x47, 0x61, 0x74, 0x65, 0x77,
	0x61, 0x79, 0x43, 0x65, 0x72, 0x74, 0x45, 0x78, 0x70, 0x69, 0x72, 0x65, 0x64, 0x12, 0x1f, 0x0a,
	0x0b, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x5f, 0x75, 0x72, 0x69, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0a, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x55, 0x72, 0x69, 0x12, 0x1d,
	0x0a, 0x0a, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x75, 0x72, 0x69, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x09, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x55, 0x72, 0x69, 0x22, 0x11, 0x0a,
	0x0f, 0x52, 0x65, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x22, 0xa5, 0x01, 0x0a, 0x17, 0x53, 0x65, 0x6e, 0x64, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x7f, 0x0a, 0x1f,
	0x63, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x5f, 0x67, 0x61, 0x74,
	0x65, 0x77, 0x61, 0x79, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x36, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74,
	0x2e, 0x6c, 0x69, 0x62, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x72, 0x6d, 0x2e, 0x76, 0x31,
	0x2e, 0x43, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x47, 0x61, 0x74, 0x65,
	0x77, 0x61, 0x79, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x48, 0x00, 0x52,
	0x1c, 0x63, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x47, 0x61, 0x74, 0x65,
	0x77, 0x61, 0x79, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x09, 0x0a,
	0x07, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x22, 0x74, 0x0a, 0x1c, 0x43, 0x61, 0x6e, 0x6e,
	0x6f, 0x74, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x47, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x43, 0x6f,
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1f, 0x0a, 0x0b, 0x67, 0x61, 0x74, 0x65,
	0x77, 0x61, 0x79, 0x5f, 0x75, 0x72, 0x69, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x67,
	0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x55, 0x72, 0x69, 0x12, 0x1d, 0x0a, 0x0a, 0x74, 0x61, 0x72,
	0x67, 0x65, 0x74, 0x5f, 0x75, 0x72, 0x69, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x74,
	0x61, 0x72, 0x67, 0x65, 0x74, 0x55, 0x72, 0x69, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f,
	0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x22, 0x1a,
	0x0a, 0x18, 0x53, 0x65, 0x6e, 0x64, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0xdd, 0x01, 0x0a, 0x28, 0x53,
	0x65, 0x6e, 0x64, 0x50, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x48, 0x65, 0x61, 0x64, 0x6c, 0x65,
	0x73, 0x73, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x28, 0x0a, 0x10, 0x72, 0x6f, 0x6f, 0x74, 0x5f,
	0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x5f, 0x75, 0x72, 0x69, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0e, 0x72, 0x6f, 0x6f, 0x74, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x55, 0x72,
	0x69, 0x12, 0x3c, 0x0a, 0x1a, 0x68, 0x65, 0x61, 0x64, 0x6c, 0x65, 0x73, 0x73, 0x5f, 0x61, 0x75,
	0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x18, 0x68, 0x65, 0x61, 0x64, 0x6c, 0x65, 0x73, 0x73, 0x41,
	0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12,
	0x49, 0x0a, 0x21, 0x68, 0x65, 0x61, 0x64, 0x6c, 0x65, 0x73, 0x73, 0x5f, 0x61, 0x75, 0x74, 0x68,
	0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x5f, 0x69, 0x70, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x1e, 0x68, 0x65, 0x61, 0x64,
	0x6c, 0x65, 0x73, 0x73, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x70, 0x22, 0x2b, 0x0a, 0x29, 0x53, 0x65,
	0x6e, 0x64, 0x50, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x48, 0x65, 0x61, 0x64, 0x6c, 0x65, 0x73,
	0x73, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x84, 0x01, 0x0a, 0x10, 0x50, 0x72, 0x6f, 0x6d,
	0x70, 0x74, 0x4d, 0x46, 0x41, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x28, 0x0a, 0x10,
	0x72, 0x6f, 0x6f, 0x74, 0x5f, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x5f, 0x75, 0x72, 0x69,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x72, 0x6f, 0x6f, 0x74, 0x43, 0x6c, 0x75, 0x73,
	0x74, 0x65, 0x72, 0x55, 0x72, 0x69, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x12, 0x12,
	0x0a, 0x04, 0x74, 0x6f, 0x74, 0x70, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x04, 0x74, 0x6f,
	0x74, 0x70, 0x12, 0x1a, 0x0a, 0x08, 0x77, 0x65, 0x62, 0x61, 0x75, 0x74, 0x68, 0x6e, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x77, 0x65, 0x62, 0x61, 0x75, 0x74, 0x68, 0x6e, 0x22, 0x30,
	0x0a, 0x11, 0x50, 0x72, 0x6f, 0x6d, 0x70, 0x74, 0x4d, 0x46, 0x41, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x74, 0x6f, 0x74, 0x70, 0x5f, 0x63, 0x6f, 0x64, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x74, 0x6f, 0x74, 0x70, 0x43, 0x6f, 0x64, 0x65,
	0x32, 0x83, 0x04, 0x0a, 0x11, 0x54, 0x73, 0x68, 0x64, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x5e, 0x0a, 0x07, 0x52, 0x65, 0x6c, 0x6f, 0x67, 0x69,
	0x6e, 0x12, 0x28, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x69, 0x62,
	0x2e, 0x74, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x72, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x6c,
	0x6f, 0x67, 0x69, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x29, 0x2e, 0x74, 0x65,
	0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x69, 0x62, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x74,
	0x65, 0x72, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x79, 0x0a, 0x10, 0x53, 0x65, 0x6e, 0x64, 0x4e, 0x6f,
	0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x31, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x69, 0x62, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x74, 0x65,
	0x72, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65, 0x6e, 0x64, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69,
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x32, 0x2e,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x69, 0x62, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x74, 0x65, 0x72, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65, 0x6e, 0x64, 0x4e, 0x6f, 0x74,
	0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0xac, 0x01, 0x0a, 0x21, 0x53, 0x65, 0x6e, 0x64, 0x50, 0x65, 0x6e, 0x64, 0x69, 0x6e,
	0x67, 0x48, 0x65, 0x61, 0x64, 0x6c, 0x65, 0x73, 0x73, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74,
	0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x42, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x2e, 0x6c, 0x69, 0x62, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x72, 0x6d, 0x2e,
	0x76, 0x31, 0x2e, 0x53, 0x65, 0x6e, 0x64, 0x50, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x48, 0x65,
	0x61, 0x64, 0x6c, 0x65, 0x73, 0x73, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x43, 0x2e, 0x74, 0x65,
	0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x69, 0x62, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x74,
	0x65, 0x72, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65, 0x6e, 0x64, 0x50, 0x65, 0x6e, 0x64, 0x69,
	0x6e, 0x67, 0x48, 0x65, 0x61, 0x64, 0x6c, 0x65, 0x73, 0x73, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e,
	0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x64, 0x0a, 0x09, 0x50, 0x72, 0x6f, 0x6d, 0x70, 0x74, 0x4d, 0x46, 0x41, 0x12, 0x2a, 0x2e,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x69, 0x62, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x74, 0x65, 0x72, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72, 0x6f, 0x6d, 0x70, 0x74, 0x4d,
	0x46, 0x41, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2b, 0x2e, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x69, 0x62, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x72,
	0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72, 0x6f, 0x6d, 0x70, 0x74, 0x4d, 0x46, 0x41, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x54, 0x5a, 0x52, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x67, 0x65, 0x6e, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2f, 0x6c, 0x69, 0x62, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x72, 0x6d, 0x2f, 0x76,
	0x31, 0x3b, 0x74, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x72, 0x6d, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDescOnce sync.Once
	file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDescData = file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDesc
)

func file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDescGZIP() []byte {
	file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDescOnce.Do(func() {
		file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDescData)
	})
	return file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDescData
}

var file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_teleport_lib_teleterm_v1_tshd_events_service_proto_goTypes = []interface{}{
	(*ReloginRequest)(nil),                            // 0: teleport.lib.teleterm.v1.ReloginRequest
	(*GatewayCertExpired)(nil),                        // 1: teleport.lib.teleterm.v1.GatewayCertExpired
	(*ReloginResponse)(nil),                           // 2: teleport.lib.teleterm.v1.ReloginResponse
	(*SendNotificationRequest)(nil),                   // 3: teleport.lib.teleterm.v1.SendNotificationRequest
	(*CannotProxyGatewayConnection)(nil),              // 4: teleport.lib.teleterm.v1.CannotProxyGatewayConnection
	(*SendNotificationResponse)(nil),                  // 5: teleport.lib.teleterm.v1.SendNotificationResponse
	(*SendPendingHeadlessAuthenticationRequest)(nil),  // 6: teleport.lib.teleterm.v1.SendPendingHeadlessAuthenticationRequest
	(*SendPendingHeadlessAuthenticationResponse)(nil), // 7: teleport.lib.teleterm.v1.SendPendingHeadlessAuthenticationResponse
	(*PromptMFARequest)(nil),                          // 8: teleport.lib.teleterm.v1.PromptMFARequest
	(*PromptMFAResponse)(nil),                         // 9: teleport.lib.teleterm.v1.PromptMFAResponse
}
var file_teleport_lib_teleterm_v1_tshd_events_service_proto_depIdxs = []int32{
	1, // 0: teleport.lib.teleterm.v1.ReloginRequest.gateway_cert_expired:type_name -> teleport.lib.teleterm.v1.GatewayCertExpired
	4, // 1: teleport.lib.teleterm.v1.SendNotificationRequest.cannot_proxy_gateway_connection:type_name -> teleport.lib.teleterm.v1.CannotProxyGatewayConnection
	0, // 2: teleport.lib.teleterm.v1.TshdEventsService.Relogin:input_type -> teleport.lib.teleterm.v1.ReloginRequest
	3, // 3: teleport.lib.teleterm.v1.TshdEventsService.SendNotification:input_type -> teleport.lib.teleterm.v1.SendNotificationRequest
	6, // 4: teleport.lib.teleterm.v1.TshdEventsService.SendPendingHeadlessAuthentication:input_type -> teleport.lib.teleterm.v1.SendPendingHeadlessAuthenticationRequest
	8, // 5: teleport.lib.teleterm.v1.TshdEventsService.PromptMFA:input_type -> teleport.lib.teleterm.v1.PromptMFARequest
	2, // 6: teleport.lib.teleterm.v1.TshdEventsService.Relogin:output_type -> teleport.lib.teleterm.v1.ReloginResponse
	5, // 7: teleport.lib.teleterm.v1.TshdEventsService.SendNotification:output_type -> teleport.lib.teleterm.v1.SendNotificationResponse
	7, // 8: teleport.lib.teleterm.v1.TshdEventsService.SendPendingHeadlessAuthentication:output_type -> teleport.lib.teleterm.v1.SendPendingHeadlessAuthenticationResponse
	9, // 9: teleport.lib.teleterm.v1.TshdEventsService.PromptMFA:output_type -> teleport.lib.teleterm.v1.PromptMFAResponse
	6, // [6:10] is the sub-list for method output_type
	2, // [2:6] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_teleport_lib_teleterm_v1_tshd_events_service_proto_init() }
func file_teleport_lib_teleterm_v1_tshd_events_service_proto_init() {
	if File_teleport_lib_teleterm_v1_tshd_events_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReloginRequest); i {
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
		file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GatewayCertExpired); i {
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
		file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReloginResponse); i {
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
		file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SendNotificationRequest); i {
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
		file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CannotProxyGatewayConnection); i {
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
		file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SendNotificationResponse); i {
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
		file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SendPendingHeadlessAuthenticationRequest); i {
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
		file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SendPendingHeadlessAuthenticationResponse); i {
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
		file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PromptMFARequest); i {
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
		file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PromptMFAResponse); i {
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
	file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*ReloginRequest_GatewayCertExpired)(nil),
	}
	file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes[3].OneofWrappers = []interface{}{
		(*SendNotificationRequest_CannotProxyGatewayConnection)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_teleport_lib_teleterm_v1_tshd_events_service_proto_goTypes,
		DependencyIndexes: file_teleport_lib_teleterm_v1_tshd_events_service_proto_depIdxs,
		MessageInfos:      file_teleport_lib_teleterm_v1_tshd_events_service_proto_msgTypes,
	}.Build()
	File_teleport_lib_teleterm_v1_tshd_events_service_proto = out.File
	file_teleport_lib_teleterm_v1_tshd_events_service_proto_rawDesc = nil
	file_teleport_lib_teleterm_v1_tshd_events_service_proto_goTypes = nil
	file_teleport_lib_teleterm_v1_tshd_events_service_proto_depIdxs = nil
}
