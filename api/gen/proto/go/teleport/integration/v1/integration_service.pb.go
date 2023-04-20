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
// 	protoc-gen-go v1.28.1
// 	protoc        (unknown)
// source: teleport/integration/v1/integration_service.proto

package integrationv1

import (
	types "github.com/gravitational/teleport/api/types"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// ListIntegrationsRequest is a request for a paginated list of Integrations.
type ListIntegrationsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Limit is the maximum amount of resources to retrieve.
	Limit int32 `protobuf:"varint,1,opt,name=limit,proto3" json:"limit,omitempty"`
	// NextKey is the key for the next page of Integrations.
	NextKey string `protobuf:"bytes,2,opt,name=next_key,json=nextKey,proto3" json:"next_key,omitempty"`
}

func (x *ListIntegrationsRequest) Reset() {
	*x = ListIntegrationsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_integration_v1_integration_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListIntegrationsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListIntegrationsRequest) ProtoMessage() {}

func (x *ListIntegrationsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_integration_v1_integration_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListIntegrationsRequest.ProtoReflect.Descriptor instead.
func (*ListIntegrationsRequest) Descriptor() ([]byte, []int) {
	return file_teleport_integration_v1_integration_service_proto_rawDescGZIP(), []int{0}
}

func (x *ListIntegrationsRequest) GetLimit() int32 {
	if x != nil {
		return x.Limit
	}
	return 0
}

func (x *ListIntegrationsRequest) GetNextKey() string {
	if x != nil {
		return x.NextKey
	}
	return ""
}

// ListIntegrationsResponse is the response for ListIntegrationsRequest.
type ListIntegrationsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Integrations is a list of Integrations.
	Integrations []*types.IntegrationV1 `protobuf:"bytes,1,rep,name=integrations,proto3" json:"integrations,omitempty"`
	// NextKey is the key for the next page of Integrations.
	NextKey string `protobuf:"bytes,2,opt,name=next_key,json=nextKey,proto3" json:"next_key,omitempty"`
	// TotalCount is the total number of integrations in all pages.
	TotalCount int32 `protobuf:"varint,3,opt,name=total_count,json=totalCount,proto3" json:"total_count,omitempty"`
}

func (x *ListIntegrationsResponse) Reset() {
	*x = ListIntegrationsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_integration_v1_integration_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListIntegrationsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListIntegrationsResponse) ProtoMessage() {}

func (x *ListIntegrationsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_integration_v1_integration_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListIntegrationsResponse.ProtoReflect.Descriptor instead.
func (*ListIntegrationsResponse) Descriptor() ([]byte, []int) {
	return file_teleport_integration_v1_integration_service_proto_rawDescGZIP(), []int{1}
}

func (x *ListIntegrationsResponse) GetIntegrations() []*types.IntegrationV1 {
	if x != nil {
		return x.Integrations
	}
	return nil
}

func (x *ListIntegrationsResponse) GetNextKey() string {
	if x != nil {
		return x.NextKey
	}
	return ""
}

func (x *ListIntegrationsResponse) GetTotalCount() int32 {
	if x != nil {
		return x.TotalCount
	}
	return 0
}

// GetIntegrationRequest is a request for a specific Integration resource.
type GetIntegrationRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Name is the name of the Integration to be requested.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *GetIntegrationRequest) Reset() {
	*x = GetIntegrationRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_integration_v1_integration_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetIntegrationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetIntegrationRequest) ProtoMessage() {}

func (x *GetIntegrationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_integration_v1_integration_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetIntegrationRequest.ProtoReflect.Descriptor instead.
func (*GetIntegrationRequest) Descriptor() ([]byte, []int) {
	return file_teleport_integration_v1_integration_service_proto_rawDescGZIP(), []int{2}
}

func (x *GetIntegrationRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

// CreateIntegrationRequest is the request to create the provided integration.
type CreateIntegrationRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Integration is the integration to be created.
	Integration *types.IntegrationV1 `protobuf:"bytes,1,opt,name=integration,proto3" json:"integration,omitempty"`
}

func (x *CreateIntegrationRequest) Reset() {
	*x = CreateIntegrationRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_integration_v1_integration_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateIntegrationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateIntegrationRequest) ProtoMessage() {}

func (x *CreateIntegrationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_integration_v1_integration_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateIntegrationRequest.ProtoReflect.Descriptor instead.
func (*CreateIntegrationRequest) Descriptor() ([]byte, []int) {
	return file_teleport_integration_v1_integration_service_proto_rawDescGZIP(), []int{3}
}

func (x *CreateIntegrationRequest) GetIntegration() *types.IntegrationV1 {
	if x != nil {
		return x.Integration
	}
	return nil
}

// UpdateIntegrationRequest is the request to update the provided integration.
type UpdateIntegrationRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Integration is the integration to be created.
	Integration *types.IntegrationV1 `protobuf:"bytes,1,opt,name=integration,proto3" json:"integration,omitempty"`
}

func (x *UpdateIntegrationRequest) Reset() {
	*x = UpdateIntegrationRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_integration_v1_integration_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateIntegrationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateIntegrationRequest) ProtoMessage() {}

func (x *UpdateIntegrationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_integration_v1_integration_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateIntegrationRequest.ProtoReflect.Descriptor instead.
func (*UpdateIntegrationRequest) Descriptor() ([]byte, []int) {
	return file_teleport_integration_v1_integration_service_proto_rawDescGZIP(), []int{4}
}

func (x *UpdateIntegrationRequest) GetIntegration() *types.IntegrationV1 {
	if x != nil {
		return x.Integration
	}
	return nil
}

// DeleteIntegrationRequest is a request for deleting a specific Integration resource.
type DeleteIntegrationRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Name is the name of the Integration to be deleted.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *DeleteIntegrationRequest) Reset() {
	*x = DeleteIntegrationRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_integration_v1_integration_service_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteIntegrationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteIntegrationRequest) ProtoMessage() {}

func (x *DeleteIntegrationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_integration_v1_integration_service_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteIntegrationRequest.ProtoReflect.Descriptor instead.
func (*DeleteIntegrationRequest) Descriptor() ([]byte, []int) {
	return file_teleport_integration_v1_integration_service_proto_rawDescGZIP(), []int{5}
}

func (x *DeleteIntegrationRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

// DeleteAllIntegrationsRequest is the request for deleting all integrations.
type DeleteAllIntegrationsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DeleteAllIntegrationsRequest) Reset() {
	*x = DeleteAllIntegrationsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_integration_v1_integration_service_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteAllIntegrationsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteAllIntegrationsRequest) ProtoMessage() {}

func (x *DeleteAllIntegrationsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_integration_v1_integration_service_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteAllIntegrationsRequest.ProtoReflect.Descriptor instead.
func (*DeleteAllIntegrationsRequest) Descriptor() ([]byte, []int) {
	return file_teleport_integration_v1_integration_service_proto_rawDescGZIP(), []int{6}
}

// GenerateAWSOIDCTokenRequest are the parameters used to request an AWS OIDC
// Integration token.
type GenerateAWSOIDCTokenRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Issuer is the entity that is signing the JWT.
	// This value must contain the AWS OIDC Integration configured provider (Teleport Proxy's Public URL)
	Issuer string `protobuf:"bytes,1,opt,name=issuer,proto3" json:"issuer,omitempty"`
}

func (x *GenerateAWSOIDCTokenRequest) Reset() {
	*x = GenerateAWSOIDCTokenRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_integration_v1_integration_service_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GenerateAWSOIDCTokenRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GenerateAWSOIDCTokenRequest) ProtoMessage() {}

func (x *GenerateAWSOIDCTokenRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_integration_v1_integration_service_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GenerateAWSOIDCTokenRequest.ProtoReflect.Descriptor instead.
func (*GenerateAWSOIDCTokenRequest) Descriptor() ([]byte, []int) {
	return file_teleport_integration_v1_integration_service_proto_rawDescGZIP(), []int{7}
}

func (x *GenerateAWSOIDCTokenRequest) GetIssuer() string {
	if x != nil {
		return x.Issuer
	}
	return ""
}

// GenerateAWSOIDCTokenResponse contains a signed AWS OIDC Integration token.
type GenerateAWSOIDCTokenResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Token is the signed JWT ready to be used
	Token string `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
}

func (x *GenerateAWSOIDCTokenResponse) Reset() {
	*x = GenerateAWSOIDCTokenResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_integration_v1_integration_service_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GenerateAWSOIDCTokenResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GenerateAWSOIDCTokenResponse) ProtoMessage() {}

func (x *GenerateAWSOIDCTokenResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_integration_v1_integration_service_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GenerateAWSOIDCTokenResponse.ProtoReflect.Descriptor instead.
func (*GenerateAWSOIDCTokenResponse) Descriptor() ([]byte, []int) {
	return file_teleport_integration_v1_integration_service_proto_rawDescGZIP(), []int{8}
}

func (x *GenerateAWSOIDCTokenResponse) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

var File_teleport_integration_v1_integration_service_proto protoreflect.FileDescriptor

var file_teleport_integration_v1_integration_service_proto_rawDesc = []byte{
	0x0a, 0x31, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x67,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x17, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e,
	0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x1a, 0x1b, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d,
	0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x21, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2f, 0x6c, 0x65, 0x67, 0x61, 0x63, 0x79, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73,
	0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x4a, 0x0a, 0x17,
	0x4c, 0x69, 0x73, 0x74, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x6c, 0x69, 0x6d, 0x69, 0x74,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x05, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x12, 0x19, 0x0a,
	0x08, 0x6e, 0x65, 0x78, 0x74, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x07, 0x6e, 0x65, 0x78, 0x74, 0x4b, 0x65, 0x79, 0x22, 0x90, 0x01, 0x0a, 0x18, 0x4c, 0x69, 0x73,
	0x74, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x38, 0x0a, 0x0c, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x74, 0x79,
	0x70, 0x65, 0x73, 0x2e, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x56,
	0x31, 0x52, 0x0c, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12,
	0x19, 0x0a, 0x08, 0x6e, 0x65, 0x78, 0x74, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x6e, 0x65, 0x78, 0x74, 0x4b, 0x65, 0x79, 0x12, 0x1f, 0x0a, 0x0b, 0x74, 0x6f,
	0x74, 0x61, 0x6c, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x0a, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x22, 0x2b, 0x0a, 0x15, 0x47,
	0x65, 0x74, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x52, 0x0a, 0x18, 0x43, 0x72, 0x65, 0x61,
	0x74, 0x65, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x36, 0x0a, 0x0b, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x74, 0x79, 0x70, 0x65,
	0x73, 0x2e, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x56, 0x31, 0x52,
	0x0b, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x52, 0x0a, 0x18,
	0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x36, 0x0a, 0x0b, 0x69, 0x6e, 0x74, 0x65,
	0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e,
	0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x56, 0x31, 0x52, 0x0b, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x22, 0x2e, 0x0a, 0x18, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x22, 0x1e, 0x0a, 0x1c, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x41, 0x6c, 0x6c, 0x49, 0x6e, 0x74,
	0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x22, 0x35, 0x0a, 0x1b, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x41, 0x57, 0x53, 0x4f,
	0x49, 0x44, 0x43, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x16, 0x0a, 0x06, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x06, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x22, 0x34, 0x0a, 0x1c, 0x47, 0x65, 0x6e, 0x65, 0x72,
	0x61, 0x74, 0x65, 0x41, 0x57, 0x53, 0x4f, 0x49, 0x44, 0x43, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x32, 0xef, 0x05,
	0x0a, 0x12, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x12, 0x77, 0x0a, 0x10, 0x4c, 0x69, 0x73, 0x74, 0x49, 0x6e, 0x74, 0x65,
	0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x30, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e,
	0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x31, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x56, 0x0a,
	0x0e, 0x47, 0x65, 0x74, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x2e, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x67,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x49, 0x6e, 0x74,
	0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x14, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x56, 0x31, 0x12, 0x5c, 0x0a, 0x11, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x49,
	0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x31, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x49, 0x6e, 0x74, 0x65, 0x67,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x14, 0x2e,
	0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x56, 0x31, 0x12, 0x5c, 0x0a, 0x11, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x49, 0x6e, 0x74,
	0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x31, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e,
	0x76, 0x31, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x14, 0x2e, 0x74, 0x79,
	0x70, 0x65, 0x73, 0x2e, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x56,
	0x31, 0x12, 0x5e, 0x0a, 0x11, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x49, 0x6e, 0x74, 0x65, 0x67,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x31, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31,
	0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74,
	0x79, 0x12, 0x66, 0x0a, 0x15, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x41, 0x6c, 0x6c, 0x49, 0x6e,
	0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x35, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x41, 0x6c, 0x6c, 0x49, 0x6e,
	0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x12, 0x83, 0x01, 0x0a, 0x14, 0x47, 0x65,
	0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x41, 0x57, 0x53, 0x4f, 0x49, 0x44, 0x43, 0x54, 0x6f, 0x6b,
	0x65, 0x6e, 0x12, 0x34, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e,
	0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x6e,
	0x65, 0x72, 0x61, 0x74, 0x65, 0x41, 0x57, 0x53, 0x4f, 0x49, 0x44, 0x43, 0x54, 0x6f, 0x6b, 0x65,
	0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x35, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e,
	0x76, 0x31, 0x2e, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x41, 0x57, 0x53, 0x4f, 0x49,
	0x44, 0x43, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42,
	0x5a, 0x5a, 0x58, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72,
	0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x69,
	0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x3b, 0x69, 0x6e,
	0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_teleport_integration_v1_integration_service_proto_rawDescOnce sync.Once
	file_teleport_integration_v1_integration_service_proto_rawDescData = file_teleport_integration_v1_integration_service_proto_rawDesc
)

func file_teleport_integration_v1_integration_service_proto_rawDescGZIP() []byte {
	file_teleport_integration_v1_integration_service_proto_rawDescOnce.Do(func() {
		file_teleport_integration_v1_integration_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_integration_v1_integration_service_proto_rawDescData)
	})
	return file_teleport_integration_v1_integration_service_proto_rawDescData
}

var file_teleport_integration_v1_integration_service_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_teleport_integration_v1_integration_service_proto_goTypes = []interface{}{
	(*ListIntegrationsRequest)(nil),      // 0: teleport.integration.v1.ListIntegrationsRequest
	(*ListIntegrationsResponse)(nil),     // 1: teleport.integration.v1.ListIntegrationsResponse
	(*GetIntegrationRequest)(nil),        // 2: teleport.integration.v1.GetIntegrationRequest
	(*CreateIntegrationRequest)(nil),     // 3: teleport.integration.v1.CreateIntegrationRequest
	(*UpdateIntegrationRequest)(nil),     // 4: teleport.integration.v1.UpdateIntegrationRequest
	(*DeleteIntegrationRequest)(nil),     // 5: teleport.integration.v1.DeleteIntegrationRequest
	(*DeleteAllIntegrationsRequest)(nil), // 6: teleport.integration.v1.DeleteAllIntegrationsRequest
	(*GenerateAWSOIDCTokenRequest)(nil),  // 7: teleport.integration.v1.GenerateAWSOIDCTokenRequest
	(*GenerateAWSOIDCTokenResponse)(nil), // 8: teleport.integration.v1.GenerateAWSOIDCTokenResponse
	(*types.IntegrationV1)(nil),          // 9: types.IntegrationV1
	(*emptypb.Empty)(nil),                // 10: google.protobuf.Empty
}
var file_teleport_integration_v1_integration_service_proto_depIdxs = []int32{
	9,  // 0: teleport.integration.v1.ListIntegrationsResponse.integrations:type_name -> types.IntegrationV1
	9,  // 1: teleport.integration.v1.CreateIntegrationRequest.integration:type_name -> types.IntegrationV1
	9,  // 2: teleport.integration.v1.UpdateIntegrationRequest.integration:type_name -> types.IntegrationV1
	0,  // 3: teleport.integration.v1.IntegrationService.ListIntegrations:input_type -> teleport.integration.v1.ListIntegrationsRequest
	2,  // 4: teleport.integration.v1.IntegrationService.GetIntegration:input_type -> teleport.integration.v1.GetIntegrationRequest
	3,  // 5: teleport.integration.v1.IntegrationService.CreateIntegration:input_type -> teleport.integration.v1.CreateIntegrationRequest
	4,  // 6: teleport.integration.v1.IntegrationService.UpdateIntegration:input_type -> teleport.integration.v1.UpdateIntegrationRequest
	5,  // 7: teleport.integration.v1.IntegrationService.DeleteIntegration:input_type -> teleport.integration.v1.DeleteIntegrationRequest
	6,  // 8: teleport.integration.v1.IntegrationService.DeleteAllIntegrations:input_type -> teleport.integration.v1.DeleteAllIntegrationsRequest
	7,  // 9: teleport.integration.v1.IntegrationService.GenerateAWSOIDCToken:input_type -> teleport.integration.v1.GenerateAWSOIDCTokenRequest
	1,  // 10: teleport.integration.v1.IntegrationService.ListIntegrations:output_type -> teleport.integration.v1.ListIntegrationsResponse
	9,  // 11: teleport.integration.v1.IntegrationService.GetIntegration:output_type -> types.IntegrationV1
	9,  // 12: teleport.integration.v1.IntegrationService.CreateIntegration:output_type -> types.IntegrationV1
	9,  // 13: teleport.integration.v1.IntegrationService.UpdateIntegration:output_type -> types.IntegrationV1
	10, // 14: teleport.integration.v1.IntegrationService.DeleteIntegration:output_type -> google.protobuf.Empty
	10, // 15: teleport.integration.v1.IntegrationService.DeleteAllIntegrations:output_type -> google.protobuf.Empty
	8,  // 16: teleport.integration.v1.IntegrationService.GenerateAWSOIDCToken:output_type -> teleport.integration.v1.GenerateAWSOIDCTokenResponse
	10, // [10:17] is the sub-list for method output_type
	3,  // [3:10] is the sub-list for method input_type
	3,  // [3:3] is the sub-list for extension type_name
	3,  // [3:3] is the sub-list for extension extendee
	0,  // [0:3] is the sub-list for field type_name
}

func init() { file_teleport_integration_v1_integration_service_proto_init() }
func file_teleport_integration_v1_integration_service_proto_init() {
	if File_teleport_integration_v1_integration_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleport_integration_v1_integration_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListIntegrationsRequest); i {
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
		file_teleport_integration_v1_integration_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListIntegrationsResponse); i {
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
		file_teleport_integration_v1_integration_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetIntegrationRequest); i {
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
		file_teleport_integration_v1_integration_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateIntegrationRequest); i {
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
		file_teleport_integration_v1_integration_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateIntegrationRequest); i {
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
		file_teleport_integration_v1_integration_service_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteIntegrationRequest); i {
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
		file_teleport_integration_v1_integration_service_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteAllIntegrationsRequest); i {
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
		file_teleport_integration_v1_integration_service_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GenerateAWSOIDCTokenRequest); i {
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
		file_teleport_integration_v1_integration_service_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GenerateAWSOIDCTokenResponse); i {
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
			RawDescriptor: file_teleport_integration_v1_integration_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_teleport_integration_v1_integration_service_proto_goTypes,
		DependencyIndexes: file_teleport_integration_v1_integration_service_proto_depIdxs,
		MessageInfos:      file_teleport_integration_v1_integration_service_proto_msgTypes,
	}.Build()
	File_teleport_integration_v1_integration_service_proto = out.File
	file_teleport_integration_v1_integration_service_proto_rawDesc = nil
	file_teleport_integration_v1_integration_service_proto_goTypes = nil
	file_teleport_integration_v1_integration_service_proto_depIdxs = nil
}
