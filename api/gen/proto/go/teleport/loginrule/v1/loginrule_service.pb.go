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
// 	protoc-gen-go v1.32.0
// 	protoc        (unknown)
// source: teleport/loginrule/v1/loginrule_service.proto

package loginrulev1

import (
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

// CreateLoginRuleRequest is a request to create a login rule.
type CreateLoginRuleRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// LoginRule is the login rule to be created.
	LoginRule *LoginRule `protobuf:"bytes,1,opt,name=login_rule,json=loginRule,proto3" json:"login_rule,omitempty"`
}

func (x *CreateLoginRuleRequest) Reset() {
	*x = CreateLoginRuleRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_loginrule_v1_loginrule_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateLoginRuleRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateLoginRuleRequest) ProtoMessage() {}

func (x *CreateLoginRuleRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_loginrule_v1_loginrule_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateLoginRuleRequest.ProtoReflect.Descriptor instead.
func (*CreateLoginRuleRequest) Descriptor() ([]byte, []int) {
	return file_teleport_loginrule_v1_loginrule_service_proto_rawDescGZIP(), []int{0}
}

func (x *CreateLoginRuleRequest) GetLoginRule() *LoginRule {
	if x != nil {
		return x.LoginRule
	}
	return nil
}

// UpsertLoginRuleRequest is a request to upsert a login rule.
type UpsertLoginRuleRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// LoginRule is the login rule to be created.
	LoginRule *LoginRule `protobuf:"bytes,1,opt,name=login_rule,json=loginRule,proto3" json:"login_rule,omitempty"`
}

func (x *UpsertLoginRuleRequest) Reset() {
	*x = UpsertLoginRuleRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_loginrule_v1_loginrule_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpsertLoginRuleRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpsertLoginRuleRequest) ProtoMessage() {}

func (x *UpsertLoginRuleRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_loginrule_v1_loginrule_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpsertLoginRuleRequest.ProtoReflect.Descriptor instead.
func (*UpsertLoginRuleRequest) Descriptor() ([]byte, []int) {
	return file_teleport_loginrule_v1_loginrule_service_proto_rawDescGZIP(), []int{1}
}

func (x *UpsertLoginRuleRequest) GetLoginRule() *LoginRule {
	if x != nil {
		return x.LoginRule
	}
	return nil
}

// GetLoginRuleRequest is a request to get a single login rule.
type GetLoginRuleRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Name is the name of the login rule to get.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *GetLoginRuleRequest) Reset() {
	*x = GetLoginRuleRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_loginrule_v1_loginrule_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetLoginRuleRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetLoginRuleRequest) ProtoMessage() {}

func (x *GetLoginRuleRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_loginrule_v1_loginrule_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetLoginRuleRequest.ProtoReflect.Descriptor instead.
func (*GetLoginRuleRequest) Descriptor() ([]byte, []int) {
	return file_teleport_loginrule_v1_loginrule_service_proto_rawDescGZIP(), []int{2}
}

func (x *GetLoginRuleRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

// ListLoginRulesRequest is a paginated request to list all login rules.
type ListLoginRulesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// PageSize is The maximum number of login rules to return in a single
	// reponse.
	PageSize int32 `protobuf:"varint,1,opt,name=page_size,json=pageSize,proto3" json:"page_size,omitempty"`
	// PageToken is the NextPageToken value returned from a previous
	// ListLoginRules request, if any.
	PageToken string `protobuf:"bytes,2,opt,name=page_token,json=pageToken,proto3" json:"page_token,omitempty"`
}

func (x *ListLoginRulesRequest) Reset() {
	*x = ListLoginRulesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_loginrule_v1_loginrule_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListLoginRulesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListLoginRulesRequest) ProtoMessage() {}

func (x *ListLoginRulesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_loginrule_v1_loginrule_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListLoginRulesRequest.ProtoReflect.Descriptor instead.
func (*ListLoginRulesRequest) Descriptor() ([]byte, []int) {
	return file_teleport_loginrule_v1_loginrule_service_proto_rawDescGZIP(), []int{3}
}

func (x *ListLoginRulesRequest) GetPageSize() int32 {
	if x != nil {
		return x.PageSize
	}
	return 0
}

func (x *ListLoginRulesRequest) GetPageToken() string {
	if x != nil {
		return x.PageToken
	}
	return ""
}

// ListLoginRulesResponse is a paginated response to a ListLoginRulesRequest.
type ListLoginRulesResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// LoginRules is the list of login rules.
	LoginRules []*LoginRule `protobuf:"bytes,1,rep,name=login_rules,json=loginRules,proto3" json:"login_rules,omitempty"`
	// NextPageToken is a token to retrieve the next page of results, or empty
	// if there are no more results.
	NextPageToken string `protobuf:"bytes,2,opt,name=next_page_token,json=nextPageToken,proto3" json:"next_page_token,omitempty"`
}

func (x *ListLoginRulesResponse) Reset() {
	*x = ListLoginRulesResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_loginrule_v1_loginrule_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListLoginRulesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListLoginRulesResponse) ProtoMessage() {}

func (x *ListLoginRulesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_loginrule_v1_loginrule_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListLoginRulesResponse.ProtoReflect.Descriptor instead.
func (*ListLoginRulesResponse) Descriptor() ([]byte, []int) {
	return file_teleport_loginrule_v1_loginrule_service_proto_rawDescGZIP(), []int{4}
}

func (x *ListLoginRulesResponse) GetLoginRules() []*LoginRule {
	if x != nil {
		return x.LoginRules
	}
	return nil
}

func (x *ListLoginRulesResponse) GetNextPageToken() string {
	if x != nil {
		return x.NextPageToken
	}
	return ""
}

// DeleteLoginRuleRequest is a request to delete a login rule.
type DeleteLoginRuleRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Name is the name of the login rule to delete.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *DeleteLoginRuleRequest) Reset() {
	*x = DeleteLoginRuleRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_loginrule_v1_loginrule_service_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteLoginRuleRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteLoginRuleRequest) ProtoMessage() {}

func (x *DeleteLoginRuleRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_loginrule_v1_loginrule_service_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteLoginRuleRequest.ProtoReflect.Descriptor instead.
func (*DeleteLoginRuleRequest) Descriptor() ([]byte, []int) {
	return file_teleport_loginrule_v1_loginrule_service_proto_rawDescGZIP(), []int{5}
}

func (x *DeleteLoginRuleRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

var File_teleport_loginrule_v1_loginrule_service_proto protoreflect.FileDescriptor

var file_teleport_loginrule_v1_loginrule_service_proto_rawDesc = []byte{
	0x0a, 0x2d, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6c, 0x6f, 0x67, 0x69, 0x6e,
	0x72, 0x75, 0x6c, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x72, 0x75, 0x6c,
	0x65, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x15, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x72,
	0x75, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x25, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6c, 0x6f,
	0x67, 0x69, 0x6e, 0x72, 0x75, 0x6c, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x6c, 0x6f, 0x67, 0x69, 0x6e,
	0x72, 0x75, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x59, 0x0a, 0x16, 0x43, 0x72,
	0x65, 0x61, 0x74, 0x65, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x3f, 0x0a, 0x0a, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x5f, 0x72, 0x75,
	0x6c, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x72, 0x75, 0x6c, 0x65, 0x2e, 0x76, 0x31,
	0x2e, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x09, 0x6c, 0x6f, 0x67, 0x69,
	0x6e, 0x52, 0x75, 0x6c, 0x65, 0x22, 0x59, 0x0a, 0x16, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74, 0x4c,
	0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x3f, 0x0a, 0x0a, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x5f, 0x72, 0x75, 0x6c, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c,
	0x6f, 0x67, 0x69, 0x6e, 0x72, 0x75, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x6f, 0x67, 0x69,
	0x6e, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x09, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75, 0x6c, 0x65,
	0x22, 0x29, 0x0a, 0x13, 0x47, 0x65, 0x74, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75, 0x6c, 0x65,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x53, 0x0a, 0x15, 0x4c,
	0x69, 0x73, 0x74, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75, 0x6c, 0x65, 0x73, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x70, 0x61, 0x67, 0x65, 0x5f, 0x73, 0x69, 0x7a,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x08, 0x70, 0x61, 0x67, 0x65, 0x53, 0x69, 0x7a,
	0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x61, 0x67, 0x65, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x61, 0x67, 0x65, 0x54, 0x6f, 0x6b, 0x65, 0x6e,
	0x22, 0x83, 0x01, 0x0a, 0x16, 0x4c, 0x69, 0x73, 0x74, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75,
	0x6c, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x41, 0x0a, 0x0b, 0x6c,
	0x6f, 0x67, 0x69, 0x6e, 0x5f, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x20, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x6f, 0x67, 0x69,
	0x6e, 0x72, 0x75, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75,
	0x6c, 0x65, 0x52, 0x0a, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75, 0x6c, 0x65, 0x73, 0x12, 0x26,
	0x0a, 0x0f, 0x6e, 0x65, 0x78, 0x74, 0x5f, 0x70, 0x61, 0x67, 0x65, 0x5f, 0x74, 0x6f, 0x6b, 0x65,
	0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x6e, 0x65, 0x78, 0x74, 0x50, 0x61, 0x67,
	0x65, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x2c, 0x0a, 0x16, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65,
	0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x32, 0x81, 0x04, 0x0a, 0x10, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75,
	0x6c, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x62, 0x0a, 0x0f, 0x43, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75, 0x6c, 0x65, 0x12, 0x2d, 0x2e, 0x74,
	0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x72, 0x75, 0x6c,
	0x65, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x4c, 0x6f, 0x67, 0x69, 0x6e,
	0x52, 0x75, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x20, 0x2e, 0x74, 0x65,
	0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x72, 0x75, 0x6c, 0x65,
	0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75, 0x6c, 0x65, 0x12, 0x62, 0x0a,
	0x0f, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75, 0x6c, 0x65,
	0x12, 0x2d, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x6f, 0x67, 0x69,
	0x6e, 0x72, 0x75, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74, 0x4c,
	0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x20, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x6f, 0x67, 0x69, 0x6e,
	0x72, 0x75, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75, 0x6c,
	0x65, 0x12, 0x5c, 0x0a, 0x0c, 0x47, 0x65, 0x74, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75, 0x6c,
	0x65, 0x12, 0x2a, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x6f, 0x67,
	0x69, 0x6e, 0x72, 0x75, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x4c, 0x6f, 0x67,
	0x69, 0x6e, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x20, 0x2e,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x72, 0x75,
	0x6c, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75, 0x6c, 0x65, 0x12,
	0x6d, 0x0a, 0x0e, 0x4c, 0x69, 0x73, 0x74, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75, 0x6c, 0x65,
	0x73, 0x12, 0x2c, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x6f, 0x67,
	0x69, 0x6e, 0x72, 0x75, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x4c, 0x6f,
	0x67, 0x69, 0x6e, 0x52, 0x75, 0x6c, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x2d, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x6f, 0x67, 0x69, 0x6e,
	0x72, 0x75, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x4c, 0x6f, 0x67, 0x69,
	0x6e, 0x52, 0x75, 0x6c, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x58,
	0x0a, 0x0f, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75, 0x6c,
	0x65, 0x12, 0x2d, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x6f, 0x67,
	0x69, 0x6e, 0x72, 0x75, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65,
	0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x42, 0x56, 0x5a, 0x54, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70,
	0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74,
	0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x72, 0x75, 0x6c,
	0x65, 0x2f, 0x76, 0x31, 0x3b, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x72, 0x75, 0x6c, 0x65, 0x76, 0x31,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_loginrule_v1_loginrule_service_proto_rawDescOnce sync.Once
	file_teleport_loginrule_v1_loginrule_service_proto_rawDescData = file_teleport_loginrule_v1_loginrule_service_proto_rawDesc
)

func file_teleport_loginrule_v1_loginrule_service_proto_rawDescGZIP() []byte {
	file_teleport_loginrule_v1_loginrule_service_proto_rawDescOnce.Do(func() {
		file_teleport_loginrule_v1_loginrule_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_loginrule_v1_loginrule_service_proto_rawDescData)
	})
	return file_teleport_loginrule_v1_loginrule_service_proto_rawDescData
}

var file_teleport_loginrule_v1_loginrule_service_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_teleport_loginrule_v1_loginrule_service_proto_goTypes = []interface{}{
	(*CreateLoginRuleRequest)(nil), // 0: teleport.loginrule.v1.CreateLoginRuleRequest
	(*UpsertLoginRuleRequest)(nil), // 1: teleport.loginrule.v1.UpsertLoginRuleRequest
	(*GetLoginRuleRequest)(nil),    // 2: teleport.loginrule.v1.GetLoginRuleRequest
	(*ListLoginRulesRequest)(nil),  // 3: teleport.loginrule.v1.ListLoginRulesRequest
	(*ListLoginRulesResponse)(nil), // 4: teleport.loginrule.v1.ListLoginRulesResponse
	(*DeleteLoginRuleRequest)(nil), // 5: teleport.loginrule.v1.DeleteLoginRuleRequest
	(*LoginRule)(nil),              // 6: teleport.loginrule.v1.LoginRule
	(*emptypb.Empty)(nil),          // 7: google.protobuf.Empty
}
var file_teleport_loginrule_v1_loginrule_service_proto_depIdxs = []int32{
	6, // 0: teleport.loginrule.v1.CreateLoginRuleRequest.login_rule:type_name -> teleport.loginrule.v1.LoginRule
	6, // 1: teleport.loginrule.v1.UpsertLoginRuleRequest.login_rule:type_name -> teleport.loginrule.v1.LoginRule
	6, // 2: teleport.loginrule.v1.ListLoginRulesResponse.login_rules:type_name -> teleport.loginrule.v1.LoginRule
	0, // 3: teleport.loginrule.v1.LoginRuleService.CreateLoginRule:input_type -> teleport.loginrule.v1.CreateLoginRuleRequest
	1, // 4: teleport.loginrule.v1.LoginRuleService.UpsertLoginRule:input_type -> teleport.loginrule.v1.UpsertLoginRuleRequest
	2, // 5: teleport.loginrule.v1.LoginRuleService.GetLoginRule:input_type -> teleport.loginrule.v1.GetLoginRuleRequest
	3, // 6: teleport.loginrule.v1.LoginRuleService.ListLoginRules:input_type -> teleport.loginrule.v1.ListLoginRulesRequest
	5, // 7: teleport.loginrule.v1.LoginRuleService.DeleteLoginRule:input_type -> teleport.loginrule.v1.DeleteLoginRuleRequest
	6, // 8: teleport.loginrule.v1.LoginRuleService.CreateLoginRule:output_type -> teleport.loginrule.v1.LoginRule
	6, // 9: teleport.loginrule.v1.LoginRuleService.UpsertLoginRule:output_type -> teleport.loginrule.v1.LoginRule
	6, // 10: teleport.loginrule.v1.LoginRuleService.GetLoginRule:output_type -> teleport.loginrule.v1.LoginRule
	4, // 11: teleport.loginrule.v1.LoginRuleService.ListLoginRules:output_type -> teleport.loginrule.v1.ListLoginRulesResponse
	7, // 12: teleport.loginrule.v1.LoginRuleService.DeleteLoginRule:output_type -> google.protobuf.Empty
	8, // [8:13] is the sub-list for method output_type
	3, // [3:8] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_teleport_loginrule_v1_loginrule_service_proto_init() }
func file_teleport_loginrule_v1_loginrule_service_proto_init() {
	if File_teleport_loginrule_v1_loginrule_service_proto != nil {
		return
	}
	file_teleport_loginrule_v1_loginrule_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_teleport_loginrule_v1_loginrule_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateLoginRuleRequest); i {
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
		file_teleport_loginrule_v1_loginrule_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpsertLoginRuleRequest); i {
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
		file_teleport_loginrule_v1_loginrule_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetLoginRuleRequest); i {
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
		file_teleport_loginrule_v1_loginrule_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListLoginRulesRequest); i {
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
		file_teleport_loginrule_v1_loginrule_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListLoginRulesResponse); i {
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
		file_teleport_loginrule_v1_loginrule_service_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteLoginRuleRequest); i {
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
			RawDescriptor: file_teleport_loginrule_v1_loginrule_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_teleport_loginrule_v1_loginrule_service_proto_goTypes,
		DependencyIndexes: file_teleport_loginrule_v1_loginrule_service_proto_depIdxs,
		MessageInfos:      file_teleport_loginrule_v1_loginrule_service_proto_msgTypes,
	}.Build()
	File_teleport_loginrule_v1_loginrule_service_proto = out.File
	file_teleport_loginrule_v1_loginrule_service_proto_rawDesc = nil
	file_teleport_loginrule_v1_loginrule_service_proto_goTypes = nil
	file_teleport_loginrule_v1_loginrule_service_proto_depIdxs = nil
}
