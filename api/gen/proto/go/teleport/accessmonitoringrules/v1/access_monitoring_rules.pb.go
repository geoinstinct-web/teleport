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
// 	protoc-gen-go v1.32.0
// 	protoc        (unknown)
// source: teleport/accessmonitoringrules/v1/access_monitoring_rules.proto

package accessmonitoringrulesv1

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

// AccessMonitoringRule represents an access monitoring rule resources.
type AccessMonitoringRule struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// header is the header for the resource.
	Header *v1.ResourceHeader `protobuf:"bytes,1,opt,name=header,proto3" json:"header,omitempty"`
	// kind is a resource kind
	Kind string `protobuf:"bytes,2,opt,name=kind,proto3" json:"kind,omitempty"`
	// sub_kind is an optional resource sub kind, used in some resources
	SubKind string `protobuf:"bytes,3,opt,name=sub_kind,json=subKind,proto3" json:"sub_kind,omitempty"`
	// version is version
	Version string `protobuf:"bytes,4,opt,name=version,proto3" json:"version,omitempty"`
	// Spec is an AccessMonitoringRule specification
	Spec *AccessMonitoringRuleSpec `protobuf:"bytes,5,opt,name=spec,proto3" json:"spec,omitempty"`
}

func (x *AccessMonitoringRule) Reset() {
	*x = AccessMonitoringRule{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccessMonitoringRule) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccessMonitoringRule) ProtoMessage() {}

func (x *AccessMonitoringRule) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccessMonitoringRule.ProtoReflect.Descriptor instead.
func (*AccessMonitoringRule) Descriptor() ([]byte, []int) {
	return file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDescGZIP(), []int{0}
}

func (x *AccessMonitoringRule) GetHeader() *v1.ResourceHeader {
	if x != nil {
		return x.Header
	}
	return nil
}

func (x *AccessMonitoringRule) GetKind() string {
	if x != nil {
		return x.Kind
	}
	return ""
}

func (x *AccessMonitoringRule) GetSubKind() string {
	if x != nil {
		return x.SubKind
	}
	return ""
}

func (x *AccessMonitoringRule) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *AccessMonitoringRule) GetSpec() *AccessMonitoringRuleSpec {
	if x != nil {
		return x.Spec
	}
	return nil
}

// AccessMonitoringRuleSpec is the access monitoring rule spec
type AccessMonitoringRuleSpec struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// subjects the rule operates on, can be a resource kind or a particular resource property.
	Subjects []string `protobuf:"bytes,1,rep,name=subjects,proto3" json:"subjects,omitempty"`
	// states are the desired state which the monitoring rule is attempting to bring the subjects matching the condition to.
	States []string `protobuf:"bytes,2,rep,name=states,proto3" json:"states,omitempty"`
	// condition is a predicate expression that operates on the specified subject resources,
	// and determines whether the subject will be moved into desired state.
	Condition string `protobuf:"bytes,3,opt,name=condition,proto3" json:"condition,omitempty"`
	// notification defines the plugin configuration for notifcations if rule is triggered.
	Notification *Notification `protobuf:"bytes,4,opt,name=notification,proto3" json:"notification,omitempty"`
}

func (x *AccessMonitoringRuleSpec) Reset() {
	*x = AccessMonitoringRuleSpec{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccessMonitoringRuleSpec) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccessMonitoringRuleSpec) ProtoMessage() {}

func (x *AccessMonitoringRuleSpec) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccessMonitoringRuleSpec.ProtoReflect.Descriptor instead.
func (*AccessMonitoringRuleSpec) Descriptor() ([]byte, []int) {
	return file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDescGZIP(), []int{1}
}

func (x *AccessMonitoringRuleSpec) GetSubjects() []string {
	if x != nil {
		return x.Subjects
	}
	return nil
}

func (x *AccessMonitoringRuleSpec) GetStates() []string {
	if x != nil {
		return x.States
	}
	return nil
}

func (x *AccessMonitoringRuleSpec) GetCondition() string {
	if x != nil {
		return x.Condition
	}
	return ""
}

func (x *AccessMonitoringRuleSpec) GetNotification() *Notification {
	if x != nil {
		return x.Notification
	}
	return nil
}

// Notification contains configurations for plugin notification rules.
type Notification struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// name is the name of the plugin to which this configuration should apply.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// recipients is the list of recipients the plugin should notify.
	Recipients []string `protobuf:"bytes,2,rep,name=recipients,proto3" json:"recipients,omitempty"`
}

func (x *Notification) Reset() {
	*x = Notification{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Notification) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Notification) ProtoMessage() {}

func (x *Notification) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Notification.ProtoReflect.Descriptor instead.
func (*Notification) Descriptor() ([]byte, []int) {
	return file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDescGZIP(), []int{2}
}

func (x *Notification) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Notification) GetRecipients() []string {
	if x != nil {
		return x.Recipients
	}
	return nil
}

// CreateAccessMonitoringRuleRequest is the request for CreateAccessMonitoringRule.
type CreateAccessMonitoringRuleRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// access_monitoring_rule is the specification of the rule to be created.
	AccessMonitoringRule *AccessMonitoringRule `protobuf:"bytes,1,opt,name=access_monitoring_rule,json=accessMonitoringRule,proto3" json:"access_monitoring_rule,omitempty"`
}

func (x *CreateAccessMonitoringRuleRequest) Reset() {
	*x = CreateAccessMonitoringRuleRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateAccessMonitoringRuleRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateAccessMonitoringRuleRequest) ProtoMessage() {}

func (x *CreateAccessMonitoringRuleRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateAccessMonitoringRuleRequest.ProtoReflect.Descriptor instead.
func (*CreateAccessMonitoringRuleRequest) Descriptor() ([]byte, []int) {
	return file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDescGZIP(), []int{3}
}

func (x *CreateAccessMonitoringRuleRequest) GetAccessMonitoringRule() *AccessMonitoringRule {
	if x != nil {
		return x.AccessMonitoringRule
	}
	return nil
}

// UpdateAccessMonitoringRuleRequest is the request for UpdateAccessMonitoringRule.
type UpdateAccessMonitoringRuleRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// access_monitoring_rule is the specification of the rule to be updated.
	AccessMonitoringRule *AccessMonitoringRule `protobuf:"bytes,1,opt,name=access_monitoring_rule,json=accessMonitoringRule,proto3" json:"access_monitoring_rule,omitempty"`
}

func (x *UpdateAccessMonitoringRuleRequest) Reset() {
	*x = UpdateAccessMonitoringRuleRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateAccessMonitoringRuleRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateAccessMonitoringRuleRequest) ProtoMessage() {}

func (x *UpdateAccessMonitoringRuleRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateAccessMonitoringRuleRequest.ProtoReflect.Descriptor instead.
func (*UpdateAccessMonitoringRuleRequest) Descriptor() ([]byte, []int) {
	return file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDescGZIP(), []int{4}
}

func (x *UpdateAccessMonitoringRuleRequest) GetAccessMonitoringRule() *AccessMonitoringRule {
	if x != nil {
		return x.AccessMonitoringRule
	}
	return nil
}

// UpsertAccessMonitoringRuleRequest is the request for UpsertAccessMonitoringRule.
type UpsertAccessMonitoringRuleRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// access_monitoring_rule is the specification of the rule to be upsertd.
	AccessMonitoringRule *AccessMonitoringRule `protobuf:"bytes,1,opt,name=access_monitoring_rule,json=accessMonitoringRule,proto3" json:"access_monitoring_rule,omitempty"`
}

func (x *UpsertAccessMonitoringRuleRequest) Reset() {
	*x = UpsertAccessMonitoringRuleRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpsertAccessMonitoringRuleRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpsertAccessMonitoringRuleRequest) ProtoMessage() {}

func (x *UpsertAccessMonitoringRuleRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpsertAccessMonitoringRuleRequest.ProtoReflect.Descriptor instead.
func (*UpsertAccessMonitoringRuleRequest) Descriptor() ([]byte, []int) {
	return file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDescGZIP(), []int{5}
}

func (x *UpsertAccessMonitoringRuleRequest) GetAccessMonitoringRule() *AccessMonitoringRule {
	if x != nil {
		return x.AccessMonitoringRule
	}
	return nil
}

// GetAccessMonitoringRuleRequest is the request for GetAccessMonitoringRule.
type GetAccessMonitoringRuleRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// resource_name is the name of the rule to be returned.
	ResourceName string `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
}

func (x *GetAccessMonitoringRuleRequest) Reset() {
	*x = GetAccessMonitoringRuleRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetAccessMonitoringRuleRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetAccessMonitoringRuleRequest) ProtoMessage() {}

func (x *GetAccessMonitoringRuleRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetAccessMonitoringRuleRequest.ProtoReflect.Descriptor instead.
func (*GetAccessMonitoringRuleRequest) Descriptor() ([]byte, []int) {
	return file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDescGZIP(), []int{6}
}

func (x *GetAccessMonitoringRuleRequest) GetResourceName() string {
	if x != nil {
		return x.ResourceName
	}
	return ""
}

// DeleteAccessMonitoringRuleRequest is the request for DeleteAccessMonitoringRule.
type DeleteAccessMonitoringRuleRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// resource_name is the name of the rule to be removed.
	ResourceName string `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
}

func (x *DeleteAccessMonitoringRuleRequest) Reset() {
	*x = DeleteAccessMonitoringRuleRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteAccessMonitoringRuleRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteAccessMonitoringRuleRequest) ProtoMessage() {}

func (x *DeleteAccessMonitoringRuleRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteAccessMonitoringRuleRequest.ProtoReflect.Descriptor instead.
func (*DeleteAccessMonitoringRuleRequest) Descriptor() ([]byte, []int) {
	return file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDescGZIP(), []int{7}
}

func (x *DeleteAccessMonitoringRuleRequest) GetResourceName() string {
	if x != nil {
		return x.ResourceName
	}
	return ""
}

// ListAccessMonitoringRulesResponse is the request for ListAccessMonitoringRules.
type ListAccessMonitoringRulesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// page_size is the maximum number of items to return.
	// The server may impose a different page size at its discretion.
	PageSize int64 `protobuf:"varint,1,opt,name=page_size,json=pageSize,proto3" json:"page_size,omitempty"`
	// page_token is the next_page_token value returned from a previous List request, if any.
	PageToken string `protobuf:"bytes,2,opt,name=page_token,json=pageToken,proto3" json:"page_token,omitempty"`
}

func (x *ListAccessMonitoringRulesRequest) Reset() {
	*x = ListAccessMonitoringRulesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListAccessMonitoringRulesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListAccessMonitoringRulesRequest) ProtoMessage() {}

func (x *ListAccessMonitoringRulesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListAccessMonitoringRulesRequest.ProtoReflect.Descriptor instead.
func (*ListAccessMonitoringRulesRequest) Descriptor() ([]byte, []int) {
	return file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDescGZIP(), []int{8}
}

func (x *ListAccessMonitoringRulesRequest) GetPageSize() int64 {
	if x != nil {
		return x.PageSize
	}
	return 0
}

func (x *ListAccessMonitoringRulesRequest) GetPageToken() string {
	if x != nil {
		return x.PageToken
	}
	return ""
}

// ListAccessMonitoringRulesResponse is the response from ListAccessMonitoringRules.
type ListAccessMonitoringRulesResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The page of AccessMonitoringRule that matched the request.
	AccessMonitoringRules []*AccessMonitoringRule `protobuf:"bytes,1,rep,name=access_monitoring_rules,json=accessMonitoringRules,proto3" json:"access_monitoring_rules,omitempty"`
	// Token to retrieve the next page of results, or empty if there are no
	// more results in the list.
	NextPageToken string `protobuf:"bytes,2,opt,name=next_page_token,json=nextPageToken,proto3" json:"next_page_token,omitempty"`
}

func (x *ListAccessMonitoringRulesResponse) Reset() {
	*x = ListAccessMonitoringRulesResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListAccessMonitoringRulesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListAccessMonitoringRulesResponse) ProtoMessage() {}

func (x *ListAccessMonitoringRulesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListAccessMonitoringRulesResponse.ProtoReflect.Descriptor instead.
func (*ListAccessMonitoringRulesResponse) Descriptor() ([]byte, []int) {
	return file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDescGZIP(), []int{9}
}

func (x *ListAccessMonitoringRulesResponse) GetAccessMonitoringRules() []*AccessMonitoringRule {
	if x != nil {
		return x.AccessMonitoringRules
	}
	return nil
}

func (x *ListAccessMonitoringRulesResponse) GetNextPageToken() string {
	if x != nil {
		return x.NextPageToken
	}
	return ""
}

var File_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto protoreflect.FileDescriptor

var file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDesc = []byte{
	0x0a, 0x3f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73,
	0x2f, 0x76, 0x31, 0x2f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x6d, 0x6f, 0x6e, 0x69, 0x74,
	0x6f, 0x72, 0x69, 0x6e, 0x67, 0x5f, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x21, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65,
	0x73, 0x2e, 0x76, 0x31, 0x1a, 0x27, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x68,
	0x65, 0x61, 0x64, 0x65, 0x72, 0x2f, 0x76, 0x31, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xec, 0x01,
	0x0a, 0x14, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69,
	0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x12, 0x3a, 0x0a, 0x06, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x52, 0x06, 0x68, 0x65, 0x61, 0x64,
	0x65, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x75, 0x62, 0x5f, 0x6b, 0x69,
	0x6e, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x75, 0x62, 0x4b, 0x69, 0x6e,
	0x64, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x4f, 0x0a, 0x04, 0x73,
	0x70, 0x65, 0x63, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x3b, 0x2e, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6d, 0x6f, 0x6e, 0x69, 0x74,
	0x6f, 0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x75,
	0x6c, 0x65, 0x53, 0x70, 0x65, 0x63, 0x52, 0x04, 0x73, 0x70, 0x65, 0x63, 0x22, 0xc1, 0x01, 0x0a,
	0x18, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e,
	0x67, 0x52, 0x75, 0x6c, 0x65, 0x53, 0x70, 0x65, 0x63, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x75, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x08, 0x73, 0x75, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x65, 0x73, 0x18,
	0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x65, 0x73, 0x12, 0x1c, 0x0a,
	0x09, 0x63, 0x6f, 0x6e, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x09, 0x63, 0x6f, 0x6e, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x53, 0x0a, 0x0c, 0x6e,
	0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x2f, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c,
	0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x52, 0x0c, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x22, 0x42, 0x0a, 0x0c, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x72, 0x65, 0x63, 0x69, 0x70, 0x69, 0x65, 0x6e,
	0x74, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0a, 0x72, 0x65, 0x63, 0x69, 0x70, 0x69,
	0x65, 0x6e, 0x74, 0x73, 0x22, 0x92, 0x01, 0x0a, 0x21, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x41,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52,
	0x75, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x6d, 0x0a, 0x16, 0x61, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x5f, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x5f,
	0x72, 0x75, 0x6c, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x37, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6d, 0x6f, 0x6e, 0x69,
	0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x41,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52,
	0x75, 0x6c, 0x65, 0x52, 0x14, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74,
	0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x22, 0x92, 0x01, 0x0a, 0x21, 0x55, 0x70,
	0x64, 0x61, 0x74, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f,
	0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x6d, 0x0a, 0x16, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f,
	0x72, 0x69, 0x6e, 0x67, 0x5f, 0x72, 0x75, 0x6c, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x37, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73,
	0x2e, 0x76, 0x31, 0x2e, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f,
	0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x14, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73,
	0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x22, 0x92,
	0x01, 0x0a, 0x21, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d,
	0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x6d, 0x0a, 0x16, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x6d,
	0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x5f, 0x72, 0x75, 0x6c, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x37, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e,
	0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67,
	0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d,
	0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x14, 0x61,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52,
	0x75, 0x6c, 0x65, 0x22, 0x45, 0x0a, 0x1e, 0x47, 0x65, 0x74, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73,
	0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x23, 0x0a, 0x0d, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x72, 0x65,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x22, 0x48, 0x0a, 0x21, 0x44, 0x65,
	0x6c, 0x65, 0x74, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f,
	0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x23, 0x0a, 0x0d, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x4e, 0x61, 0x6d, 0x65, 0x22, 0x5e, 0x0a, 0x20, 0x4c, 0x69, 0x73, 0x74, 0x41, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65,
	0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x70, 0x61, 0x67, 0x65,
	0x5f, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x08, 0x70, 0x61, 0x67,
	0x65, 0x53, 0x69, 0x7a, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x61, 0x67, 0x65, 0x5f, 0x74, 0x6f,
	0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x61, 0x67, 0x65, 0x54,
	0x6f, 0x6b, 0x65, 0x6e, 0x22, 0xbc, 0x01, 0x0a, 0x21, 0x4c, 0x69, 0x73, 0x74, 0x41, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c,
	0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x6f, 0x0a, 0x17, 0x61, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x5f, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x5f,
	0x72, 0x75, 0x6c, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x37, 0x2e, 0x74, 0x65,
	0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6d, 0x6f, 0x6e,
	0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e,
	0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67,
	0x52, 0x75, 0x6c, 0x65, 0x52, 0x15, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69,
	0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x73, 0x12, 0x26, 0x0a, 0x0f, 0x6e,
	0x65, 0x78, 0x74, 0x5f, 0x70, 0x61, 0x67, 0x65, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x6e, 0x65, 0x78, 0x74, 0x50, 0x61, 0x67, 0x65, 0x54, 0x6f,
	0x6b, 0x65, 0x6e, 0x42, 0x6e, 0x5a, 0x6c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x2f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72,
	0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x3b, 0x61, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65,
	0x73, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDescOnce sync.Once
	file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDescData = file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDesc
)

func file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDescGZIP() []byte {
	file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDescOnce.Do(func() {
		file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDescData)
	})
	return file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDescData
}

var file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_goTypes = []interface{}{
	(*AccessMonitoringRule)(nil),              // 0: teleport.accessmonitoringrules.v1.AccessMonitoringRule
	(*AccessMonitoringRuleSpec)(nil),          // 1: teleport.accessmonitoringrules.v1.AccessMonitoringRuleSpec
	(*Notification)(nil),                      // 2: teleport.accessmonitoringrules.v1.Notification
	(*CreateAccessMonitoringRuleRequest)(nil), // 3: teleport.accessmonitoringrules.v1.CreateAccessMonitoringRuleRequest
	(*UpdateAccessMonitoringRuleRequest)(nil), // 4: teleport.accessmonitoringrules.v1.UpdateAccessMonitoringRuleRequest
	(*UpsertAccessMonitoringRuleRequest)(nil), // 5: teleport.accessmonitoringrules.v1.UpsertAccessMonitoringRuleRequest
	(*GetAccessMonitoringRuleRequest)(nil),    // 6: teleport.accessmonitoringrules.v1.GetAccessMonitoringRuleRequest
	(*DeleteAccessMonitoringRuleRequest)(nil), // 7: teleport.accessmonitoringrules.v1.DeleteAccessMonitoringRuleRequest
	(*ListAccessMonitoringRulesRequest)(nil),  // 8: teleport.accessmonitoringrules.v1.ListAccessMonitoringRulesRequest
	(*ListAccessMonitoringRulesResponse)(nil), // 9: teleport.accessmonitoringrules.v1.ListAccessMonitoringRulesResponse
	(*v1.ResourceHeader)(nil),                 // 10: teleport.header.v1.ResourceHeader
}
var file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_depIdxs = []int32{
	10, // 0: teleport.accessmonitoringrules.v1.AccessMonitoringRule.header:type_name -> teleport.header.v1.ResourceHeader
	1,  // 1: teleport.accessmonitoringrules.v1.AccessMonitoringRule.spec:type_name -> teleport.accessmonitoringrules.v1.AccessMonitoringRuleSpec
	2,  // 2: teleport.accessmonitoringrules.v1.AccessMonitoringRuleSpec.notification:type_name -> teleport.accessmonitoringrules.v1.Notification
	0,  // 3: teleport.accessmonitoringrules.v1.CreateAccessMonitoringRuleRequest.access_monitoring_rule:type_name -> teleport.accessmonitoringrules.v1.AccessMonitoringRule
	0,  // 4: teleport.accessmonitoringrules.v1.UpdateAccessMonitoringRuleRequest.access_monitoring_rule:type_name -> teleport.accessmonitoringrules.v1.AccessMonitoringRule
	0,  // 5: teleport.accessmonitoringrules.v1.UpsertAccessMonitoringRuleRequest.access_monitoring_rule:type_name -> teleport.accessmonitoringrules.v1.AccessMonitoringRule
	0,  // 6: teleport.accessmonitoringrules.v1.ListAccessMonitoringRulesResponse.access_monitoring_rules:type_name -> teleport.accessmonitoringrules.v1.AccessMonitoringRule
	7,  // [7:7] is the sub-list for method output_type
	7,  // [7:7] is the sub-list for method input_type
	7,  // [7:7] is the sub-list for extension type_name
	7,  // [7:7] is the sub-list for extension extendee
	0,  // [0:7] is the sub-list for field type_name
}

func init() { file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_init() }
func file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_init() {
	if File_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccessMonitoringRule); i {
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
		file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccessMonitoringRuleSpec); i {
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
		file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Notification); i {
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
		file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateAccessMonitoringRuleRequest); i {
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
		file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateAccessMonitoringRuleRequest); i {
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
		file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpsertAccessMonitoringRuleRequest); i {
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
		file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetAccessMonitoringRuleRequest); i {
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
		file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteAccessMonitoringRuleRequest); i {
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
		file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListAccessMonitoringRulesRequest); i {
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
		file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListAccessMonitoringRulesResponse); i {
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
			RawDescriptor: file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_goTypes,
		DependencyIndexes: file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_depIdxs,
		MessageInfos:      file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_msgTypes,
	}.Build()
	File_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto = out.File
	file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_rawDesc = nil
	file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_goTypes = nil
	file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_depIdxs = nil
}
