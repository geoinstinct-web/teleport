// Copyright 2019 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.12.2
// source: google/iam/v1/policy.proto

package iam

import (
	reflect "reflect"
	sync "sync"

	_ "google.golang.org/genproto/googleapis/api/annotations"
	expr "google.golang.org/genproto/googleapis/type/expr"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// The type of action performed on a Binding in a policy.
type BindingDelta_Action int32

const (
	// Unspecified.
	BindingDelta_ACTION_UNSPECIFIED BindingDelta_Action = 0
	// Addition of a Binding.
	BindingDelta_ADD BindingDelta_Action = 1
	// Removal of a Binding.
	BindingDelta_REMOVE BindingDelta_Action = 2
)

// Enum value maps for BindingDelta_Action.
var (
	BindingDelta_Action_name = map[int32]string{
		0: "ACTION_UNSPECIFIED",
		1: "ADD",
		2: "REMOVE",
	}
	BindingDelta_Action_value = map[string]int32{
		"ACTION_UNSPECIFIED": 0,
		"ADD":                1,
		"REMOVE":             2,
	}
)

func (x BindingDelta_Action) Enum() *BindingDelta_Action {
	p := new(BindingDelta_Action)
	*p = x
	return p
}

func (x BindingDelta_Action) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (BindingDelta_Action) Descriptor() protoreflect.EnumDescriptor {
	return file_google_iam_v1_policy_proto_enumTypes[0].Descriptor()
}

func (BindingDelta_Action) Type() protoreflect.EnumType {
	return &file_google_iam_v1_policy_proto_enumTypes[0]
}

func (x BindingDelta_Action) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use BindingDelta_Action.Descriptor instead.
func (BindingDelta_Action) EnumDescriptor() ([]byte, []int) {
	return file_google_iam_v1_policy_proto_rawDescGZIP(), []int{3, 0}
}

// The type of action performed on an audit configuration in a policy.
type AuditConfigDelta_Action int32

const (
	// Unspecified.
	AuditConfigDelta_ACTION_UNSPECIFIED AuditConfigDelta_Action = 0
	// Addition of an audit configuration.
	AuditConfigDelta_ADD AuditConfigDelta_Action = 1
	// Removal of an audit configuration.
	AuditConfigDelta_REMOVE AuditConfigDelta_Action = 2
)

// Enum value maps for AuditConfigDelta_Action.
var (
	AuditConfigDelta_Action_name = map[int32]string{
		0: "ACTION_UNSPECIFIED",
		1: "ADD",
		2: "REMOVE",
	}
	AuditConfigDelta_Action_value = map[string]int32{
		"ACTION_UNSPECIFIED": 0,
		"ADD":                1,
		"REMOVE":             2,
	}
)

func (x AuditConfigDelta_Action) Enum() *AuditConfigDelta_Action {
	p := new(AuditConfigDelta_Action)
	*p = x
	return p
}

func (x AuditConfigDelta_Action) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (AuditConfigDelta_Action) Descriptor() protoreflect.EnumDescriptor {
	return file_google_iam_v1_policy_proto_enumTypes[1].Descriptor()
}

func (AuditConfigDelta_Action) Type() protoreflect.EnumType {
	return &file_google_iam_v1_policy_proto_enumTypes[1]
}

func (x AuditConfigDelta_Action) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use AuditConfigDelta_Action.Descriptor instead.
func (AuditConfigDelta_Action) EnumDescriptor() ([]byte, []int) {
	return file_google_iam_v1_policy_proto_rawDescGZIP(), []int{4, 0}
}

// Defines an Identity and Access Management (IAM) policy. It is used to
// specify access control policies for Cloud Platform resources.
//
//
// A `Policy` is a collection of `bindings`. A `binding` binds one or more
// `members` to a single `role`. Members can be user accounts, service accounts,
// Google groups, and domains (such as G Suite). A `role` is a named list of
// permissions (defined by IAM or configured by users). A `binding` can
// optionally specify a `condition`, which is a logic expression that further
// constrains the role binding based on attributes about the request and/or
// target resource.
//
// **JSON Example**
//
//     {
//       "bindings": [
//         {
//           "role": "roles/resourcemanager.organizationAdmin",
//           "members": [
//             "user:mike@example.com",
//             "group:admins@example.com",
//             "domain:google.com",
//             "serviceAccount:my-project-id@appspot.gserviceaccount.com"
//           ]
//         },
//         {
//           "role": "roles/resourcemanager.organizationViewer",
//           "members": ["user:eve@example.com"],
//           "condition": {
//             "title": "expirable access",
//             "description": "Does not grant access after Sep 2020",
//             "expression": "request.time <
//             timestamp('2020-10-01T00:00:00.000Z')",
//           }
//         }
//       ]
//     }
//
// **YAML Example**
//
//     bindings:
//     - members:
//       - user:mike@example.com
//       - group:admins@example.com
//       - domain:google.com
//       - serviceAccount:my-project-id@appspot.gserviceaccount.com
//       role: roles/resourcemanager.organizationAdmin
//     - members:
//       - user:eve@example.com
//       role: roles/resourcemanager.organizationViewer
//       condition:
//         title: expirable access
//         description: Does not grant access after Sep 2020
//         expression: request.time < timestamp('2020-10-01T00:00:00.000Z')
//
// For a description of IAM and its features, see the
// [IAM developer's guide](https://cloud.google.com/iam/docs).
type Policy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Specifies the format of the policy.
	//
	// Valid values are 0, 1, and 3. Requests specifying an invalid value will be
	// rejected.
	//
	// Operations affecting conditional bindings must specify version 3. This can
	// be either setting a conditional policy, modifying a conditional binding,
	// or removing a binding (conditional or unconditional) from the stored
	// conditional policy.
	// Operations on non-conditional policies may specify any valid value or
	// leave the field unset.
	//
	// If no etag is provided in the call to `setIamPolicy`, version compliance
	// checks against the stored policy is skipped.
	Version int32 `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	// Associates a list of `members` to a `role`. Optionally may specify a
	// `condition` that determines when binding is in effect.
	// `bindings` with no members will result in an error.
	Bindings []*Binding `protobuf:"bytes,4,rep,name=bindings,proto3" json:"bindings,omitempty"`
	// `etag` is used for optimistic concurrency control as a way to help
	// prevent simultaneous updates of a policy from overwriting each other.
	// It is strongly suggested that systems make use of the `etag` in the
	// read-modify-write cycle to perform policy updates in order to avoid race
	// conditions: An `etag` is returned in the response to `getIamPolicy`, and
	// systems are expected to put that etag in the request to `setIamPolicy` to
	// ensure that their change will be applied to the same version of the policy.
	//
	// If no `etag` is provided in the call to `setIamPolicy`, then the existing
	// policy is overwritten. Due to blind-set semantics of an etag-less policy,
	// 'setIamPolicy' will not fail even if the incoming policy version does not
	// meet the requirements for modifying the stored policy.
	Etag []byte `protobuf:"bytes,3,opt,name=etag,proto3" json:"etag,omitempty"`
}

func (x *Policy) Reset() {
	*x = Policy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_google_iam_v1_policy_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Policy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Policy) ProtoMessage() {}

func (x *Policy) ProtoReflect() protoreflect.Message {
	mi := &file_google_iam_v1_policy_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Policy.ProtoReflect.Descriptor instead.
func (*Policy) Descriptor() ([]byte, []int) {
	return file_google_iam_v1_policy_proto_rawDescGZIP(), []int{0}
}

func (x *Policy) GetVersion() int32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *Policy) GetBindings() []*Binding {
	if x != nil {
		return x.Bindings
	}
	return nil
}

func (x *Policy) GetEtag() []byte {
	if x != nil {
		return x.Etag
	}
	return nil
}

// Associates `members` with a `role`.
type Binding struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Role that is assigned to `members`.
	// For example, `roles/viewer`, `roles/editor`, or `roles/owner`.
	Role string `protobuf:"bytes,1,opt,name=role,proto3" json:"role,omitempty"`
	// Specifies the identities requesting access for a Cloud Platform resource.
	// `members` can have the following values:
	//
	// * `allUsers`: A special identifier that represents anyone who is
	//    on the internet; with or without a Google account.
	//
	// * `allAuthenticatedUsers`: A special identifier that represents anyone
	//    who is authenticated with a Google account or a service account.
	//
	// * `user:{emailid}`: An email address that represents a specific Google
	//    account. For example, `alice@example.com` .
	//
	//
	// * `serviceAccount:{emailid}`: An email address that represents a service
	//    account. For example, `my-other-app@appspot.gserviceaccount.com`.
	//
	// * `group:{emailid}`: An email address that represents a Google group.
	//    For example, `admins@example.com`.
	//
	//
	// * `domain:{domain}`: The G Suite domain (primary) that represents all the
	//    users of that domain. For example, `google.com` or `example.com`.
	//
	//
	Members []string `protobuf:"bytes,2,rep,name=members,proto3" json:"members,omitempty"`
	// The condition that is associated with this binding.
	// NOTE: An unsatisfied condition will not allow user access via current
	// binding. Different bindings, including their conditions, are examined
	// independently.
	Condition *expr.Expr `protobuf:"bytes,3,opt,name=condition,proto3" json:"condition,omitempty"`
}

func (x *Binding) Reset() {
	*x = Binding{}
	if protoimpl.UnsafeEnabled {
		mi := &file_google_iam_v1_policy_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Binding) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Binding) ProtoMessage() {}

func (x *Binding) ProtoReflect() protoreflect.Message {
	mi := &file_google_iam_v1_policy_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Binding.ProtoReflect.Descriptor instead.
func (*Binding) Descriptor() ([]byte, []int) {
	return file_google_iam_v1_policy_proto_rawDescGZIP(), []int{1}
}

func (x *Binding) GetRole() string {
	if x != nil {
		return x.Role
	}
	return ""
}

func (x *Binding) GetMembers() []string {
	if x != nil {
		return x.Members
	}
	return nil
}

func (x *Binding) GetCondition() *expr.Expr {
	if x != nil {
		return x.Condition
	}
	return nil
}

// The difference delta between two policies.
type PolicyDelta struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The delta for Bindings between two policies.
	BindingDeltas []*BindingDelta `protobuf:"bytes,1,rep,name=binding_deltas,json=bindingDeltas,proto3" json:"binding_deltas,omitempty"`
	// The delta for AuditConfigs between two policies.
	AuditConfigDeltas []*AuditConfigDelta `protobuf:"bytes,2,rep,name=audit_config_deltas,json=auditConfigDeltas,proto3" json:"audit_config_deltas,omitempty"`
}

func (x *PolicyDelta) Reset() {
	*x = PolicyDelta{}
	if protoimpl.UnsafeEnabled {
		mi := &file_google_iam_v1_policy_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PolicyDelta) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PolicyDelta) ProtoMessage() {}

func (x *PolicyDelta) ProtoReflect() protoreflect.Message {
	mi := &file_google_iam_v1_policy_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PolicyDelta.ProtoReflect.Descriptor instead.
func (*PolicyDelta) Descriptor() ([]byte, []int) {
	return file_google_iam_v1_policy_proto_rawDescGZIP(), []int{2}
}

func (x *PolicyDelta) GetBindingDeltas() []*BindingDelta {
	if x != nil {
		return x.BindingDeltas
	}
	return nil
}

func (x *PolicyDelta) GetAuditConfigDeltas() []*AuditConfigDelta {
	if x != nil {
		return x.AuditConfigDeltas
	}
	return nil
}

// One delta entry for Binding. Each individual change (only one member in each
// entry) to a binding will be a separate entry.
type BindingDelta struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The action that was performed on a Binding.
	// Required
	Action BindingDelta_Action `protobuf:"varint,1,opt,name=action,proto3,enum=google.iam.v1.BindingDelta_Action" json:"action,omitempty"`
	// Role that is assigned to `members`.
	// For example, `roles/viewer`, `roles/editor`, or `roles/owner`.
	// Required
	Role string `protobuf:"bytes,2,opt,name=role,proto3" json:"role,omitempty"`
	// A single identity requesting access for a Cloud Platform resource.
	// Follows the same format of Binding.members.
	// Required
	Member string `protobuf:"bytes,3,opt,name=member,proto3" json:"member,omitempty"`
	// The condition that is associated with this binding.
	Condition *expr.Expr `protobuf:"bytes,4,opt,name=condition,proto3" json:"condition,omitempty"`
}

func (x *BindingDelta) Reset() {
	*x = BindingDelta{}
	if protoimpl.UnsafeEnabled {
		mi := &file_google_iam_v1_policy_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BindingDelta) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BindingDelta) ProtoMessage() {}

func (x *BindingDelta) ProtoReflect() protoreflect.Message {
	mi := &file_google_iam_v1_policy_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BindingDelta.ProtoReflect.Descriptor instead.
func (*BindingDelta) Descriptor() ([]byte, []int) {
	return file_google_iam_v1_policy_proto_rawDescGZIP(), []int{3}
}

func (x *BindingDelta) GetAction() BindingDelta_Action {
	if x != nil {
		return x.Action
	}
	return BindingDelta_ACTION_UNSPECIFIED
}

func (x *BindingDelta) GetRole() string {
	if x != nil {
		return x.Role
	}
	return ""
}

func (x *BindingDelta) GetMember() string {
	if x != nil {
		return x.Member
	}
	return ""
}

func (x *BindingDelta) GetCondition() *expr.Expr {
	if x != nil {
		return x.Condition
	}
	return nil
}

// One delta entry for AuditConfig. Each individual change (only one
// exempted_member in each entry) to a AuditConfig will be a separate entry.
type AuditConfigDelta struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The action that was performed on an audit configuration in a policy.
	// Required
	Action AuditConfigDelta_Action `protobuf:"varint,1,opt,name=action,proto3,enum=google.iam.v1.AuditConfigDelta_Action" json:"action,omitempty"`
	// Specifies a service that was configured for Cloud Audit Logging.
	// For example, `storage.googleapis.com`, `cloudsql.googleapis.com`.
	// `allServices` is a special value that covers all services.
	// Required
	Service string `protobuf:"bytes,2,opt,name=service,proto3" json:"service,omitempty"`
	// A single identity that is exempted from "data access" audit
	// logging for the `service` specified above.
	// Follows the same format of Binding.members.
	ExemptedMember string `protobuf:"bytes,3,opt,name=exempted_member,json=exemptedMember,proto3" json:"exempted_member,omitempty"`
	// Specifies the log_type that was be enabled. ADMIN_ACTIVITY is always
	// enabled, and cannot be configured.
	// Required
	LogType string `protobuf:"bytes,4,opt,name=log_type,json=logType,proto3" json:"log_type,omitempty"`
}

func (x *AuditConfigDelta) Reset() {
	*x = AuditConfigDelta{}
	if protoimpl.UnsafeEnabled {
		mi := &file_google_iam_v1_policy_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuditConfigDelta) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuditConfigDelta) ProtoMessage() {}

func (x *AuditConfigDelta) ProtoReflect() protoreflect.Message {
	mi := &file_google_iam_v1_policy_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuditConfigDelta.ProtoReflect.Descriptor instead.
func (*AuditConfigDelta) Descriptor() ([]byte, []int) {
	return file_google_iam_v1_policy_proto_rawDescGZIP(), []int{4}
}

func (x *AuditConfigDelta) GetAction() AuditConfigDelta_Action {
	if x != nil {
		return x.Action
	}
	return AuditConfigDelta_ACTION_UNSPECIFIED
}

func (x *AuditConfigDelta) GetService() string {
	if x != nil {
		return x.Service
	}
	return ""
}

func (x *AuditConfigDelta) GetExemptedMember() string {
	if x != nil {
		return x.ExemptedMember
	}
	return ""
}

func (x *AuditConfigDelta) GetLogType() string {
	if x != nil {
		return x.LogType
	}
	return ""
}

var File_google_iam_v1_policy_proto protoreflect.FileDescriptor

var file_google_iam_v1_policy_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x69, 0x61, 0x6d, 0x2f, 0x76, 0x31, 0x2f,
	0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0d, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x69, 0x61, 0x6d, 0x2e, 0x76, 0x31, 0x1a, 0x16, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x2f, 0x65, 0x78, 0x70, 0x72, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f,
	0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0x6a, 0x0a, 0x06, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x18, 0x0a, 0x07, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x07, 0x76, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x32, 0x0a, 0x08, 0x62, 0x69, 0x6e, 0x64, 0x69, 0x6e, 0x67,
	0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x69, 0x61, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x42, 0x69, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x52,
	0x08, 0x62, 0x69, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x65, 0x74, 0x61,
	0x67, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x65, 0x74, 0x61, 0x67, 0x22, 0x68, 0x0a,
	0x07, 0x42, 0x69, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x12, 0x12, 0x0a, 0x04, 0x72, 0x6f, 0x6c, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x72, 0x6f, 0x6c, 0x65, 0x12, 0x18, 0x0a, 0x07,
	0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x07, 0x6d,
	0x65, 0x6d, 0x62, 0x65, 0x72, 0x73, 0x12, 0x2f, 0x0a, 0x09, 0x63, 0x6f, 0x6e, 0x64, 0x69, 0x74,
	0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x45, 0x78, 0x70, 0x72, 0x52, 0x09, 0x63, 0x6f,
	0x6e, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0xa2, 0x01, 0x0a, 0x0b, 0x50, 0x6f, 0x6c, 0x69,
	0x63, 0x79, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x12, 0x42, 0x0a, 0x0e, 0x62, 0x69, 0x6e, 0x64, 0x69,
	0x6e, 0x67, 0x5f, 0x64, 0x65, 0x6c, 0x74, 0x61, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x1b, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x69, 0x61, 0x6d, 0x2e, 0x76, 0x31, 0x2e,
	0x42, 0x69, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x52, 0x0d, 0x62, 0x69,
	0x6e, 0x64, 0x69, 0x6e, 0x67, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x73, 0x12, 0x4f, 0x0a, 0x13, 0x61,
	0x75, 0x64, 0x69, 0x74, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f, 0x64, 0x65, 0x6c, 0x74,
	0x61, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x69, 0x61, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x75, 0x64, 0x69, 0x74, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x52, 0x11, 0x61, 0x75, 0x64, 0x69, 0x74,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x73, 0x22, 0xde, 0x01, 0x0a,
	0x0c, 0x42, 0x69, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x12, 0x3a, 0x0a,
	0x06, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x22, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x69, 0x61, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x42, 0x69,
	0x6e, 0x64, 0x69, 0x6e, 0x67, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x2e, 0x41, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x52, 0x06, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x72, 0x6f, 0x6c,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x72, 0x6f, 0x6c, 0x65, 0x12, 0x16, 0x0a,
	0x06, 0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x6d,
	0x65, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x2f, 0x0a, 0x09, 0x63, 0x6f, 0x6e, 0x64, 0x69, 0x74, 0x69,
	0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x45, 0x78, 0x70, 0x72, 0x52, 0x09, 0x63, 0x6f, 0x6e,
	0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x35, 0x0a, 0x06, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x12, 0x16, 0x0a, 0x12, 0x41, 0x43, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45,
	0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x07, 0x0a, 0x03, 0x41, 0x44, 0x44, 0x10,
	0x01, 0x12, 0x0a, 0x0a, 0x06, 0x52, 0x45, 0x4d, 0x4f, 0x56, 0x45, 0x10, 0x02, 0x22, 0xe7, 0x01,
	0x0a, 0x10, 0x41, 0x75, 0x64, 0x69, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x44, 0x65, 0x6c,
	0x74, 0x61, 0x12, 0x3e, 0x0a, 0x06, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0e, 0x32, 0x26, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x69, 0x61, 0x6d, 0x2e,
	0x76, 0x31, 0x2e, 0x41, 0x75, 0x64, 0x69, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x44, 0x65,
	0x6c, 0x74, 0x61, 0x2e, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x06, 0x61, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x12, 0x18, 0x0a, 0x07, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x27, 0x0a, 0x0f,
	0x65, 0x78, 0x65, 0x6d, 0x70, 0x74, 0x65, 0x64, 0x5f, 0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x65, 0x78, 0x65, 0x6d, 0x70, 0x74, 0x65, 0x64, 0x4d,
	0x65, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x19, 0x0a, 0x08, 0x6c, 0x6f, 0x67, 0x5f, 0x74, 0x79, 0x70,
	0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6c, 0x6f, 0x67, 0x54, 0x79, 0x70, 0x65,
	0x22, 0x35, 0x0a, 0x06, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x16, 0x0a, 0x12, 0x41, 0x43,
	0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44,
	0x10, 0x00, 0x12, 0x07, 0x0a, 0x03, 0x41, 0x44, 0x44, 0x10, 0x01, 0x12, 0x0a, 0x0a, 0x06, 0x52,
	0x45, 0x4d, 0x4f, 0x56, 0x45, 0x10, 0x02, 0x42, 0x83, 0x01, 0x0a, 0x11, 0x63, 0x6f, 0x6d, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x69, 0x61, 0x6d, 0x2e, 0x76, 0x31, 0x42, 0x0b, 0x50,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x30, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x67, 0x6f, 0x6c, 0x61, 0x6e, 0x67, 0x2e, 0x6f, 0x72, 0x67, 0x2f,
	0x67, 0x65, 0x6e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x61,
	0x70, 0x69, 0x73, 0x2f, 0x69, 0x61, 0x6d, 0x2f, 0x76, 0x31, 0x3b, 0x69, 0x61, 0x6d, 0xf8, 0x01,
	0x01, 0xaa, 0x02, 0x13, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x43, 0x6c, 0x6f, 0x75, 0x64,
	0x2e, 0x49, 0x61, 0x6d, 0x2e, 0x56, 0x31, 0xca, 0x02, 0x13, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x5c, 0x43, 0x6c, 0x6f, 0x75, 0x64, 0x5c, 0x49, 0x61, 0x6d, 0x5c, 0x56, 0x31, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_google_iam_v1_policy_proto_rawDescOnce sync.Once
	file_google_iam_v1_policy_proto_rawDescData = file_google_iam_v1_policy_proto_rawDesc
)

func file_google_iam_v1_policy_proto_rawDescGZIP() []byte {
	file_google_iam_v1_policy_proto_rawDescOnce.Do(func() {
		file_google_iam_v1_policy_proto_rawDescData = protoimpl.X.CompressGZIP(file_google_iam_v1_policy_proto_rawDescData)
	})
	return file_google_iam_v1_policy_proto_rawDescData
}

var file_google_iam_v1_policy_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_google_iam_v1_policy_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_google_iam_v1_policy_proto_goTypes = []interface{}{
	(BindingDelta_Action)(0),     // 0: google.iam.v1.BindingDelta.Action
	(AuditConfigDelta_Action)(0), // 1: google.iam.v1.AuditConfigDelta.Action
	(*Policy)(nil),               // 2: google.iam.v1.Policy
	(*Binding)(nil),              // 3: google.iam.v1.Binding
	(*PolicyDelta)(nil),          // 4: google.iam.v1.PolicyDelta
	(*BindingDelta)(nil),         // 5: google.iam.v1.BindingDelta
	(*AuditConfigDelta)(nil),     // 6: google.iam.v1.AuditConfigDelta
	(*expr.Expr)(nil),            // 7: google.type.Expr
}
var file_google_iam_v1_policy_proto_depIdxs = []int32{
	3, // 0: google.iam.v1.Policy.bindings:type_name -> google.iam.v1.Binding
	7, // 1: google.iam.v1.Binding.condition:type_name -> google.type.Expr
	5, // 2: google.iam.v1.PolicyDelta.binding_deltas:type_name -> google.iam.v1.BindingDelta
	6, // 3: google.iam.v1.PolicyDelta.audit_config_deltas:type_name -> google.iam.v1.AuditConfigDelta
	0, // 4: google.iam.v1.BindingDelta.action:type_name -> google.iam.v1.BindingDelta.Action
	7, // 5: google.iam.v1.BindingDelta.condition:type_name -> google.type.Expr
	1, // 6: google.iam.v1.AuditConfigDelta.action:type_name -> google.iam.v1.AuditConfigDelta.Action
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_google_iam_v1_policy_proto_init() }
func file_google_iam_v1_policy_proto_init() {
	if File_google_iam_v1_policy_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_google_iam_v1_policy_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Policy); i {
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
		file_google_iam_v1_policy_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Binding); i {
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
		file_google_iam_v1_policy_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PolicyDelta); i {
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
		file_google_iam_v1_policy_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BindingDelta); i {
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
		file_google_iam_v1_policy_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuditConfigDelta); i {
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
			RawDescriptor: file_google_iam_v1_policy_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_google_iam_v1_policy_proto_goTypes,
		DependencyIndexes: file_google_iam_v1_policy_proto_depIdxs,
		EnumInfos:         file_google_iam_v1_policy_proto_enumTypes,
		MessageInfos:      file_google_iam_v1_policy_proto_msgTypes,
	}.Build()
	File_google_iam_v1_policy_proto = out.File
	file_google_iam_v1_policy_proto_rawDesc = nil
	file_google_iam_v1_policy_proto_goTypes = nil
	file_google_iam_v1_policy_proto_depIdxs = nil
}
