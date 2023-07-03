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
// 	protoc-gen-go v1.30.0
// 	protoc        (unknown)
// source: teleport/accesslist/v1/accesslist.proto

package accesslist

import (
	v1 "github.com/gravitational/teleport/api/gen/proto/go/common/v1"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// AccessList describes the basic building block of access grants, which are
// similar to access requests but for longer lived permissions that need to be
// regularly audited.
type AccessList struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// header is the header for the resource.
	Header *v1.ResourceHeader `protobuf:"bytes,1,opt,name=header,proto3" json:"header,omitempty"`
	// spec is the specification for the access list.
	Spec *AccessListSpec `protobuf:"bytes,2,opt,name=spec,proto3" json:"spec,omitempty"`
}

func (x *AccessList) Reset() {
	*x = AccessList{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_accesslist_v1_accesslist_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccessList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccessList) ProtoMessage() {}

func (x *AccessList) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_accesslist_v1_accesslist_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccessList.ProtoReflect.Descriptor instead.
func (*AccessList) Descriptor() ([]byte, []int) {
	return file_teleport_accesslist_v1_accesslist_proto_rawDescGZIP(), []int{0}
}

func (x *AccessList) GetHeader() *v1.ResourceHeader {
	if x != nil {
		return x.Header
	}
	return nil
}

func (x *AccessList) GetSpec() *AccessListSpec {
	if x != nil {
		return x.Spec
	}
	return nil
}

// AccessListSpec is the specification for an access list.
type AccessListSpec struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// description is a plaintext description of the access list.
	Description string `protobuf:"bytes,1,opt,name=description,proto3" json:"description,omitempty"`
	// owners is a list of owners of the access list.
	Owners []*AccessListOwner `protobuf:"bytes,2,rep,name=owners,proto3" json:"owners,omitempty"`
	// audit describes the frequency that this access list must be audited.
	Audit *AccessListAudit `protobuf:"bytes,3,opt,name=audit,proto3" json:"audit,omitempty"`
	// membership_requires describes the requirements for a user to be a member of the access list.
	// For a membership to an access list to be effective, the user must meet the requirements of
	// Membership_requires and must be in the members list.
	MembershipRequires *AccessListRequires `protobuf:"bytes,4,opt,name=membership_requires,json=membershipRequires,proto3" json:"membership_requires,omitempty"`
	// ownership_requires describes the requirements for a user to be an owner of the access list.
	// For ownership of an access list to be effective, the user must meet the requirements of
	// ownership_requires and must be in the owners list.
	OwnershipRequires *AccessListRequires `protobuf:"bytes,5,opt,name=ownership_requires,json=ownershipRequires,proto3" json:"ownership_requires,omitempty"`
	// grants describes the access granted by membership to this access list.
	Grants *AccessListGrants `protobuf:"bytes,6,opt,name=grants,proto3" json:"grants,omitempty"`
	// members describes the current members of the access list.
	Members []*AccessListMember `protobuf:"bytes,7,rep,name=members,proto3" json:"members,omitempty"`
}

func (x *AccessListSpec) Reset() {
	*x = AccessListSpec{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_accesslist_v1_accesslist_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccessListSpec) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccessListSpec) ProtoMessage() {}

func (x *AccessListSpec) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_accesslist_v1_accesslist_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccessListSpec.ProtoReflect.Descriptor instead.
func (*AccessListSpec) Descriptor() ([]byte, []int) {
	return file_teleport_accesslist_v1_accesslist_proto_rawDescGZIP(), []int{1}
}

func (x *AccessListSpec) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *AccessListSpec) GetOwners() []*AccessListOwner {
	if x != nil {
		return x.Owners
	}
	return nil
}

func (x *AccessListSpec) GetAudit() *AccessListAudit {
	if x != nil {
		return x.Audit
	}
	return nil
}

func (x *AccessListSpec) GetMembershipRequires() *AccessListRequires {
	if x != nil {
		return x.MembershipRequires
	}
	return nil
}

func (x *AccessListSpec) GetOwnershipRequires() *AccessListRequires {
	if x != nil {
		return x.OwnershipRequires
	}
	return nil
}

func (x *AccessListSpec) GetGrants() *AccessListGrants {
	if x != nil {
		return x.Grants
	}
	return nil
}

func (x *AccessListSpec) GetMembers() []*AccessListMember {
	if x != nil {
		return x.Members
	}
	return nil
}

// AccessListOwner is an owner of an access list.
type AccessListOwner struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// name is the username of the owner.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// description is the plaintext description of the owner and why they are an owner.
	Description string `protobuf:"bytes,2,opt,name=description,proto3" json:"description,omitempty"`
}

func (x *AccessListOwner) Reset() {
	*x = AccessListOwner{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_accesslist_v1_accesslist_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccessListOwner) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccessListOwner) ProtoMessage() {}

func (x *AccessListOwner) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_accesslist_v1_accesslist_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccessListOwner.ProtoReflect.Descriptor instead.
func (*AccessListOwner) Descriptor() ([]byte, []int) {
	return file_teleport_accesslist_v1_accesslist_proto_rawDescGZIP(), []int{2}
}

func (x *AccessListOwner) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *AccessListOwner) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

// AccessListAudit describes the audit configuration for an access list.
type AccessListAudit struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// frequency is a duration that describes how often an access list must be audited.
	Frequency *durationpb.Duration `protobuf:"bytes,1,opt,name=frequency,proto3" json:"frequency,omitempty"`
}

func (x *AccessListAudit) Reset() {
	*x = AccessListAudit{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_accesslist_v1_accesslist_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccessListAudit) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccessListAudit) ProtoMessage() {}

func (x *AccessListAudit) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_accesslist_v1_accesslist_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccessListAudit.ProtoReflect.Descriptor instead.
func (*AccessListAudit) Descriptor() ([]byte, []int) {
	return file_teleport_accesslist_v1_accesslist_proto_rawDescGZIP(), []int{3}
}

func (x *AccessListAudit) GetFrequency() *durationpb.Duration {
	if x != nil {
		return x.Frequency
	}
	return nil
}

// AccessListRequires describes a requirement section for an access list. A user must
// meet the following criteria to obtain the specific access to the list.
type AccessListRequires struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// roles are the user roles that must be present for the user to obtain access.
	Roles []string `protobuf:"bytes,1,rep,name=roles,proto3" json:"roles,omitempty"`
	// traits are the traits that must be present for the user to obtain access.
	Traits []*v1.Trait `protobuf:"bytes,2,rep,name=traits,proto3" json:"traits,omitempty"`
}

func (x *AccessListRequires) Reset() {
	*x = AccessListRequires{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_accesslist_v1_accesslist_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccessListRequires) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccessListRequires) ProtoMessage() {}

func (x *AccessListRequires) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_accesslist_v1_accesslist_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccessListRequires.ProtoReflect.Descriptor instead.
func (*AccessListRequires) Descriptor() ([]byte, []int) {
	return file_teleport_accesslist_v1_accesslist_proto_rawDescGZIP(), []int{4}
}

func (x *AccessListRequires) GetRoles() []string {
	if x != nil {
		return x.Roles
	}
	return nil
}

func (x *AccessListRequires) GetTraits() []*v1.Trait {
	if x != nil {
		return x.Traits
	}
	return nil
}

// AccessListGrants describes what access is granted by membership to the access list.
type AccessListGrants struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// roles are the roles that are granted to users who are members of the access list.
	Roles []string `protobuf:"bytes,1,rep,name=roles,proto3" json:"roles,omitempty"`
	// traits are the traits that are granted to users who are members of the access list.
	Traits []*v1.Trait `protobuf:"bytes,2,rep,name=traits,proto3" json:"traits,omitempty"`
}

func (x *AccessListGrants) Reset() {
	*x = AccessListGrants{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_accesslist_v1_accesslist_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccessListGrants) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccessListGrants) ProtoMessage() {}

func (x *AccessListGrants) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_accesslist_v1_accesslist_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccessListGrants.ProtoReflect.Descriptor instead.
func (*AccessListGrants) Descriptor() ([]byte, []int) {
	return file_teleport_accesslist_v1_accesslist_proto_rawDescGZIP(), []int{5}
}

func (x *AccessListGrants) GetRoles() []string {
	if x != nil {
		return x.Roles
	}
	return nil
}

func (x *AccessListGrants) GetTraits() []*v1.Trait {
	if x != nil {
		return x.Traits
	}
	return nil
}

// AccessListMember describes a member of an access list.
type AccessListMember struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// name is the name of the member of the access list.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// joined is when the user joined the access list.
	Joined *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=joined,proto3" json:"joined,omitempty"`
	// expires is when the user's membership to the access list expires.
	Expires *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=expires,proto3" json:"expires,omitempty"`
	// reason is the reason this user was added to the access list.
	Reason string `protobuf:"bytes,4,opt,name=reason,proto3" json:"reason,omitempty"`
	// added_by is the user that added this user to the access list.
	AddedBy string `protobuf:"bytes,5,opt,name=added_by,json=addedBy,proto3" json:"added_by,omitempty"`
}

func (x *AccessListMember) Reset() {
	*x = AccessListMember{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_accesslist_v1_accesslist_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccessListMember) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccessListMember) ProtoMessage() {}

func (x *AccessListMember) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_accesslist_v1_accesslist_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccessListMember.ProtoReflect.Descriptor instead.
func (*AccessListMember) Descriptor() ([]byte, []int) {
	return file_teleport_accesslist_v1_accesslist_proto_rawDescGZIP(), []int{6}
}

func (x *AccessListMember) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *AccessListMember) GetJoined() *timestamppb.Timestamp {
	if x != nil {
		return x.Joined
	}
	return nil
}

func (x *AccessListMember) GetExpires() *timestamppb.Timestamp {
	if x != nil {
		return x.Expires
	}
	return nil
}

func (x *AccessListMember) GetReason() string {
	if x != nil {
		return x.Reason
	}
	return ""
}

func (x *AccessListMember) GetAddedBy() string {
	if x != nil {
		return x.AddedBy
	}
	return ""
}

var File_teleport_accesslist_v1_accesslist_proto protoreflect.FileDescriptor

var file_teleport_accesslist_v1_accesslist_proto_rawDesc = []byte{
	0x0a, 0x27, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x6c, 0x69, 0x73, 0x74, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6c,
	0x69, 0x73, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x16, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6c, 0x69, 0x73, 0x74, 0x2e, 0x76,
	0x31, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2f, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x27, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x63, 0x6f, 0x6d,
	0x6d, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x68,
	0x65, 0x61, 0x64, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x2f,
	0x74, 0x72, 0x61, 0x69, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x84, 0x01, 0x0a, 0x0a,
	0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x3a, 0x0a, 0x06, 0x68, 0x65,
	0x61, 0x64, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e,
	0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x52, 0x06,
	0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x3a, 0x0a, 0x04, 0x73, 0x70, 0x65, 0x63, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x26, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e,
	0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6c, 0x69, 0x73, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x53, 0x70, 0x65, 0x63, 0x52, 0x04, 0x73, 0x70,
	0x65, 0x63, 0x22, 0xf0, 0x03, 0x0a, 0x0e, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c, 0x69, 0x73,
	0x74, 0x53, 0x70, 0x65, 0x63, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x3f, 0x0a, 0x06, 0x6f, 0x77, 0x6e, 0x65, 0x72,
	0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6c, 0x69, 0x73, 0x74, 0x2e, 0x76, 0x31,
	0x2e, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x4f, 0x77, 0x6e, 0x65, 0x72,
	0x52, 0x06, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x73, 0x12, 0x3d, 0x0a, 0x05, 0x61, 0x75, 0x64, 0x69,
	0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6c, 0x69, 0x73, 0x74, 0x2e, 0x76, 0x31,
	0x2e, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x41, 0x75, 0x64, 0x69, 0x74,
	0x52, 0x05, 0x61, 0x75, 0x64, 0x69, 0x74, 0x12, 0x5b, 0x0a, 0x13, 0x6d, 0x65, 0x6d, 0x62, 0x65,
	0x72, 0x73, 0x68, 0x69, 0x70, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x73, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e,
	0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6c, 0x69, 0x73, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x73,
	0x52, 0x12, 0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x73, 0x68, 0x69, 0x70, 0x52, 0x65, 0x71, 0x75,
	0x69, 0x72, 0x65, 0x73, 0x12, 0x59, 0x0a, 0x12, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x73, 0x68, 0x69,
	0x70, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x2a, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x6c, 0x69, 0x73, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73,
	0x4c, 0x69, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x73, 0x52, 0x11, 0x6f, 0x77,
	0x6e, 0x65, 0x72, 0x73, 0x68, 0x69, 0x70, 0x52, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x73, 0x12,
	0x40, 0x0a, 0x06, 0x67, 0x72, 0x61, 0x6e, 0x74, 0x73, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x28, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x6c, 0x69, 0x73, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c,
	0x69, 0x73, 0x74, 0x47, 0x72, 0x61, 0x6e, 0x74, 0x73, 0x52, 0x06, 0x67, 0x72, 0x61, 0x6e, 0x74,
	0x73, 0x12, 0x42, 0x0a, 0x07, 0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x73, 0x18, 0x07, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x28, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x6c, 0x69, 0x73, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x52, 0x07, 0x6d, 0x65,
	0x6d, 0x62, 0x65, 0x72, 0x73, 0x22, 0x47, 0x0a, 0x0f, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c,
	0x69, 0x73, 0x74, 0x4f, 0x77, 0x6e, 0x65, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b,
	0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x4a,
	0x0a, 0x0f, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x41, 0x75, 0x64, 0x69,
	0x74, 0x12, 0x37, 0x0a, 0x09, 0x66, 0x72, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52,
	0x09, 0x66, 0x72, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x79, 0x22, 0x5d, 0x0a, 0x12, 0x41, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x73,
	0x12, 0x14, 0x0a, 0x05, 0x72, 0x6f, 0x6c, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x05, 0x72, 0x6f, 0x6c, 0x65, 0x73, 0x12, 0x31, 0x0a, 0x06, 0x74, 0x72, 0x61, 0x69, 0x74, 0x73,
	0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x72, 0x61, 0x69,
	0x74, 0x52, 0x06, 0x74, 0x72, 0x61, 0x69, 0x74, 0x73, 0x22, 0x5b, 0x0a, 0x10, 0x41, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x47, 0x72, 0x61, 0x6e, 0x74, 0x73, 0x12, 0x14, 0x0a,
	0x05, 0x72, 0x6f, 0x6c, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x05, 0x72, 0x6f,
	0x6c, 0x65, 0x73, 0x12, 0x31, 0x0a, 0x06, 0x74, 0x72, 0x61, 0x69, 0x74, 0x73, 0x18, 0x02, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x63,
	0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x72, 0x61, 0x69, 0x74, 0x52, 0x06,
	0x74, 0x72, 0x61, 0x69, 0x74, 0x73, 0x22, 0xc3, 0x01, 0x0a, 0x10, 0x41, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x4c, 0x69, 0x73, 0x74, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12,
	0x32, 0x0a, 0x06, 0x6a, 0x6f, 0x69, 0x6e, 0x65, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x06, 0x6a, 0x6f, 0x69,
	0x6e, 0x65, 0x64, 0x12, 0x34, 0x0a, 0x07, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x52, 0x07, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x61,
	0x73, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x72, 0x65, 0x61, 0x73, 0x6f,
	0x6e, 0x12, 0x19, 0x0a, 0x08, 0x61, 0x64, 0x64, 0x65, 0x64, 0x5f, 0x62, 0x79, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x61, 0x64, 0x64, 0x65, 0x64, 0x42, 0x79, 0x42, 0x4d, 0x5a, 0x4b,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69,
	0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x67, 0x6f, 0x2f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6c, 0x69, 0x73, 0x74, 0x2f, 0x76, 0x31,
	0x3b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6c, 0x69, 0x73, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_teleport_accesslist_v1_accesslist_proto_rawDescOnce sync.Once
	file_teleport_accesslist_v1_accesslist_proto_rawDescData = file_teleport_accesslist_v1_accesslist_proto_rawDesc
)

func file_teleport_accesslist_v1_accesslist_proto_rawDescGZIP() []byte {
	file_teleport_accesslist_v1_accesslist_proto_rawDescOnce.Do(func() {
		file_teleport_accesslist_v1_accesslist_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_accesslist_v1_accesslist_proto_rawDescData)
	})
	return file_teleport_accesslist_v1_accesslist_proto_rawDescData
}

var file_teleport_accesslist_v1_accesslist_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_teleport_accesslist_v1_accesslist_proto_goTypes = []interface{}{
	(*AccessList)(nil),            // 0: teleport.accesslist.v1.AccessList
	(*AccessListSpec)(nil),        // 1: teleport.accesslist.v1.AccessListSpec
	(*AccessListOwner)(nil),       // 2: teleport.accesslist.v1.AccessListOwner
	(*AccessListAudit)(nil),       // 3: teleport.accesslist.v1.AccessListAudit
	(*AccessListRequires)(nil),    // 4: teleport.accesslist.v1.AccessListRequires
	(*AccessListGrants)(nil),      // 5: teleport.accesslist.v1.AccessListGrants
	(*AccessListMember)(nil),      // 6: teleport.accesslist.v1.AccessListMember
	(*v1.ResourceHeader)(nil),     // 7: teleport.common.v1.ResourceHeader
	(*durationpb.Duration)(nil),   // 8: google.protobuf.Duration
	(*v1.Trait)(nil),              // 9: teleport.common.v1.Trait
	(*timestamppb.Timestamp)(nil), // 10: google.protobuf.Timestamp
}
var file_teleport_accesslist_v1_accesslist_proto_depIdxs = []int32{
	7,  // 0: teleport.accesslist.v1.AccessList.header:type_name -> teleport.common.v1.ResourceHeader
	1,  // 1: teleport.accesslist.v1.AccessList.spec:type_name -> teleport.accesslist.v1.AccessListSpec
	2,  // 2: teleport.accesslist.v1.AccessListSpec.owners:type_name -> teleport.accesslist.v1.AccessListOwner
	3,  // 3: teleport.accesslist.v1.AccessListSpec.audit:type_name -> teleport.accesslist.v1.AccessListAudit
	4,  // 4: teleport.accesslist.v1.AccessListSpec.membership_requires:type_name -> teleport.accesslist.v1.AccessListRequires
	4,  // 5: teleport.accesslist.v1.AccessListSpec.ownership_requires:type_name -> teleport.accesslist.v1.AccessListRequires
	5,  // 6: teleport.accesslist.v1.AccessListSpec.grants:type_name -> teleport.accesslist.v1.AccessListGrants
	6,  // 7: teleport.accesslist.v1.AccessListSpec.members:type_name -> teleport.accesslist.v1.AccessListMember
	8,  // 8: teleport.accesslist.v1.AccessListAudit.frequency:type_name -> google.protobuf.Duration
	9,  // 9: teleport.accesslist.v1.AccessListRequires.traits:type_name -> teleport.common.v1.Trait
	9,  // 10: teleport.accesslist.v1.AccessListGrants.traits:type_name -> teleport.common.v1.Trait
	10, // 11: teleport.accesslist.v1.AccessListMember.joined:type_name -> google.protobuf.Timestamp
	10, // 12: teleport.accesslist.v1.AccessListMember.expires:type_name -> google.protobuf.Timestamp
	13, // [13:13] is the sub-list for method output_type
	13, // [13:13] is the sub-list for method input_type
	13, // [13:13] is the sub-list for extension type_name
	13, // [13:13] is the sub-list for extension extendee
	0,  // [0:13] is the sub-list for field type_name
}

func init() { file_teleport_accesslist_v1_accesslist_proto_init() }
func file_teleport_accesslist_v1_accesslist_proto_init() {
	if File_teleport_accesslist_v1_accesslist_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleport_accesslist_v1_accesslist_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccessList); i {
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
		file_teleport_accesslist_v1_accesslist_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccessListSpec); i {
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
		file_teleport_accesslist_v1_accesslist_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccessListOwner); i {
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
		file_teleport_accesslist_v1_accesslist_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccessListAudit); i {
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
		file_teleport_accesslist_v1_accesslist_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccessListRequires); i {
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
		file_teleport_accesslist_v1_accesslist_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccessListGrants); i {
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
		file_teleport_accesslist_v1_accesslist_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccessListMember); i {
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
			RawDescriptor: file_teleport_accesslist_v1_accesslist_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_accesslist_v1_accesslist_proto_goTypes,
		DependencyIndexes: file_teleport_accesslist_v1_accesslist_proto_depIdxs,
		MessageInfos:      file_teleport_accesslist_v1_accesslist_proto_msgTypes,
	}.Build()
	File_teleport_accesslist_v1_accesslist_proto = out.File
	file_teleport_accesslist_v1_accesslist_proto_rawDesc = nil
	file_teleport_accesslist_v1_accesslist_proto_goTypes = nil
	file_teleport_accesslist_v1_accesslist_proto_depIdxs = nil
}
