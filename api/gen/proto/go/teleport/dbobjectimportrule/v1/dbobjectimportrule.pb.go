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
// source: teleport/dbobjectimportrule/v1/dbobjectimportrule.proto

package dbobjectimportrulev1

import (
	v1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	v11 "github.com/gravitational/teleport/api/gen/proto/go/teleport/label/v1"
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

// DatabaseObjectImportRule is the resource representing a global database object import rule.
// The import rules govern which database objects are imported from databases.
// See type teleport.dbobject.v1.DatabaseObject for the description of a database object.
// For rationale behind this type, see the RFD 151.
type DatabaseObjectImportRule struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The kind of resource represented.
	Kind string `protobuf:"bytes,1,opt,name=kind,proto3" json:"kind,omitempty"`
	// Mandatory field for all resources. Not populated for this resource type.
	SubKind string `protobuf:"bytes,2,opt,name=sub_kind,json=subKind,proto3" json:"sub_kind,omitempty"`
	// The version of the resource being represented.
	Version string `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"`
	// Common metadata that all resources share.
	Metadata *v1.Metadata `protobuf:"bytes,4,opt,name=metadata,proto3" json:"metadata,omitempty"`
	// spec represents the specifications for the database object import rule.
	Spec *DatabaseObjectImportRuleSpec `protobuf:"bytes,5,opt,name=spec,proto3" json:"spec,omitempty"`
}

func (x *DatabaseObjectImportRule) Reset() {
	*x = DatabaseObjectImportRule{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DatabaseObjectImportRule) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DatabaseObjectImportRule) ProtoMessage() {}

func (x *DatabaseObjectImportRule) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DatabaseObjectImportRule.ProtoReflect.Descriptor instead.
func (*DatabaseObjectImportRule) Descriptor() ([]byte, []int) {
	return file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_rawDescGZIP(), []int{0}
}

func (x *DatabaseObjectImportRule) GetKind() string {
	if x != nil {
		return x.Kind
	}
	return ""
}

func (x *DatabaseObjectImportRule) GetSubKind() string {
	if x != nil {
		return x.SubKind
	}
	return ""
}

func (x *DatabaseObjectImportRule) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *DatabaseObjectImportRule) GetMetadata() *v1.Metadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

func (x *DatabaseObjectImportRule) GetSpec() *DatabaseObjectImportRuleSpec {
	if x != nil {
		return x.Spec
	}
	return nil
}

// DatabaseObjectImportRuleSpec is the spec for database object import rule.
type DatabaseObjectImportRuleSpec struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// priority represents the priority of the rule application.
	//
	// Rules are processed from lowest to highest priority.
	// If two rules apply the same label, then the value applied with the rule with the highest priority wins.
	Priority int32 `protobuf:"varint,1,opt,name=priority,proto3" json:"priority,omitempty"`
	// db_labels is a set of labels matched against database labels.
	DatabaseLabels []*v11.Label `protobuf:"bytes,3,rep,name=database_labels,json=databaseLabels,proto3" json:"database_labels,omitempty"`
	// mappings is a list of matches that will map match conditions to labels.
	Mappings []*DatabaseObjectImportRuleMapping `protobuf:"bytes,4,rep,name=mappings,proto3" json:"mappings,omitempty"`
}

func (x *DatabaseObjectImportRuleSpec) Reset() {
	*x = DatabaseObjectImportRuleSpec{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DatabaseObjectImportRuleSpec) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DatabaseObjectImportRuleSpec) ProtoMessage() {}

func (x *DatabaseObjectImportRuleSpec) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DatabaseObjectImportRuleSpec.ProtoReflect.Descriptor instead.
func (*DatabaseObjectImportRuleSpec) Descriptor() ([]byte, []int) {
	return file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_rawDescGZIP(), []int{1}
}

func (x *DatabaseObjectImportRuleSpec) GetPriority() int32 {
	if x != nil {
		return x.Priority
	}
	return 0
}

func (x *DatabaseObjectImportRuleSpec) GetDatabaseLabels() []*v11.Label {
	if x != nil {
		return x.DatabaseLabels
	}
	return nil
}

func (x *DatabaseObjectImportRuleSpec) GetMappings() []*DatabaseObjectImportRuleMapping {
	if x != nil {
		return x.Mappings
	}
	return nil
}

// DatabaseObjectImportRuleMapping is the mapping between object properties and labels that will be added to the object.
type DatabaseObjectImportRuleMapping struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// match specifies the matching rules, like the object names.
	Match *DatabaseObjectImportMatch `protobuf:"bytes,1,opt,name=match,proto3" json:"match,omitempty"`
	// scope specifies the object scope. Optional. If not provided, all scopes will be accepted.
	Scope *DatabaseObjectImportScope `protobuf:"bytes,2,opt,name=scope,proto3" json:"scope,omitempty"`
	// add_labels specifies which labels to add if the match succeeds. At least one should be present.
	AddLabels map[string]string `protobuf:"bytes,3,rep,name=add_labels,json=addLabels,proto3" json:"add_labels,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *DatabaseObjectImportRuleMapping) Reset() {
	*x = DatabaseObjectImportRuleMapping{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DatabaseObjectImportRuleMapping) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DatabaseObjectImportRuleMapping) ProtoMessage() {}

func (x *DatabaseObjectImportRuleMapping) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DatabaseObjectImportRuleMapping.ProtoReflect.Descriptor instead.
func (*DatabaseObjectImportRuleMapping) Descriptor() ([]byte, []int) {
	return file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_rawDescGZIP(), []int{2}
}

func (x *DatabaseObjectImportRuleMapping) GetMatch() *DatabaseObjectImportMatch {
	if x != nil {
		return x.Match
	}
	return nil
}

func (x *DatabaseObjectImportRuleMapping) GetScope() *DatabaseObjectImportScope {
	if x != nil {
		return x.Scope
	}
	return nil
}

func (x *DatabaseObjectImportRuleMapping) GetAddLabels() map[string]string {
	if x != nil {
		return x.AddLabels
	}
	return nil
}

// DatabaseObjectImportMatch specifies acceptable object names. Must have at least one non-empty member.
type DatabaseObjectImportMatch struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// table_names specify the names of the tables to match. Optional.
	TableNames []string `protobuf:"bytes,1,rep,name=table_names,json=tableNames,proto3" json:"table_names,omitempty"`
	// view_names specify the names of the views to match. Optional.
	ViewNames []string `protobuf:"bytes,2,rep,name=view_names,json=viewNames,proto3" json:"view_names,omitempty"`
	// procedure_names specify the names of the procedures to match. Optional.
	ProcedureNames []string `protobuf:"bytes,3,rep,name=procedure_names,json=procedureNames,proto3" json:"procedure_names,omitempty"`
}

func (x *DatabaseObjectImportMatch) Reset() {
	*x = DatabaseObjectImportMatch{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DatabaseObjectImportMatch) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DatabaseObjectImportMatch) ProtoMessage() {}

func (x *DatabaseObjectImportMatch) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DatabaseObjectImportMatch.ProtoReflect.Descriptor instead.
func (*DatabaseObjectImportMatch) Descriptor() ([]byte, []int) {
	return file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_rawDescGZIP(), []int{3}
}

func (x *DatabaseObjectImportMatch) GetTableNames() []string {
	if x != nil {
		return x.TableNames
	}
	return nil
}

func (x *DatabaseObjectImportMatch) GetViewNames() []string {
	if x != nil {
		return x.ViewNames
	}
	return nil
}

func (x *DatabaseObjectImportMatch) GetProcedureNames() []string {
	if x != nil {
		return x.ProcedureNames
	}
	return nil
}

// DatabaseObjectImportScope specifies the object scope. Members are matched independently of each other.
type DatabaseObjectImportScope struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// database_names specify the names of the databases to include in the scope. Optional.
	DatabaseNames []string `protobuf:"bytes,1,rep,name=database_names,json=databaseNames,proto3" json:"database_names,omitempty"`
	// schema_names specify the names of the schemas to include in the scope. Optional.
	SchemaNames []string `protobuf:"bytes,2,rep,name=schema_names,json=schemaNames,proto3" json:"schema_names,omitempty"`
}

func (x *DatabaseObjectImportScope) Reset() {
	*x = DatabaseObjectImportScope{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DatabaseObjectImportScope) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DatabaseObjectImportScope) ProtoMessage() {}

func (x *DatabaseObjectImportScope) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DatabaseObjectImportScope.ProtoReflect.Descriptor instead.
func (*DatabaseObjectImportScope) Descriptor() ([]byte, []int) {
	return file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_rawDescGZIP(), []int{4}
}

func (x *DatabaseObjectImportScope) GetDatabaseNames() []string {
	if x != nil {
		return x.DatabaseNames
	}
	return nil
}

func (x *DatabaseObjectImportScope) GetSchemaNames() []string {
	if x != nil {
		return x.SchemaNames
	}
	return nil
}

var File_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto protoreflect.FileDescriptor

var file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_rawDesc = []byte{
	0x0a, 0x37, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x64, 0x62, 0x6f, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x72, 0x75, 0x6c, 0x65, 0x2f, 0x76, 0x31,
	0x2f, 0x64, 0x62, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x72,
	0x75, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1e, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x64, 0x62, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x69, 0x6d, 0x70, 0x6f,
	0x72, 0x74, 0x72, 0x75, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x21, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x2f, 0x76, 0x31, 0x2f, 0x6d, 0x65,
	0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x74, 0x65,
	0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x2f, 0x76, 0x31, 0x2f,
	0x6c, 0x61, 0x62, 0x65, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xef, 0x01, 0x0a, 0x18,
	0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x6d,
	0x70, 0x6f, 0x72, 0x74, 0x52, 0x75, 0x6c, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6b, 0x69, 0x6e, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x12, 0x19, 0x0a, 0x08,
	0x73, 0x75, 0x62, 0x5f, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07,
	0x73, 0x75, 0x62, 0x4b, 0x69, 0x6e, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x12, 0x38, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x68,
	0x65, 0x61, 0x64, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x50, 0x0a, 0x04, 0x73,
	0x70, 0x65, 0x63, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x3c, 0x2e, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x62, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x69, 0x6d, 0x70,
	0x6f, 0x72, 0x74, 0x72, 0x75, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x61, 0x74, 0x61, 0x62,
	0x61, 0x73, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x52,
	0x75, 0x6c, 0x65, 0x53, 0x70, 0x65, 0x63, 0x52, 0x04, 0x73, 0x70, 0x65, 0x63, 0x22, 0xeb, 0x01,
	0x0a, 0x1c, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74,
	0x49, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x52, 0x75, 0x6c, 0x65, 0x53, 0x70, 0x65, 0x63, 0x12, 0x1a,
	0x0a, 0x08, 0x70, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05,
	0x52, 0x08, 0x70, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x12, 0x41, 0x0a, 0x0f, 0x64, 0x61,
	0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x5f, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x18, 0x03, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c,
	0x61, 0x62, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x52, 0x0e, 0x64,
	0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x12, 0x5b, 0x0a,
	0x08, 0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x3f, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x62, 0x6f, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x72, 0x75, 0x6c, 0x65, 0x2e, 0x76, 0x31,
	0x2e, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49,
	0x6d, 0x70, 0x6f, 0x72, 0x74, 0x52, 0x75, 0x6c, 0x65, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67,
	0x52, 0x08, 0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x73, 0x4a, 0x04, 0x08, 0x02, 0x10, 0x03,
	0x52, 0x09, 0x64, 0x62, 0x5f, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x22, 0xf0, 0x02, 0x0a, 0x1f,
	0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x6d,
	0x70, 0x6f, 0x72, 0x74, 0x52, 0x75, 0x6c, 0x65, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x12,
	0x4f, 0x0a, 0x05, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x39,
	0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x62, 0x6f, 0x62, 0x6a, 0x65,
	0x63, 0x74, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x72, 0x75, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x2e,
	0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x6d,
	0x70, 0x6f, 0x72, 0x74, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x52, 0x05, 0x6d, 0x61, 0x74, 0x63, 0x68,
	0x12, 0x4f, 0x0a, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x39, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x62, 0x6f, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x72, 0x75, 0x6c, 0x65, 0x2e, 0x76, 0x31,
	0x2e, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49,
	0x6d, 0x70, 0x6f, 0x72, 0x74, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x52, 0x05, 0x73, 0x63, 0x6f, 0x70,
	0x65, 0x12, 0x6d, 0x0a, 0x0a, 0x61, 0x64, 0x64, 0x5f, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x18,
	0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x4e, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74,
	0x2e, 0x64, 0x62, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x72,
	0x75, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x4f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x52, 0x75, 0x6c, 0x65, 0x4d,
	0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x2e, 0x41, 0x64, 0x64, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x09, 0x61, 0x64, 0x64, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73,
	0x1a, 0x3c, 0x0a, 0x0e, 0x41, 0x64, 0x64, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0x84,
	0x01, 0x0a, 0x19, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x49, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x12, 0x1f, 0x0a, 0x0b,
	0x74, 0x61, 0x62, 0x6c, 0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x09, 0x52, 0x0a, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x12, 0x1d, 0x0a,
	0x0a, 0x76, 0x69, 0x65, 0x77, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28,
	0x09, 0x52, 0x09, 0x76, 0x69, 0x65, 0x77, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x12, 0x27, 0x0a, 0x0f,
	0x70, 0x72, 0x6f, 0x63, 0x65, 0x64, 0x75, 0x72, 0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x18,
	0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0e, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x64, 0x75, 0x72, 0x65,
	0x4e, 0x61, 0x6d, 0x65, 0x73, 0x22, 0x65, 0x0a, 0x19, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73,
	0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x53, 0x63, 0x6f,
	0x70, 0x65, 0x12, 0x25, 0x0a, 0x0e, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x5f, 0x6e,
	0x61, 0x6d, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0d, 0x64, 0x61, 0x74, 0x61,
	0x62, 0x61, 0x73, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x12, 0x21, 0x0a, 0x0c, 0x73, 0x63, 0x68,
	0x65, 0x6d, 0x61, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x0b, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x42, 0x68, 0x5a, 0x66,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69,
	0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x67, 0x6f, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x64, 0x62, 0x6f, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x72, 0x75, 0x6c, 0x65, 0x2f, 0x76,
	0x31, 0x3b, 0x64, 0x62, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74,
	0x72, 0x75, 0x6c, 0x65, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_rawDescOnce sync.Once
	file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_rawDescData = file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_rawDesc
)

func file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_rawDescGZIP() []byte {
	file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_rawDescOnce.Do(func() {
		file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_rawDescData)
	})
	return file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_rawDescData
}

var file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_goTypes = []interface{}{
	(*DatabaseObjectImportRule)(nil),        // 0: teleport.dbobjectimportrule.v1.DatabaseObjectImportRule
	(*DatabaseObjectImportRuleSpec)(nil),    // 1: teleport.dbobjectimportrule.v1.DatabaseObjectImportRuleSpec
	(*DatabaseObjectImportRuleMapping)(nil), // 2: teleport.dbobjectimportrule.v1.DatabaseObjectImportRuleMapping
	(*DatabaseObjectImportMatch)(nil),       // 3: teleport.dbobjectimportrule.v1.DatabaseObjectImportMatch
	(*DatabaseObjectImportScope)(nil),       // 4: teleport.dbobjectimportrule.v1.DatabaseObjectImportScope
	nil,                                     // 5: teleport.dbobjectimportrule.v1.DatabaseObjectImportRuleMapping.AddLabelsEntry
	(*v1.Metadata)(nil),                     // 6: teleport.header.v1.Metadata
	(*v11.Label)(nil),                       // 7: teleport.label.v1.Label
}
var file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_depIdxs = []int32{
	6, // 0: teleport.dbobjectimportrule.v1.DatabaseObjectImportRule.metadata:type_name -> teleport.header.v1.Metadata
	1, // 1: teleport.dbobjectimportrule.v1.DatabaseObjectImportRule.spec:type_name -> teleport.dbobjectimportrule.v1.DatabaseObjectImportRuleSpec
	7, // 2: teleport.dbobjectimportrule.v1.DatabaseObjectImportRuleSpec.database_labels:type_name -> teleport.label.v1.Label
	2, // 3: teleport.dbobjectimportrule.v1.DatabaseObjectImportRuleSpec.mappings:type_name -> teleport.dbobjectimportrule.v1.DatabaseObjectImportRuleMapping
	3, // 4: teleport.dbobjectimportrule.v1.DatabaseObjectImportRuleMapping.match:type_name -> teleport.dbobjectimportrule.v1.DatabaseObjectImportMatch
	4, // 5: teleport.dbobjectimportrule.v1.DatabaseObjectImportRuleMapping.scope:type_name -> teleport.dbobjectimportrule.v1.DatabaseObjectImportScope
	5, // 6: teleport.dbobjectimportrule.v1.DatabaseObjectImportRuleMapping.add_labels:type_name -> teleport.dbobjectimportrule.v1.DatabaseObjectImportRuleMapping.AddLabelsEntry
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_init() }
func file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_init() {
	if File_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DatabaseObjectImportRule); i {
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
		file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DatabaseObjectImportRuleSpec); i {
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
		file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DatabaseObjectImportRuleMapping); i {
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
		file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DatabaseObjectImportMatch); i {
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
		file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DatabaseObjectImportScope); i {
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
			RawDescriptor: file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_goTypes,
		DependencyIndexes: file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_depIdxs,
		MessageInfos:      file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_msgTypes,
	}.Build()
	File_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto = out.File
	file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_rawDesc = nil
	file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_goTypes = nil
	file_teleport_dbobjectimportrule_v1_dbobjectimportrule_proto_depIdxs = nil
}
