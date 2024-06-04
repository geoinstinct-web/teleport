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
// source: teleport/userpreferences/v1/unified_resource_preferences.proto

package userpreferencesv1

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

// DefaultTab is the default tab selected in the unified resource web UI
type DefaultTab int32

const (
	DefaultTab_DEFAULT_TAB_UNSPECIFIED DefaultTab = 0
	// ALL is all resources
	DefaultTab_DEFAULT_TAB_ALL DefaultTab = 1
	// PINNED is only pinned resources
	DefaultTab_DEFAULT_TAB_PINNED DefaultTab = 2
)

// Enum value maps for DefaultTab.
var (
	DefaultTab_name = map[int32]string{
		0: "DEFAULT_TAB_UNSPECIFIED",
		1: "DEFAULT_TAB_ALL",
		2: "DEFAULT_TAB_PINNED",
	}
	DefaultTab_value = map[string]int32{
		"DEFAULT_TAB_UNSPECIFIED": 0,
		"DEFAULT_TAB_ALL":         1,
		"DEFAULT_TAB_PINNED":      2,
	}
)

func (x DefaultTab) Enum() *DefaultTab {
	p := new(DefaultTab)
	*p = x
	return p
}

func (x DefaultTab) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (DefaultTab) Descriptor() protoreflect.EnumDescriptor {
	return file_teleport_userpreferences_v1_unified_resource_preferences_proto_enumTypes[0].Descriptor()
}

func (DefaultTab) Type() protoreflect.EnumType {
	return &file_teleport_userpreferences_v1_unified_resource_preferences_proto_enumTypes[0]
}

func (x DefaultTab) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use DefaultTab.Descriptor instead.
func (DefaultTab) EnumDescriptor() ([]byte, []int) {
	return file_teleport_userpreferences_v1_unified_resource_preferences_proto_rawDescGZIP(), []int{0}
}

// ViewMode is the view mode selected in the unified resource Web UI
type ViewMode int32

const (
	ViewMode_VIEW_MODE_UNSPECIFIED ViewMode = 0
	// CARD is the card view
	ViewMode_VIEW_MODE_CARD ViewMode = 1
	// LIST is the list view
	ViewMode_VIEW_MODE_LIST ViewMode = 2
)

// Enum value maps for ViewMode.
var (
	ViewMode_name = map[int32]string{
		0: "VIEW_MODE_UNSPECIFIED",
		1: "VIEW_MODE_CARD",
		2: "VIEW_MODE_LIST",
	}
	ViewMode_value = map[string]int32{
		"VIEW_MODE_UNSPECIFIED": 0,
		"VIEW_MODE_CARD":        1,
		"VIEW_MODE_LIST":        2,
	}
)

func (x ViewMode) Enum() *ViewMode {
	p := new(ViewMode)
	*p = x
	return p
}

func (x ViewMode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ViewMode) Descriptor() protoreflect.EnumDescriptor {
	return file_teleport_userpreferences_v1_unified_resource_preferences_proto_enumTypes[1].Descriptor()
}

func (ViewMode) Type() protoreflect.EnumType {
	return &file_teleport_userpreferences_v1_unified_resource_preferences_proto_enumTypes[1]
}

func (x ViewMode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ViewMode.Descriptor instead.
func (ViewMode) EnumDescriptor() ([]byte, []int) {
	return file_teleport_userpreferences_v1_unified_resource_preferences_proto_rawDescGZIP(), []int{1}
}

// * LabelsViewMode is whether the labels for resources should all be collapsed or expanded. This only applies to the list view.
type LabelsViewMode int32

const (
	LabelsViewMode_LABELS_VIEW_MODE_UNSPECIFIED LabelsViewMode = 0
	// EXPANDED is the expanded state which shows all labels for every resource.
	LabelsViewMode_LABELS_VIEW_MODE_EXPANDED LabelsViewMode = 1
	// COLLAPSED is the collapsed state which hides all labels for every resource.
	LabelsViewMode_LABELS_VIEW_MODE_COLLAPSED LabelsViewMode = 2
)

// Enum value maps for LabelsViewMode.
var (
	LabelsViewMode_name = map[int32]string{
		0: "LABELS_VIEW_MODE_UNSPECIFIED",
		1: "LABELS_VIEW_MODE_EXPANDED",
		2: "LABELS_VIEW_MODE_COLLAPSED",
	}
	LabelsViewMode_value = map[string]int32{
		"LABELS_VIEW_MODE_UNSPECIFIED": 0,
		"LABELS_VIEW_MODE_EXPANDED":    1,
		"LABELS_VIEW_MODE_COLLAPSED":   2,
	}
)

func (x LabelsViewMode) Enum() *LabelsViewMode {
	p := new(LabelsViewMode)
	*p = x
	return p
}

func (x LabelsViewMode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (LabelsViewMode) Descriptor() protoreflect.EnumDescriptor {
	return file_teleport_userpreferences_v1_unified_resource_preferences_proto_enumTypes[2].Descriptor()
}

func (LabelsViewMode) Type() protoreflect.EnumType {
	return &file_teleport_userpreferences_v1_unified_resource_preferences_proto_enumTypes[2]
}

func (x LabelsViewMode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use LabelsViewMode.Descriptor instead.
func (LabelsViewMode) EnumDescriptor() ([]byte, []int) {
	return file_teleport_userpreferences_v1_unified_resource_preferences_proto_rawDescGZIP(), []int{2}
}

// * AvailableResourceMode specifies which option in the availability filter menu the user has selected, if any
type AvailableResourceMode int32

const (
	AvailableResourceMode_AVAILABLE_RESOURCE_MODE_UNSPECIFIED AvailableResourceMode = 0
	AvailableResourceMode_AVAILABLE_RESOURCE_MODE_ALL         AvailableResourceMode = 1
	AvailableResourceMode_AVAILABLE_RESOURCE_MODE_ACCESSIBLE  AvailableResourceMode = 2
	AvailableResourceMode_AVAILABLE_RESOURCE_MODE_REQUESTABLE AvailableResourceMode = 3
	AvailableResourceMode_AVAILABLE_RESOURCE_MODE_NONE        AvailableResourceMode = 4
)

// Enum value maps for AvailableResourceMode.
var (
	AvailableResourceMode_name = map[int32]string{
		0: "AVAILABLE_RESOURCE_MODE_UNSPECIFIED",
		1: "AVAILABLE_RESOURCE_MODE_ALL",
		2: "AVAILABLE_RESOURCE_MODE_ACCESSIBLE",
		3: "AVAILABLE_RESOURCE_MODE_REQUESTABLE",
		4: "AVAILABLE_RESOURCE_MODE_NONE",
	}
	AvailableResourceMode_value = map[string]int32{
		"AVAILABLE_RESOURCE_MODE_UNSPECIFIED": 0,
		"AVAILABLE_RESOURCE_MODE_ALL":         1,
		"AVAILABLE_RESOURCE_MODE_ACCESSIBLE":  2,
		"AVAILABLE_RESOURCE_MODE_REQUESTABLE": 3,
		"AVAILABLE_RESOURCE_MODE_NONE":        4,
	}
)

func (x AvailableResourceMode) Enum() *AvailableResourceMode {
	p := new(AvailableResourceMode)
	*p = x
	return p
}

func (x AvailableResourceMode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (AvailableResourceMode) Descriptor() protoreflect.EnumDescriptor {
	return file_teleport_userpreferences_v1_unified_resource_preferences_proto_enumTypes[3].Descriptor()
}

func (AvailableResourceMode) Type() protoreflect.EnumType {
	return &file_teleport_userpreferences_v1_unified_resource_preferences_proto_enumTypes[3]
}

func (x AvailableResourceMode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use AvailableResourceMode.Descriptor instead.
func (AvailableResourceMode) EnumDescriptor() ([]byte, []int) {
	return file_teleport_userpreferences_v1_unified_resource_preferences_proto_rawDescGZIP(), []int{3}
}

// UnifiedResourcePreferences are preferences used in the Unified Resource web UI
type UnifiedResourcePreferences struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// default_tab is the default tab selected in the unified resource web UI
	DefaultTab DefaultTab `protobuf:"varint,1,opt,name=default_tab,json=defaultTab,proto3,enum=teleport.userpreferences.v1.DefaultTab" json:"default_tab,omitempty"`
	// view_mode is the view mode selected in the unified resource Web UI
	ViewMode ViewMode `protobuf:"varint,2,opt,name=view_mode,json=viewMode,proto3,enum=teleport.userpreferences.v1.ViewMode" json:"view_mode,omitempty"`
	// labels_view_mode is whether the labels for resources should all be collapsed or expanded in the unified resource Web UI list view.
	LabelsViewMode LabelsViewMode `protobuf:"varint,3,opt,name=labels_view_mode,json=labelsViewMode,proto3,enum=teleport.userpreferences.v1.LabelsViewMode" json:"labels_view_mode,omitempty"`
	// available_resource_mode specifies which option in the availability filter menu the user has selected, if any
	AvailableResourceMode AvailableResourceMode `protobuf:"varint,4,opt,name=available_resource_mode,json=availableResourceMode,proto3,enum=teleport.userpreferences.v1.AvailableResourceMode" json:"available_resource_mode,omitempty"`
}

func (x *UnifiedResourcePreferences) Reset() {
	*x = UnifiedResourcePreferences{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_userpreferences_v1_unified_resource_preferences_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UnifiedResourcePreferences) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UnifiedResourcePreferences) ProtoMessage() {}

func (x *UnifiedResourcePreferences) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_userpreferences_v1_unified_resource_preferences_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UnifiedResourcePreferences.ProtoReflect.Descriptor instead.
func (*UnifiedResourcePreferences) Descriptor() ([]byte, []int) {
	return file_teleport_userpreferences_v1_unified_resource_preferences_proto_rawDescGZIP(), []int{0}
}

func (x *UnifiedResourcePreferences) GetDefaultTab() DefaultTab {
	if x != nil {
		return x.DefaultTab
	}
	return DefaultTab_DEFAULT_TAB_UNSPECIFIED
}

func (x *UnifiedResourcePreferences) GetViewMode() ViewMode {
	if x != nil {
		return x.ViewMode
	}
	return ViewMode_VIEW_MODE_UNSPECIFIED
}

func (x *UnifiedResourcePreferences) GetLabelsViewMode() LabelsViewMode {
	if x != nil {
		return x.LabelsViewMode
	}
	return LabelsViewMode_LABELS_VIEW_MODE_UNSPECIFIED
}

func (x *UnifiedResourcePreferences) GetAvailableResourceMode() AvailableResourceMode {
	if x != nil {
		return x.AvailableResourceMode
	}
	return AvailableResourceMode_AVAILABLE_RESOURCE_MODE_UNSPECIFIED
}

var File_teleport_userpreferences_v1_unified_resource_preferences_proto protoreflect.FileDescriptor

var file_teleport_userpreferences_v1_unified_resource_preferences_proto_rawDesc = []byte{
	0x0a, 0x3e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x75, 0x73, 0x65, 0x72, 0x70,
	0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x75, 0x6e,
	0x69, 0x66, 0x69, 0x65, 0x64, 0x5f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x70,
	0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x1b, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x70,
	0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x22, 0xed, 0x02,
	0x0a, 0x1a, 0x55, 0x6e, 0x69, 0x66, 0x69, 0x65, 0x64, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x50, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x12, 0x48, 0x0a, 0x0b,
	0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x5f, 0x74, 0x61, 0x62, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0e, 0x32, 0x27, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65,
	0x72, 0x70, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e,
	0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x54, 0x61, 0x62, 0x52, 0x0a, 0x64, 0x65, 0x66, 0x61,
	0x75, 0x6c, 0x74, 0x54, 0x61, 0x62, 0x12, 0x42, 0x0a, 0x09, 0x76, 0x69, 0x65, 0x77, 0x5f, 0x6d,
	0x6f, 0x64, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x25, 0x2e, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x70, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65,
	0x6e, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x56, 0x69, 0x65, 0x77, 0x4d, 0x6f, 0x64, 0x65,
	0x52, 0x08, 0x76, 0x69, 0x65, 0x77, 0x4d, 0x6f, 0x64, 0x65, 0x12, 0x55, 0x0a, 0x10, 0x6c, 0x61,
	0x62, 0x65, 0x6c, 0x73, 0x5f, 0x76, 0x69, 0x65, 0x77, 0x5f, 0x6d, 0x6f, 0x64, 0x65, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x2b, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e,
	0x75, 0x73, 0x65, 0x72, 0x70, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x2e,
	0x76, 0x31, 0x2e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x56, 0x69, 0x65, 0x77, 0x4d, 0x6f, 0x64,
	0x65, 0x52, 0x0e, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x56, 0x69, 0x65, 0x77, 0x4d, 0x6f, 0x64,
	0x65, 0x12, 0x6a, 0x0a, 0x17, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x5f, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x6d, 0x6f, 0x64, 0x65, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x0e, 0x32, 0x32, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73,
	0x65, 0x72, 0x70, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31,
	0x2e, 0x41, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x4d, 0x6f, 0x64, 0x65, 0x52, 0x15, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c,
	0x65, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4d, 0x6f, 0x64, 0x65, 0x2a, 0x56, 0x0a,
	0x0a, 0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x54, 0x61, 0x62, 0x12, 0x1b, 0x0a, 0x17, 0x44,
	0x45, 0x46, 0x41, 0x55, 0x4c, 0x54, 0x5f, 0x54, 0x41, 0x42, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45,
	0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x13, 0x0a, 0x0f, 0x44, 0x45, 0x46, 0x41,
	0x55, 0x4c, 0x54, 0x5f, 0x54, 0x41, 0x42, 0x5f, 0x41, 0x4c, 0x4c, 0x10, 0x01, 0x12, 0x16, 0x0a,
	0x12, 0x44, 0x45, 0x46, 0x41, 0x55, 0x4c, 0x54, 0x5f, 0x54, 0x41, 0x42, 0x5f, 0x50, 0x49, 0x4e,
	0x4e, 0x45, 0x44, 0x10, 0x02, 0x2a, 0x4d, 0x0a, 0x08, 0x56, 0x69, 0x65, 0x77, 0x4d, 0x6f, 0x64,
	0x65, 0x12, 0x19, 0x0a, 0x15, 0x56, 0x49, 0x45, 0x57, 0x5f, 0x4d, 0x4f, 0x44, 0x45, 0x5f, 0x55,
	0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x12, 0x0a, 0x0e,
	0x56, 0x49, 0x45, 0x57, 0x5f, 0x4d, 0x4f, 0x44, 0x45, 0x5f, 0x43, 0x41, 0x52, 0x44, 0x10, 0x01,
	0x12, 0x12, 0x0a, 0x0e, 0x56, 0x49, 0x45, 0x57, 0x5f, 0x4d, 0x4f, 0x44, 0x45, 0x5f, 0x4c, 0x49,
	0x53, 0x54, 0x10, 0x02, 0x2a, 0x71, 0x0a, 0x0e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x56, 0x69,
	0x65, 0x77, 0x4d, 0x6f, 0x64, 0x65, 0x12, 0x20, 0x0a, 0x1c, 0x4c, 0x41, 0x42, 0x45, 0x4c, 0x53,
	0x5f, 0x56, 0x49, 0x45, 0x57, 0x5f, 0x4d, 0x4f, 0x44, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45,
	0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x1d, 0x0a, 0x19, 0x4c, 0x41, 0x42, 0x45,
	0x4c, 0x53, 0x5f, 0x56, 0x49, 0x45, 0x57, 0x5f, 0x4d, 0x4f, 0x44, 0x45, 0x5f, 0x45, 0x58, 0x50,
	0x41, 0x4e, 0x44, 0x45, 0x44, 0x10, 0x01, 0x12, 0x1e, 0x0a, 0x1a, 0x4c, 0x41, 0x42, 0x45, 0x4c,
	0x53, 0x5f, 0x56, 0x49, 0x45, 0x57, 0x5f, 0x4d, 0x4f, 0x44, 0x45, 0x5f, 0x43, 0x4f, 0x4c, 0x4c,
	0x41, 0x50, 0x53, 0x45, 0x44, 0x10, 0x02, 0x2a, 0xd4, 0x01, 0x0a, 0x15, 0x41, 0x76, 0x61, 0x69,
	0x6c, 0x61, 0x62, 0x6c, 0x65, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4d, 0x6f, 0x64,
	0x65, 0x12, 0x27, 0x0a, 0x23, 0x41, 0x56, 0x41, 0x49, 0x4c, 0x41, 0x42, 0x4c, 0x45, 0x5f, 0x52,
	0x45, 0x53, 0x4f, 0x55, 0x52, 0x43, 0x45, 0x5f, 0x4d, 0x4f, 0x44, 0x45, 0x5f, 0x55, 0x4e, 0x53,
	0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x1f, 0x0a, 0x1b, 0x41, 0x56,
	0x41, 0x49, 0x4c, 0x41, 0x42, 0x4c, 0x45, 0x5f, 0x52, 0x45, 0x53, 0x4f, 0x55, 0x52, 0x43, 0x45,
	0x5f, 0x4d, 0x4f, 0x44, 0x45, 0x5f, 0x41, 0x4c, 0x4c, 0x10, 0x01, 0x12, 0x26, 0x0a, 0x22, 0x41,
	0x56, 0x41, 0x49, 0x4c, 0x41, 0x42, 0x4c, 0x45, 0x5f, 0x52, 0x45, 0x53, 0x4f, 0x55, 0x52, 0x43,
	0x45, 0x5f, 0x4d, 0x4f, 0x44, 0x45, 0x5f, 0x41, 0x43, 0x43, 0x45, 0x53, 0x53, 0x49, 0x42, 0x4c,
	0x45, 0x10, 0x02, 0x12, 0x27, 0x0a, 0x23, 0x41, 0x56, 0x41, 0x49, 0x4c, 0x41, 0x42, 0x4c, 0x45,
	0x5f, 0x52, 0x45, 0x53, 0x4f, 0x55, 0x52, 0x43, 0x45, 0x5f, 0x4d, 0x4f, 0x44, 0x45, 0x5f, 0x52,
	0x45, 0x51, 0x55, 0x45, 0x53, 0x54, 0x41, 0x42, 0x4c, 0x45, 0x10, 0x03, 0x12, 0x20, 0x0a, 0x1c,
	0x41, 0x56, 0x41, 0x49, 0x4c, 0x41, 0x42, 0x4c, 0x45, 0x5f, 0x52, 0x45, 0x53, 0x4f, 0x55, 0x52,
	0x43, 0x45, 0x5f, 0x4d, 0x4f, 0x44, 0x45, 0x5f, 0x4e, 0x4f, 0x4e, 0x45, 0x10, 0x04, 0x42, 0x59,
	0x5a, 0x57, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61,
	0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x75, 0x73, 0x65, 0x72, 0x70, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65,
	0x6e, 0x63, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x3b, 0x75, 0x73, 0x65, 0x72, 0x70, 0x72, 0x65, 0x66,
	0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_teleport_userpreferences_v1_unified_resource_preferences_proto_rawDescOnce sync.Once
	file_teleport_userpreferences_v1_unified_resource_preferences_proto_rawDescData = file_teleport_userpreferences_v1_unified_resource_preferences_proto_rawDesc
)

func file_teleport_userpreferences_v1_unified_resource_preferences_proto_rawDescGZIP() []byte {
	file_teleport_userpreferences_v1_unified_resource_preferences_proto_rawDescOnce.Do(func() {
		file_teleport_userpreferences_v1_unified_resource_preferences_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_userpreferences_v1_unified_resource_preferences_proto_rawDescData)
	})
	return file_teleport_userpreferences_v1_unified_resource_preferences_proto_rawDescData
}

var file_teleport_userpreferences_v1_unified_resource_preferences_proto_enumTypes = make([]protoimpl.EnumInfo, 4)
var file_teleport_userpreferences_v1_unified_resource_preferences_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_teleport_userpreferences_v1_unified_resource_preferences_proto_goTypes = []interface{}{
	(DefaultTab)(0),                    // 0: teleport.userpreferences.v1.DefaultTab
	(ViewMode)(0),                      // 1: teleport.userpreferences.v1.ViewMode
	(LabelsViewMode)(0),                // 2: teleport.userpreferences.v1.LabelsViewMode
	(AvailableResourceMode)(0),         // 3: teleport.userpreferences.v1.AvailableResourceMode
	(*UnifiedResourcePreferences)(nil), // 4: teleport.userpreferences.v1.UnifiedResourcePreferences
}
var file_teleport_userpreferences_v1_unified_resource_preferences_proto_depIdxs = []int32{
	0, // 0: teleport.userpreferences.v1.UnifiedResourcePreferences.default_tab:type_name -> teleport.userpreferences.v1.DefaultTab
	1, // 1: teleport.userpreferences.v1.UnifiedResourcePreferences.view_mode:type_name -> teleport.userpreferences.v1.ViewMode
	2, // 2: teleport.userpreferences.v1.UnifiedResourcePreferences.labels_view_mode:type_name -> teleport.userpreferences.v1.LabelsViewMode
	3, // 3: teleport.userpreferences.v1.UnifiedResourcePreferences.available_resource_mode:type_name -> teleport.userpreferences.v1.AvailableResourceMode
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_teleport_userpreferences_v1_unified_resource_preferences_proto_init() }
func file_teleport_userpreferences_v1_unified_resource_preferences_proto_init() {
	if File_teleport_userpreferences_v1_unified_resource_preferences_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleport_userpreferences_v1_unified_resource_preferences_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UnifiedResourcePreferences); i {
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
			RawDescriptor: file_teleport_userpreferences_v1_unified_resource_preferences_proto_rawDesc,
			NumEnums:      4,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_userpreferences_v1_unified_resource_preferences_proto_goTypes,
		DependencyIndexes: file_teleport_userpreferences_v1_unified_resource_preferences_proto_depIdxs,
		EnumInfos:         file_teleport_userpreferences_v1_unified_resource_preferences_proto_enumTypes,
		MessageInfos:      file_teleport_userpreferences_v1_unified_resource_preferences_proto_msgTypes,
	}.Build()
	File_teleport_userpreferences_v1_unified_resource_preferences_proto = out.File
	file_teleport_userpreferences_v1_unified_resource_preferences_proto_rawDesc = nil
	file_teleport_userpreferences_v1_unified_resource_preferences_proto_goTypes = nil
	file_teleport_userpreferences_v1_unified_resource_preferences_proto_depIdxs = nil
}
