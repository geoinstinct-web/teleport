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
// source: accessgraph/v1alpha/graph.proto

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

// Node is a node in the access graph.
type Node struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ID is the unique ID of the node.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// Kind is the kind of the node, ex: "user", "user_group", "resource", etc.
	Kind string `protobuf:"bytes,2,opt,name=kind,proto3" json:"kind,omitempty"`
	// SubKind is the subkind of the node, ex: "ssh", "db", "k8s", etc.
	SubKind string `protobuf:"bytes,3,opt,name=sub_kind,json=subKind,proto3" json:"sub_kind,omitempty"`
	// Name is the name of the node.
	Name string `protobuf:"bytes,4,opt,name=name,proto3" json:"name,omitempty"`
	// Labels is a set of labels for the resource.
	Labels map[string]string `protobuf:"bytes,5,rep,name=labels,proto3" json:"labels,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// Hostname is the hostname of the node.
	Hostname string `protobuf:"bytes,6,opt,name=hostname,proto3" json:"hostname,omitempty"`
	// Properties is a set of properties for the resource.
	Properties map[string]string `protobuf:"bytes,7,rep,name=properties,proto3" json:"properties,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Node) Reset() {
	*x = Node{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_graph_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Node) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Node) ProtoMessage() {}

func (x *Node) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_graph_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Node.ProtoReflect.Descriptor instead.
func (*Node) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_graph_proto_rawDescGZIP(), []int{0}
}

func (x *Node) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Node) GetKind() string {
	if x != nil {
		return x.Kind
	}
	return ""
}

func (x *Node) GetSubKind() string {
	if x != nil {
		return x.SubKind
	}
	return ""
}

func (x *Node) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Node) GetLabels() map[string]string {
	if x != nil {
		return x.Labels
	}
	return nil
}

func (x *Node) GetHostname() string {
	if x != nil {
		return x.Hostname
	}
	return ""
}

func (x *Node) GetProperties() map[string]string {
	if x != nil {
		return x.Properties
	}
	return nil
}

// Edge is an edge in the access graph.
type Edge struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// from is the ID of the node the edge is from.
	From string `protobuf:"bytes,1,opt,name=from,proto3" json:"from,omitempty"`
	// to is the ID of the node the edge is to.
	To string `protobuf:"bytes,2,opt,name=to,proto3" json:"to,omitempty"`
	// edge_type is the type of the edge, e.g. "member_of", "belongs_to", etc.
	EdgeType string `protobuf:"bytes,3,opt,name=edge_type,json=edgeType,proto3" json:"edge_type,omitempty"`
}

func (x *Edge) Reset() {
	*x = Edge{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_graph_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Edge) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Edge) ProtoMessage() {}

func (x *Edge) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_graph_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Edge.ProtoReflect.Descriptor instead.
func (*Edge) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_graph_proto_rawDescGZIP(), []int{1}
}

func (x *Edge) GetFrom() string {
	if x != nil {
		return x.From
	}
	return ""
}

func (x *Edge) GetTo() string {
	if x != nil {
		return x.To
	}
	return ""
}

func (x *Edge) GetEdgeType() string {
	if x != nil {
		return x.EdgeType
	}
	return ""
}

var File_accessgraph_v1alpha_graph_proto protoreflect.FileDescriptor

var file_accessgraph_v1alpha_graph_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2f, 0x76, 0x31,
	0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x13, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76,
	0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x22, 0xf9, 0x02, 0x0a, 0x04, 0x4e, 0x6f, 0x64, 0x65, 0x12,
	0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12,
	0x12, 0x0a, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6b,
	0x69, 0x6e, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x75, 0x62, 0x5f, 0x6b, 0x69, 0x6e, 0x64, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x75, 0x62, 0x4b, 0x69, 0x6e, 0x64, 0x12, 0x12,
	0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x12, 0x3d, 0x0a, 0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x18, 0x05, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x25, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68,
	0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x2e, 0x4c, 0x61,
	0x62, 0x65, 0x6c, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c,
	0x73, 0x12, 0x1a, 0x0a, 0x08, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x08, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x49, 0x0a,
	0x0a, 0x70, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x69, 0x65, 0x73, 0x18, 0x07, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x29, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e,
	0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x2e, 0x50, 0x72, 0x6f,
	0x70, 0x65, 0x72, 0x74, 0x69, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0a, 0x70, 0x72,
	0x6f, 0x70, 0x65, 0x72, 0x74, 0x69, 0x65, 0x73, 0x1a, 0x39, 0x0a, 0x0b, 0x4c, 0x61, 0x62, 0x65,
	0x6c, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a,
	0x02, 0x38, 0x01, 0x1a, 0x3d, 0x0a, 0x0f, 0x50, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x69, 0x65,
	0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02,
	0x38, 0x01, 0x22, 0x47, 0x0a, 0x04, 0x45, 0x64, 0x67, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x66, 0x72,
	0x6f, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x12, 0x0e,
	0x0a, 0x02, 0x74, 0x6f, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x74, 0x6f, 0x12, 0x1b,
	0x0a, 0x09, 0x65, 0x64, 0x67, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x08, 0x65, 0x64, 0x67, 0x65, 0x54, 0x79, 0x70, 0x65, 0x42, 0x57, 0x5a, 0x55, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74,
	0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x61, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68,
	0x61, 0x3b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x76, 0x31, 0x61,
	0x6c, 0x70, 0x68, 0x61, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_accessgraph_v1alpha_graph_proto_rawDescOnce sync.Once
	file_accessgraph_v1alpha_graph_proto_rawDescData = file_accessgraph_v1alpha_graph_proto_rawDesc
)

func file_accessgraph_v1alpha_graph_proto_rawDescGZIP() []byte {
	file_accessgraph_v1alpha_graph_proto_rawDescOnce.Do(func() {
		file_accessgraph_v1alpha_graph_proto_rawDescData = protoimpl.X.CompressGZIP(file_accessgraph_v1alpha_graph_proto_rawDescData)
	})
	return file_accessgraph_v1alpha_graph_proto_rawDescData
}

var file_accessgraph_v1alpha_graph_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_accessgraph_v1alpha_graph_proto_goTypes = []interface{}{
	(*Node)(nil), // 0: accessgraph.v1alpha.Node
	(*Edge)(nil), // 1: accessgraph.v1alpha.Edge
	nil,          // 2: accessgraph.v1alpha.Node.LabelsEntry
	nil,          // 3: accessgraph.v1alpha.Node.PropertiesEntry
}
var file_accessgraph_v1alpha_graph_proto_depIdxs = []int32{
	2, // 0: accessgraph.v1alpha.Node.labels:type_name -> accessgraph.v1alpha.Node.LabelsEntry
	3, // 1: accessgraph.v1alpha.Node.properties:type_name -> accessgraph.v1alpha.Node.PropertiesEntry
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_accessgraph_v1alpha_graph_proto_init() }
func file_accessgraph_v1alpha_graph_proto_init() {
	if File_accessgraph_v1alpha_graph_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_accessgraph_v1alpha_graph_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Node); i {
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
		file_accessgraph_v1alpha_graph_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Edge); i {
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
			RawDescriptor: file_accessgraph_v1alpha_graph_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_accessgraph_v1alpha_graph_proto_goTypes,
		DependencyIndexes: file_accessgraph_v1alpha_graph_proto_depIdxs,
		MessageInfos:      file_accessgraph_v1alpha_graph_proto_msgTypes,
	}.Build()
	File_accessgraph_v1alpha_graph_proto = out.File
	file_accessgraph_v1alpha_graph_proto_rawDesc = nil
	file_accessgraph_v1alpha_graph_proto_goTypes = nil
	file_accessgraph_v1alpha_graph_proto_depIdxs = nil
}
