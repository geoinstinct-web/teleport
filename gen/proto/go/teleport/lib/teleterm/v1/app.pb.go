//
// Teleport
// Copyright (C) 2024 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        (unknown)
// source: teleport/lib/teleterm/v1/app.proto

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

// App describes an app resource.
type App struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// uri uniquely identifies an app within Teleport Connect.
	Uri string `protobuf:"bytes,1,opt,name=uri,proto3" json:"uri,omitempty"`
	// name is the name of the app.
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	// endpoint_uri is the URI to which the app service is going to proxy requests. It corresponds to
	// app_service.apps[].uri in the Teleport configuration.
	EndpointUri string `protobuf:"bytes,3,opt,name=endpoint_uri,json=endpointUri,proto3" json:"endpoint_uri,omitempty"`
	// desc is the app description.
	Desc string `protobuf:"bytes,4,opt,name=desc,proto3" json:"desc,omitempty"`
	// aws_console is true if this app is AWS management console.
	AwsConsole bool `protobuf:"varint,5,opt,name=aws_console,json=awsConsole,proto3" json:"aws_console,omitempty"`
	// public_addr is the public address the application is accessible at.
	//
	// If the app resource has its public_addr field set, this field returns the value of public_addr
	// from the app resource.
	//
	// If the app resource does not have public_addr field set, this field returns the name of the app
	// under the proxy hostname of the cluster to which the app belongs, e.g.,
	// dumper.root-cluster.com, example-app.leaf-cluster.org.
	//
	// In both cases public_addr does not include a port number. An app resource cannot include a port
	// number in its public_addr, as the backend will (wrongly) reject such resource with an error
	// saying "public_addr "example.com:1337" can not contain a port, applications will be available
	// on the same port as the web proxy". This is obviously not the case for custom public addresses.
	// Ultimately, it means that public_addr alone is not enough to access the app, unless either the
	// cluster or the custom domain use the default port of 443.
	//
	// Always empty for SAML applications.
	PublicAddr string `protobuf:"bytes,6,opt,name=public_addr,json=publicAddr,proto3" json:"public_addr,omitempty"`
	// friendly_name is a user readable name of the app.
	// Right now, it is set only for Okta applications.
	// It is constructed from a label value.
	// See more in api/types/resource.go.
	FriendlyName string `protobuf:"bytes,7,opt,name=friendly_name,json=friendlyName,proto3" json:"friendly_name,omitempty"`
	// saml_app is true if the application is a SAML Application (Service Provider).
	SamlApp bool `protobuf:"varint,8,opt,name=saml_app,json=samlApp,proto3" json:"saml_app,omitempty"`
	// labels is a list of labels for the app.
	Labels []*Label `protobuf:"bytes,9,rep,name=labels,proto3" json:"labels,omitempty"`
	// fqdn is the hostname under which the app is accessible within the root cluster. It is used by
	// the Web UI to route the requests from the /web/launch URL to the correct app. fqdn by itself
	// does not include the port number, so fqdn alone cannot be used to launch an app, hence why it's
	// incorporated into the /web/launch URL.
	//
	// If the app belongs to a root cluster, fqdn is equal to public_addr or [name].[root cluster
	// proxy hostname] if public_addr is not present.
	// If the app belongs to a leaf cluster, fqdn is equal to [name].[root cluster proxy hostname].
	//
	// fqdn is not present for SAML applications.
	Fqdn string `protobuf:"bytes,10,opt,name=fqdn,proto3" json:"fqdn,omitempty"`
	// aws_roles is a list of AWS IAM roles for the application representing AWS console.
	AwsRoles []*AWSRole `protobuf:"bytes,11,rep,name=aws_roles,json=awsRoles,proto3" json:"aws_roles,omitempty"`
}

func (x *App) Reset() {
	*x = App{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_lib_teleterm_v1_app_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *App) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*App) ProtoMessage() {}

func (x *App) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_lib_teleterm_v1_app_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use App.ProtoReflect.Descriptor instead.
func (*App) Descriptor() ([]byte, []int) {
	return file_teleport_lib_teleterm_v1_app_proto_rawDescGZIP(), []int{0}
}

func (x *App) GetUri() string {
	if x != nil {
		return x.Uri
	}
	return ""
}

func (x *App) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *App) GetEndpointUri() string {
	if x != nil {
		return x.EndpointUri
	}
	return ""
}

func (x *App) GetDesc() string {
	if x != nil {
		return x.Desc
	}
	return ""
}

func (x *App) GetAwsConsole() bool {
	if x != nil {
		return x.AwsConsole
	}
	return false
}

func (x *App) GetPublicAddr() string {
	if x != nil {
		return x.PublicAddr
	}
	return ""
}

func (x *App) GetFriendlyName() string {
	if x != nil {
		return x.FriendlyName
	}
	return ""
}

func (x *App) GetSamlApp() bool {
	if x != nil {
		return x.SamlApp
	}
	return false
}

func (x *App) GetLabels() []*Label {
	if x != nil {
		return x.Labels
	}
	return nil
}

func (x *App) GetFqdn() string {
	if x != nil {
		return x.Fqdn
	}
	return ""
}

func (x *App) GetAwsRoles() []*AWSRole {
	if x != nil {
		return x.AwsRoles
	}
	return nil
}

// AwsRole describes AWS IAM role.
type AWSRole struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Name is the full role name with the entire path.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Display is the role display name.
	Display string `protobuf:"bytes,2,opt,name=display,proto3" json:"display,omitempty"`
	// ARN is the full role ARN.
	Arn string `protobuf:"bytes,3,opt,name=arn,proto3" json:"arn,omitempty"`
	// AccountID is the AWS Account ID this role refers to.
	AccountId string `protobuf:"bytes,4,opt,name=account_id,json=accountId,proto3" json:"account_id,omitempty"`
}

func (x *AWSRole) Reset() {
	*x = AWSRole{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_lib_teleterm_v1_app_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AWSRole) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AWSRole) ProtoMessage() {}

func (x *AWSRole) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_lib_teleterm_v1_app_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AWSRole.ProtoReflect.Descriptor instead.
func (*AWSRole) Descriptor() ([]byte, []int) {
	return file_teleport_lib_teleterm_v1_app_proto_rawDescGZIP(), []int{1}
}

func (x *AWSRole) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *AWSRole) GetDisplay() string {
	if x != nil {
		return x.Display
	}
	return ""
}

func (x *AWSRole) GetArn() string {
	if x != nil {
		return x.Arn
	}
	return ""
}

func (x *AWSRole) GetAccountId() string {
	if x != nil {
		return x.AccountId
	}
	return ""
}

var File_teleport_lib_teleterm_v1_app_proto protoreflect.FileDescriptor

var file_teleport_lib_teleterm_v1_app_proto_rawDesc = []byte{
	0x0a, 0x22, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6c, 0x69, 0x62, 0x2f, 0x74,
	0x65, 0x6c, 0x65, 0x74, 0x65, 0x72, 0x6d, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x70, 0x70, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x18, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c,
	0x69, 0x62, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x72, 0x6d, 0x2e, 0x76, 0x31, 0x1a, 0x24,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6c, 0x69, 0x62, 0x2f, 0x74, 0x65, 0x6c,
	0x65, 0x74, 0x65, 0x72, 0x6d, 0x2f, 0x76, 0x31, 0x2f, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xf1, 0x02, 0x0a, 0x03, 0x41, 0x70, 0x70, 0x12, 0x10, 0x0a, 0x03,
	0x75, 0x72, 0x69, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x75, 0x72, 0x69, 0x12, 0x12,
	0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x12, 0x21, 0x0a, 0x0c, 0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x5f, 0x75,
	0x72, 0x69, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69,
	0x6e, 0x74, 0x55, 0x72, 0x69, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x65, 0x73, 0x63, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x64, 0x65, 0x73, 0x63, 0x12, 0x1f, 0x0a, 0x0b, 0x61, 0x77, 0x73,
	0x5f, 0x63, 0x6f, 0x6e, 0x73, 0x6f, 0x6c, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a,
	0x61, 0x77, 0x73, 0x43, 0x6f, 0x6e, 0x73, 0x6f, 0x6c, 0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x70, 0x75,
	0x62, 0x6c, 0x69, 0x63, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x41, 0x64, 0x64, 0x72, 0x12, 0x23, 0x0a, 0x0d, 0x66,
	0x72, 0x69, 0x65, 0x6e, 0x64, 0x6c, 0x79, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x07, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0c, 0x66, 0x72, 0x69, 0x65, 0x6e, 0x64, 0x6c, 0x79, 0x4e, 0x61, 0x6d, 0x65,
	0x12, 0x19, 0x0a, 0x08, 0x73, 0x61, 0x6d, 0x6c, 0x5f, 0x61, 0x70, 0x70, 0x18, 0x08, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x07, 0x73, 0x61, 0x6d, 0x6c, 0x41, 0x70, 0x70, 0x12, 0x37, 0x0a, 0x06, 0x6c,
	0x61, 0x62, 0x65, 0x6c, 0x73, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x74, 0x65,
	0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x69, 0x62, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x74,
	0x65, 0x72, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x52, 0x06, 0x6c, 0x61,
	0x62, 0x65, 0x6c, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x66, 0x71, 0x64, 0x6e, 0x18, 0x0a, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x66, 0x71, 0x64, 0x6e, 0x12, 0x3e, 0x0a, 0x09, 0x61, 0x77, 0x73, 0x5f,
	0x72, 0x6f, 0x6c, 0x65, 0x73, 0x18, 0x0b, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x74, 0x65,
	0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x69, 0x62, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x74,
	0x65, 0x72, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x57, 0x53, 0x52, 0x6f, 0x6c, 0x65, 0x52, 0x08,
	0x61, 0x77, 0x73, 0x52, 0x6f, 0x6c, 0x65, 0x73, 0x22, 0x68, 0x0a, 0x07, 0x41, 0x57, 0x53, 0x52,
	0x6f, 0x6c, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x64, 0x69, 0x73, 0x70, 0x6c,
	0x61, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61,
	0x79, 0x12, 0x10, 0x0a, 0x03, 0x61, 0x72, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03,
	0x61, 0x72, 0x6e, 0x12, 0x1d, 0x0a, 0x0a, 0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x5f, 0x69,
	0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74,
	0x49, 0x64, 0x42, 0x54, 0x5a, 0x52, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74,
	0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6c, 0x69,
	0x62, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x72, 0x6d, 0x2f, 0x76, 0x31, 0x3b, 0x74, 0x65,
	0x6c, 0x65, 0x74, 0x65, 0x72, 0x6d, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_lib_teleterm_v1_app_proto_rawDescOnce sync.Once
	file_teleport_lib_teleterm_v1_app_proto_rawDescData = file_teleport_lib_teleterm_v1_app_proto_rawDesc
)

func file_teleport_lib_teleterm_v1_app_proto_rawDescGZIP() []byte {
	file_teleport_lib_teleterm_v1_app_proto_rawDescOnce.Do(func() {
		file_teleport_lib_teleterm_v1_app_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_lib_teleterm_v1_app_proto_rawDescData)
	})
	return file_teleport_lib_teleterm_v1_app_proto_rawDescData
}

var file_teleport_lib_teleterm_v1_app_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_teleport_lib_teleterm_v1_app_proto_goTypes = []interface{}{
	(*App)(nil),     // 0: teleport.lib.teleterm.v1.App
	(*AWSRole)(nil), // 1: teleport.lib.teleterm.v1.AWSRole
	(*Label)(nil),   // 2: teleport.lib.teleterm.v1.Label
}
var file_teleport_lib_teleterm_v1_app_proto_depIdxs = []int32{
	2, // 0: teleport.lib.teleterm.v1.App.labels:type_name -> teleport.lib.teleterm.v1.Label
	1, // 1: teleport.lib.teleterm.v1.App.aws_roles:type_name -> teleport.lib.teleterm.v1.AWSRole
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_teleport_lib_teleterm_v1_app_proto_init() }
func file_teleport_lib_teleterm_v1_app_proto_init() {
	if File_teleport_lib_teleterm_v1_app_proto != nil {
		return
	}
	file_teleport_lib_teleterm_v1_label_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_teleport_lib_teleterm_v1_app_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*App); i {
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
		file_teleport_lib_teleterm_v1_app_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AWSRole); i {
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
			RawDescriptor: file_teleport_lib_teleterm_v1_app_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_lib_teleterm_v1_app_proto_goTypes,
		DependencyIndexes: file_teleport_lib_teleterm_v1_app_proto_depIdxs,
		MessageInfos:      file_teleport_lib_teleterm_v1_app_proto_msgTypes,
	}.Build()
	File_teleport_lib_teleterm_v1_app_proto = out.File
	file_teleport_lib_teleterm_v1_app_proto_rawDesc = nil
	file_teleport_lib_teleterm_v1_app_proto_goTypes = nil
	file_teleport_lib_teleterm_v1_app_proto_depIdxs = nil
}
