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
// 	protoc-gen-go v1.32.0
// 	protoc        (unknown)
// source: teleport/integration/v1/awsoidc_service.proto

package integrationv1

import (
	types "github.com/gravitational/teleport/api/types"
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

// ListDatabasesRequest is a request for a paginated list of AWS Databases.
type ListDatabasesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Integration is the AWS OIDC Integration name.
	Integration string `protobuf:"bytes,1,opt,name=integration,proto3" json:"integration,omitempty"`
	// Region is the AWS Region
	Region string `protobuf:"bytes,2,opt,name=region,proto3" json:"region,omitempty"`
	// RDSType is either instance or cluster (for Aurora DBs).
	RdsType string `protobuf:"bytes,3,opt,name=rds_type,json=rdsType,proto3" json:"rds_type,omitempty"`
	// Engines filters the returned Databases based on their engine.
	// Eg, mysql, postgres, mariadb, aurora, aurora-mysql, aurora-postgresql
	Engines []string `protobuf:"bytes,4,rep,name=engines,proto3" json:"engines,omitempty"`
	// NextToken is the token to be used to fetch the next page.
	// If empty, the first page is fetched.
	NextToken string `protobuf:"bytes,5,opt,name=next_token,json=nextToken,proto3" json:"next_token,omitempty"`
}

func (x *ListDatabasesRequest) Reset() {
	*x = ListDatabasesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_integration_v1_awsoidc_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListDatabasesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListDatabasesRequest) ProtoMessage() {}

func (x *ListDatabasesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_integration_v1_awsoidc_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListDatabasesRequest.ProtoReflect.Descriptor instead.
func (*ListDatabasesRequest) Descriptor() ([]byte, []int) {
	return file_teleport_integration_v1_awsoidc_service_proto_rawDescGZIP(), []int{0}
}

func (x *ListDatabasesRequest) GetIntegration() string {
	if x != nil {
		return x.Integration
	}
	return ""
}

func (x *ListDatabasesRequest) GetRegion() string {
	if x != nil {
		return x.Region
	}
	return ""
}

func (x *ListDatabasesRequest) GetRdsType() string {
	if x != nil {
		return x.RdsType
	}
	return ""
}

func (x *ListDatabasesRequest) GetEngines() []string {
	if x != nil {
		return x.Engines
	}
	return nil
}

func (x *ListDatabasesRequest) GetNextToken() string {
	if x != nil {
		return x.NextToken
	}
	return ""
}

// ListDatabasesResponse contains a page of AWS Databases.
type ListDatabasesResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Databases contains the page of Databases.
	Databases []*types.DatabaseV3 `protobuf:"bytes,1,rep,name=databases,proto3" json:"databases,omitempty"`
	// NextToken is used for pagination.
	// If non-empty, it can be used to request the next page.
	NextToken string `protobuf:"bytes,2,opt,name=next_token,json=nextToken,proto3" json:"next_token,omitempty"`
}

func (x *ListDatabasesResponse) Reset() {
	*x = ListDatabasesResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_integration_v1_awsoidc_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListDatabasesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListDatabasesResponse) ProtoMessage() {}

func (x *ListDatabasesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_integration_v1_awsoidc_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListDatabasesResponse.ProtoReflect.Descriptor instead.
func (*ListDatabasesResponse) Descriptor() ([]byte, []int) {
	return file_teleport_integration_v1_awsoidc_service_proto_rawDescGZIP(), []int{1}
}

func (x *ListDatabasesResponse) GetDatabases() []*types.DatabaseV3 {
	if x != nil {
		return x.Databases
	}
	return nil
}

func (x *ListDatabasesResponse) GetNextToken() string {
	if x != nil {
		return x.NextToken
	}
	return ""
}

// DeployDatabaseServiceRequest is a request to deploy .
type DeployDatabaseServiceRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Integration is the AWS OIDC Integration name.
	Integration string `protobuf:"bytes,1,opt,name=integration,proto3" json:"integration,omitempty"`
	// Region is the AWS Region
	Region string `protobuf:"bytes,2,opt,name=region,proto3" json:"region,omitempty"`
	// TaskRoleARN is the AWS IAM Role received by the deployed service.
	TaskRoleArn string `protobuf:"bytes,3,opt,name=task_role_arn,json=taskRoleArn,proto3" json:"task_role_arn,omitempty"`
	// TeleportVersion is the teleport version to be deployed.
	// This is used to fetch the correct tag for the teleport container image.
	// Eg, 14.3.4 (no "v" prefix)
	TeleportVersion string `protobuf:"bytes,4,opt,name=teleport_version,json=teleportVersion,proto3" json:"teleport_version,omitempty"`
	// DeploymentJoinTokenName is the Teleport IAM Join Token to be used by the deployed
	// service to join the cluster.
	DeploymentJoinTokenName string `protobuf:"bytes,5,opt,name=deployment_join_token_name,json=deploymentJoinTokenName,proto3" json:"deployment_join_token_name,omitempty"`
	// Deployments is a list of services that will be deployed.
	Deployments []*DeployDatabaseServiceDeployment `protobuf:"bytes,6,rep,name=deployments,proto3" json:"deployments,omitempty"`
}

func (x *DeployDatabaseServiceRequest) Reset() {
	*x = DeployDatabaseServiceRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_integration_v1_awsoidc_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeployDatabaseServiceRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeployDatabaseServiceRequest) ProtoMessage() {}

func (x *DeployDatabaseServiceRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_integration_v1_awsoidc_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeployDatabaseServiceRequest.ProtoReflect.Descriptor instead.
func (*DeployDatabaseServiceRequest) Descriptor() ([]byte, []int) {
	return file_teleport_integration_v1_awsoidc_service_proto_rawDescGZIP(), []int{2}
}

func (x *DeployDatabaseServiceRequest) GetIntegration() string {
	if x != nil {
		return x.Integration
	}
	return ""
}

func (x *DeployDatabaseServiceRequest) GetRegion() string {
	if x != nil {
		return x.Region
	}
	return ""
}

func (x *DeployDatabaseServiceRequest) GetTaskRoleArn() string {
	if x != nil {
		return x.TaskRoleArn
	}
	return ""
}

func (x *DeployDatabaseServiceRequest) GetTeleportVersion() string {
	if x != nil {
		return x.TeleportVersion
	}
	return ""
}

func (x *DeployDatabaseServiceRequest) GetDeploymentJoinTokenName() string {
	if x != nil {
		return x.DeploymentJoinTokenName
	}
	return ""
}

func (x *DeployDatabaseServiceRequest) GetDeployments() []*DeployDatabaseServiceDeployment {
	if x != nil {
		return x.Deployments
	}
	return nil
}

// DeployDatabaseServiceDeployment represents a single deployment.
type DeployDatabaseServiceDeployment struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// TeleportConfigString is the teleport.yaml configuration (base64 encoded) used by teleport.
	TeleportConfigString string `protobuf:"bytes,1,opt,name=teleport_config_string,json=teleportConfigString,proto3" json:"teleport_config_string,omitempty"`
	// VpcId is the VPCID where the service is going to be deployed.
	VpcId string `protobuf:"bytes,2,opt,name=vpc_id,json=vpcId,proto3" json:"vpc_id,omitempty"`
	// SubnetIds are the subnets for the network configuration.
	// They must belong to the VpcId above.
	SubnetIds []string `protobuf:"bytes,3,rep,name=subnet_ids,json=subnetIds,proto3" json:"subnet_ids,omitempty"`
	// SecurityGroups are the SecurityGroup IDs to associate with this particular deployment.
	// If empty, the default security group for the VPC is going to be used.
	SecurityGroups []string `protobuf:"bytes,4,rep,name=security_groups,json=securityGroups,proto3" json:"security_groups,omitempty"`
}

func (x *DeployDatabaseServiceDeployment) Reset() {
	*x = DeployDatabaseServiceDeployment{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_integration_v1_awsoidc_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeployDatabaseServiceDeployment) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeployDatabaseServiceDeployment) ProtoMessage() {}

func (x *DeployDatabaseServiceDeployment) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_integration_v1_awsoidc_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeployDatabaseServiceDeployment.ProtoReflect.Descriptor instead.
func (*DeployDatabaseServiceDeployment) Descriptor() ([]byte, []int) {
	return file_teleport_integration_v1_awsoidc_service_proto_rawDescGZIP(), []int{3}
}

func (x *DeployDatabaseServiceDeployment) GetTeleportConfigString() string {
	if x != nil {
		return x.TeleportConfigString
	}
	return ""
}

func (x *DeployDatabaseServiceDeployment) GetVpcId() string {
	if x != nil {
		return x.VpcId
	}
	return ""
}

func (x *DeployDatabaseServiceDeployment) GetSubnetIds() []string {
	if x != nil {
		return x.SubnetIds
	}
	return nil
}

func (x *DeployDatabaseServiceDeployment) GetSecurityGroups() []string {
	if x != nil {
		return x.SecurityGroups
	}
	return nil
}

// DeployDatabaseServiceResponse contains information about the deployed service.
type DeployDatabaseServiceResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ClusterArn identifies the cluster where the deployment was made.
	ClusterArn string `protobuf:"bytes,1,opt,name=cluster_arn,json=clusterArn,proto3" json:"cluster_arn,omitempty"`
	// ClusterDashboardUrl is the URL for Amazon Web Console that links directly to the Amazon ECS Cluster.
	ClusterDashboardUrl string `protobuf:"bytes,2,opt,name=cluster_dashboard_url,json=clusterDashboardUrl,proto3" json:"cluster_dashboard_url,omitempty"`
}

func (x *DeployDatabaseServiceResponse) Reset() {
	*x = DeployDatabaseServiceResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_integration_v1_awsoidc_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeployDatabaseServiceResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeployDatabaseServiceResponse) ProtoMessage() {}

func (x *DeployDatabaseServiceResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_integration_v1_awsoidc_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeployDatabaseServiceResponse.ProtoReflect.Descriptor instead.
func (*DeployDatabaseServiceResponse) Descriptor() ([]byte, []int) {
	return file_teleport_integration_v1_awsoidc_service_proto_rawDescGZIP(), []int{4}
}

func (x *DeployDatabaseServiceResponse) GetClusterArn() string {
	if x != nil {
		return x.ClusterArn
	}
	return ""
}

func (x *DeployDatabaseServiceResponse) GetClusterDashboardUrl() string {
	if x != nil {
		return x.ClusterDashboardUrl
	}
	return ""
}

var File_teleport_integration_v1_awsoidc_service_proto protoreflect.FileDescriptor

var file_teleport_integration_v1_awsoidc_service_proto_rawDesc = []byte{
	0x0a, 0x2d, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x67,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x77, 0x73, 0x6f, 0x69, 0x64,
	0x63, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x17, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x1a, 0x21, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x2f, 0x6c, 0x65, 0x67, 0x61, 0x63, 0x79, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f,
	0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa4, 0x01, 0x0a, 0x14,
	0x4c, 0x69, 0x73, 0x74, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x73, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x69, 0x6e, 0x74, 0x65, 0x67,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x67, 0x69, 0x6f, 0x6e,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x72, 0x65, 0x67, 0x69, 0x6f, 0x6e, 0x12, 0x19,
	0x0a, 0x08, 0x72, 0x64, 0x73, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x07, 0x72, 0x64, 0x73, 0x54, 0x79, 0x70, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x65, 0x6e, 0x67,
	0x69, 0x6e, 0x65, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x09, 0x52, 0x07, 0x65, 0x6e, 0x67, 0x69,
	0x6e, 0x65, 0x73, 0x12, 0x1d, 0x0a, 0x0a, 0x6e, 0x65, 0x78, 0x74, 0x5f, 0x74, 0x6f, 0x6b, 0x65,
	0x6e, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6e, 0x65, 0x78, 0x74, 0x54, 0x6f, 0x6b,
	0x65, 0x6e, 0x22, 0x67, 0x0a, 0x15, 0x4c, 0x69, 0x73, 0x74, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61,
	0x73, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2f, 0x0a, 0x09, 0x64,
	0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x11,
	0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x56,
	0x33, 0x52, 0x09, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x73, 0x12, 0x1d, 0x0a, 0x0a,
	0x6e, 0x65, 0x78, 0x74, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x09, 0x6e, 0x65, 0x78, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0xc0, 0x02, 0x0a, 0x1c,
	0x44, 0x65, 0x70, 0x6c, 0x6f, 0x79, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x20, 0x0a, 0x0b,
	0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0b, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x16,
	0x0a, 0x06, 0x72, 0x65, 0x67, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06,
	0x72, 0x65, 0x67, 0x69, 0x6f, 0x6e, 0x12, 0x22, 0x0a, 0x0d, 0x74, 0x61, 0x73, 0x6b, 0x5f, 0x72,
	0x6f, 0x6c, 0x65, 0x5f, 0x61, 0x72, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x74,
	0x61, 0x73, 0x6b, 0x52, 0x6f, 0x6c, 0x65, 0x41, 0x72, 0x6e, 0x12, 0x29, 0x0a, 0x10, 0x74, 0x65,
	0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x56, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x3b, 0x0a, 0x1a, 0x64, 0x65, 0x70, 0x6c, 0x6f, 0x79, 0x6d,
	0x65, 0x6e, 0x74, 0x5f, 0x6a, 0x6f, 0x69, 0x6e, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x5f, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x17, 0x64, 0x65, 0x70, 0x6c, 0x6f,
	0x79, 0x6d, 0x65, 0x6e, 0x74, 0x4a, 0x6f, 0x69, 0x6e, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x4e, 0x61,
	0x6d, 0x65, 0x12, 0x5a, 0x0a, 0x0b, 0x64, 0x65, 0x70, 0x6c, 0x6f, 0x79, 0x6d, 0x65, 0x6e, 0x74,
	0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x38, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76,
	0x31, 0x2e, 0x44, 0x65, 0x70, 0x6c, 0x6f, 0x79, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65,
	0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x44, 0x65, 0x70, 0x6c, 0x6f, 0x79, 0x6d, 0x65, 0x6e,
	0x74, 0x52, 0x0b, 0x64, 0x65, 0x70, 0x6c, 0x6f, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x22, 0xb6,
	0x01, 0x0a, 0x1f, 0x44, 0x65, 0x70, 0x6c, 0x6f, 0x79, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73,
	0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x44, 0x65, 0x70, 0x6c, 0x6f, 0x79, 0x6d, 0x65,
	0x6e, 0x74, 0x12, 0x34, 0x0a, 0x16, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x5f, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x14, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x12, 0x15, 0x0a, 0x06, 0x76, 0x70, 0x63, 0x5f,
	0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x70, 0x63, 0x49, 0x64, 0x12,
	0x1d, 0x0a, 0x0a, 0x73, 0x75, 0x62, 0x6e, 0x65, 0x74, 0x5f, 0x69, 0x64, 0x73, 0x18, 0x03, 0x20,
	0x03, 0x28, 0x09, 0x52, 0x09, 0x73, 0x75, 0x62, 0x6e, 0x65, 0x74, 0x49, 0x64, 0x73, 0x12, 0x27,
	0x0a, 0x0f, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x5f, 0x67, 0x72, 0x6f, 0x75, 0x70,
	0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74,
	0x79, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x22, 0x74, 0x0a, 0x1d, 0x44, 0x65, 0x70, 0x6c, 0x6f,
	0x79, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x63, 0x6c, 0x75, 0x73,
	0x74, 0x65, 0x72, 0x5f, 0x61, 0x72, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x63,
	0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x41, 0x72, 0x6e, 0x12, 0x32, 0x0a, 0x15, 0x63, 0x6c, 0x75,
	0x73, 0x74, 0x65, 0x72, 0x5f, 0x64, 0x61, 0x73, 0x68, 0x62, 0x6f, 0x61, 0x72, 0x64, 0x5f, 0x75,
	0x72, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x13, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65,
	0x72, 0x44, 0x61, 0x73, 0x68, 0x62, 0x6f, 0x61, 0x72, 0x64, 0x55, 0x72, 0x6c, 0x32, 0x89, 0x02,
	0x0a, 0x0e, 0x41, 0x57, 0x53, 0x4f, 0x49, 0x44, 0x43, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x12, 0x6e, 0x0a, 0x0d, 0x4c, 0x69, 0x73, 0x74, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65,
	0x73, 0x12, 0x2d, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74,
	0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74,
	0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x2e, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65,
	0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x44,
	0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x86, 0x01, 0x0a, 0x15, 0x44, 0x65, 0x70, 0x6c, 0x6f, 0x79, 0x44, 0x61, 0x74, 0x61, 0x62,
	0x61, 0x73, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x35, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x65, 0x70, 0x6c, 0x6f, 0x79, 0x44, 0x61, 0x74, 0x61, 0x62,
	0x61, 0x73, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x36, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74,
	0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x65, 0x70, 0x6c,
	0x6f, 0x79, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x5a, 0x5a, 0x58, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61,
	0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x3b, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_integration_v1_awsoidc_service_proto_rawDescOnce sync.Once
	file_teleport_integration_v1_awsoidc_service_proto_rawDescData = file_teleport_integration_v1_awsoidc_service_proto_rawDesc
)

func file_teleport_integration_v1_awsoidc_service_proto_rawDescGZIP() []byte {
	file_teleport_integration_v1_awsoidc_service_proto_rawDescOnce.Do(func() {
		file_teleport_integration_v1_awsoidc_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_integration_v1_awsoidc_service_proto_rawDescData)
	})
	return file_teleport_integration_v1_awsoidc_service_proto_rawDescData
}

var file_teleport_integration_v1_awsoidc_service_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_teleport_integration_v1_awsoidc_service_proto_goTypes = []interface{}{
	(*ListDatabasesRequest)(nil),            // 0: teleport.integration.v1.ListDatabasesRequest
	(*ListDatabasesResponse)(nil),           // 1: teleport.integration.v1.ListDatabasesResponse
	(*DeployDatabaseServiceRequest)(nil),    // 2: teleport.integration.v1.DeployDatabaseServiceRequest
	(*DeployDatabaseServiceDeployment)(nil), // 3: teleport.integration.v1.DeployDatabaseServiceDeployment
	(*DeployDatabaseServiceResponse)(nil),   // 4: teleport.integration.v1.DeployDatabaseServiceResponse
	(*types.DatabaseV3)(nil),                // 5: types.DatabaseV3
}
var file_teleport_integration_v1_awsoidc_service_proto_depIdxs = []int32{
	5, // 0: teleport.integration.v1.ListDatabasesResponse.databases:type_name -> types.DatabaseV3
	3, // 1: teleport.integration.v1.DeployDatabaseServiceRequest.deployments:type_name -> teleport.integration.v1.DeployDatabaseServiceDeployment
	0, // 2: teleport.integration.v1.AWSOIDCService.ListDatabases:input_type -> teleport.integration.v1.ListDatabasesRequest
	2, // 3: teleport.integration.v1.AWSOIDCService.DeployDatabaseService:input_type -> teleport.integration.v1.DeployDatabaseServiceRequest
	1, // 4: teleport.integration.v1.AWSOIDCService.ListDatabases:output_type -> teleport.integration.v1.ListDatabasesResponse
	4, // 5: teleport.integration.v1.AWSOIDCService.DeployDatabaseService:output_type -> teleport.integration.v1.DeployDatabaseServiceResponse
	4, // [4:6] is the sub-list for method output_type
	2, // [2:4] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_teleport_integration_v1_awsoidc_service_proto_init() }
func file_teleport_integration_v1_awsoidc_service_proto_init() {
	if File_teleport_integration_v1_awsoidc_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleport_integration_v1_awsoidc_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListDatabasesRequest); i {
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
		file_teleport_integration_v1_awsoidc_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListDatabasesResponse); i {
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
		file_teleport_integration_v1_awsoidc_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeployDatabaseServiceRequest); i {
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
		file_teleport_integration_v1_awsoidc_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeployDatabaseServiceDeployment); i {
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
		file_teleport_integration_v1_awsoidc_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeployDatabaseServiceResponse); i {
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
			RawDescriptor: file_teleport_integration_v1_awsoidc_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_teleport_integration_v1_awsoidc_service_proto_goTypes,
		DependencyIndexes: file_teleport_integration_v1_awsoidc_service_proto_depIdxs,
		MessageInfos:      file_teleport_integration_v1_awsoidc_service_proto_msgTypes,
	}.Build()
	File_teleport_integration_v1_awsoidc_service_proto = out.File
	file_teleport_integration_v1_awsoidc_service_proto_rawDesc = nil
	file_teleport_integration_v1_awsoidc_service_proto_goTypes = nil
	file_teleport_integration_v1_awsoidc_service_proto_depIdxs = nil
}
