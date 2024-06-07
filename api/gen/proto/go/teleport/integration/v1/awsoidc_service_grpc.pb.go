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

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.4.0
// - protoc             (unknown)
// source: teleport/integration/v1/awsoidc_service.proto

package integrationv1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.62.0 or later.
const _ = grpc.SupportPackageIsVersion8

const (
	AWSOIDCService_ListEICE_FullMethodName              = "/teleport.integration.v1.AWSOIDCService/ListEICE"
	AWSOIDCService_CreateEICE_FullMethodName            = "/teleport.integration.v1.AWSOIDCService/CreateEICE"
	AWSOIDCService_ListDatabases_FullMethodName         = "/teleport.integration.v1.AWSOIDCService/ListDatabases"
	AWSOIDCService_ListSecurityGroups_FullMethodName    = "/teleport.integration.v1.AWSOIDCService/ListSecurityGroups"
	AWSOIDCService_DeployDatabaseService_FullMethodName = "/teleport.integration.v1.AWSOIDCService/DeployDatabaseService"
	AWSOIDCService_DeployService_FullMethodName         = "/teleport.integration.v1.AWSOIDCService/DeployService"
	AWSOIDCService_EnrollEKSClusters_FullMethodName     = "/teleport.integration.v1.AWSOIDCService/EnrollEKSClusters"
	AWSOIDCService_ListEC2_FullMethodName               = "/teleport.integration.v1.AWSOIDCService/ListEC2"
	AWSOIDCService_ListEKSClusters_FullMethodName       = "/teleport.integration.v1.AWSOIDCService/ListEKSClusters"
)

// AWSOIDCServiceClient is the client API for AWSOIDCService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// AWSOIDCService provides access to AWS APIs using the AWS OIDC Integration.
type AWSOIDCServiceClient interface {
	// ListEICE returns a list of EC2 Instance Connect Endpoints.
	// An optional NextToken that can be used to fetch the next page.
	// It uses the following API:
	// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstanceConnectEndpoints.html
	ListEICE(ctx context.Context, in *ListEICERequest, opts ...grpc.CallOption) (*ListEICEResponse, error)
	// CreateEICE creates multiple EC2 Instance Connect Endpoint using the provided Subnets and Security Group IDs.
	// It uses the following API:
	// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateInstanceConnectEndpoint.html
	CreateEICE(ctx context.Context, in *CreateEICERequest, opts ...grpc.CallOption) (*CreateEICEResponse, error)
	// ListDatabases calls the following AWS API:
	// https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBClusters.html
	// https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html
	// It returns a list of Databases and an optional NextToken that can be used to fetch the next page
	ListDatabases(ctx context.Context, in *ListDatabasesRequest, opts ...grpc.CallOption) (*ListDatabasesResponse, error)
	// ListSecurityGroups returns a list of AWS VPC SecurityGroups.
	// It uses the following API:
	// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html
	ListSecurityGroups(ctx context.Context, in *ListSecurityGroupsRequest, opts ...grpc.CallOption) (*ListSecurityGroupsResponse, error)
	// DeployDatabaseService deploys a Database Services to Amazon ECS.
	DeployDatabaseService(ctx context.Context, in *DeployDatabaseServiceRequest, opts ...grpc.CallOption) (*DeployDatabaseServiceResponse, error)
	// DeployService deploys an ECS Service to Amazon ECS.
	DeployService(ctx context.Context, in *DeployServiceRequest, opts ...grpc.CallOption) (*DeployServiceResponse, error)
	// EnrollEKSClusters enrolls EKS clusters by installing kube agent Helm chart.
	EnrollEKSClusters(ctx context.Context, in *EnrollEKSClustersRequest, opts ...grpc.CallOption) (*EnrollEKSClustersResponse, error)
	// ListEC2 lists the EC2 instances of the AWS account per region.
	// It uses the following API:
	// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html
	ListEC2(ctx context.Context, in *ListEC2Request, opts ...grpc.CallOption) (*ListEC2Response, error)
	// ListEKSClusters retrieves a paginated list of EKS clusters in the specified AWS region for a specific account.
	// It uses the following APIs:
	// https://docs.aws.amazon.com/eks/latest/APIReference/API_ListClusters.html
	// https://docs.aws.amazon.com/eks/latest/APIReference/API_DescribeCluster.html
	ListEKSClusters(ctx context.Context, in *ListEKSClustersRequest, opts ...grpc.CallOption) (*ListEKSClustersResponse, error)
}

type aWSOIDCServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAWSOIDCServiceClient(cc grpc.ClientConnInterface) AWSOIDCServiceClient {
	return &aWSOIDCServiceClient{cc}
}

func (c *aWSOIDCServiceClient) ListEICE(ctx context.Context, in *ListEICERequest, opts ...grpc.CallOption) (*ListEICEResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListEICEResponse)
	err := c.cc.Invoke(ctx, AWSOIDCService_ListEICE_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aWSOIDCServiceClient) CreateEICE(ctx context.Context, in *CreateEICERequest, opts ...grpc.CallOption) (*CreateEICEResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CreateEICEResponse)
	err := c.cc.Invoke(ctx, AWSOIDCService_CreateEICE_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aWSOIDCServiceClient) ListDatabases(ctx context.Context, in *ListDatabasesRequest, opts ...grpc.CallOption) (*ListDatabasesResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListDatabasesResponse)
	err := c.cc.Invoke(ctx, AWSOIDCService_ListDatabases_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aWSOIDCServiceClient) ListSecurityGroups(ctx context.Context, in *ListSecurityGroupsRequest, opts ...grpc.CallOption) (*ListSecurityGroupsResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListSecurityGroupsResponse)
	err := c.cc.Invoke(ctx, AWSOIDCService_ListSecurityGroups_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aWSOIDCServiceClient) DeployDatabaseService(ctx context.Context, in *DeployDatabaseServiceRequest, opts ...grpc.CallOption) (*DeployDatabaseServiceResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(DeployDatabaseServiceResponse)
	err := c.cc.Invoke(ctx, AWSOIDCService_DeployDatabaseService_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aWSOIDCServiceClient) DeployService(ctx context.Context, in *DeployServiceRequest, opts ...grpc.CallOption) (*DeployServiceResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(DeployServiceResponse)
	err := c.cc.Invoke(ctx, AWSOIDCService_DeployService_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aWSOIDCServiceClient) EnrollEKSClusters(ctx context.Context, in *EnrollEKSClustersRequest, opts ...grpc.CallOption) (*EnrollEKSClustersResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(EnrollEKSClustersResponse)
	err := c.cc.Invoke(ctx, AWSOIDCService_EnrollEKSClusters_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aWSOIDCServiceClient) ListEC2(ctx context.Context, in *ListEC2Request, opts ...grpc.CallOption) (*ListEC2Response, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListEC2Response)
	err := c.cc.Invoke(ctx, AWSOIDCService_ListEC2_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aWSOIDCServiceClient) ListEKSClusters(ctx context.Context, in *ListEKSClustersRequest, opts ...grpc.CallOption) (*ListEKSClustersResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListEKSClustersResponse)
	err := c.cc.Invoke(ctx, AWSOIDCService_ListEKSClusters_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AWSOIDCServiceServer is the server API for AWSOIDCService service.
// All implementations must embed UnimplementedAWSOIDCServiceServer
// for forward compatibility
//
// AWSOIDCService provides access to AWS APIs using the AWS OIDC Integration.
type AWSOIDCServiceServer interface {
	// ListEICE returns a list of EC2 Instance Connect Endpoints.
	// An optional NextToken that can be used to fetch the next page.
	// It uses the following API:
	// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstanceConnectEndpoints.html
	ListEICE(context.Context, *ListEICERequest) (*ListEICEResponse, error)
	// CreateEICE creates multiple EC2 Instance Connect Endpoint using the provided Subnets and Security Group IDs.
	// It uses the following API:
	// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateInstanceConnectEndpoint.html
	CreateEICE(context.Context, *CreateEICERequest) (*CreateEICEResponse, error)
	// ListDatabases calls the following AWS API:
	// https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBClusters.html
	// https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html
	// It returns a list of Databases and an optional NextToken that can be used to fetch the next page
	ListDatabases(context.Context, *ListDatabasesRequest) (*ListDatabasesResponse, error)
	// ListSecurityGroups returns a list of AWS VPC SecurityGroups.
	// It uses the following API:
	// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html
	ListSecurityGroups(context.Context, *ListSecurityGroupsRequest) (*ListSecurityGroupsResponse, error)
	// DeployDatabaseService deploys a Database Services to Amazon ECS.
	DeployDatabaseService(context.Context, *DeployDatabaseServiceRequest) (*DeployDatabaseServiceResponse, error)
	// DeployService deploys an ECS Service to Amazon ECS.
	DeployService(context.Context, *DeployServiceRequest) (*DeployServiceResponse, error)
	// EnrollEKSClusters enrolls EKS clusters by installing kube agent Helm chart.
	EnrollEKSClusters(context.Context, *EnrollEKSClustersRequest) (*EnrollEKSClustersResponse, error)
	// ListEC2 lists the EC2 instances of the AWS account per region.
	// It uses the following API:
	// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html
	ListEC2(context.Context, *ListEC2Request) (*ListEC2Response, error)
	// ListEKSClusters retrieves a paginated list of EKS clusters in the specified AWS region for a specific account.
	// It uses the following APIs:
	// https://docs.aws.amazon.com/eks/latest/APIReference/API_ListClusters.html
	// https://docs.aws.amazon.com/eks/latest/APIReference/API_DescribeCluster.html
	ListEKSClusters(context.Context, *ListEKSClustersRequest) (*ListEKSClustersResponse, error)
	mustEmbedUnimplementedAWSOIDCServiceServer()
}

// UnimplementedAWSOIDCServiceServer must be embedded to have forward compatible implementations.
type UnimplementedAWSOIDCServiceServer struct {
}

func (UnimplementedAWSOIDCServiceServer) ListEICE(context.Context, *ListEICERequest) (*ListEICEResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListEICE not implemented")
}
func (UnimplementedAWSOIDCServiceServer) CreateEICE(context.Context, *CreateEICERequest) (*CreateEICEResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateEICE not implemented")
}
func (UnimplementedAWSOIDCServiceServer) ListDatabases(context.Context, *ListDatabasesRequest) (*ListDatabasesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListDatabases not implemented")
}
func (UnimplementedAWSOIDCServiceServer) ListSecurityGroups(context.Context, *ListSecurityGroupsRequest) (*ListSecurityGroupsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListSecurityGroups not implemented")
}
func (UnimplementedAWSOIDCServiceServer) DeployDatabaseService(context.Context, *DeployDatabaseServiceRequest) (*DeployDatabaseServiceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeployDatabaseService not implemented")
}
func (UnimplementedAWSOIDCServiceServer) DeployService(context.Context, *DeployServiceRequest) (*DeployServiceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeployService not implemented")
}
func (UnimplementedAWSOIDCServiceServer) EnrollEKSClusters(context.Context, *EnrollEKSClustersRequest) (*EnrollEKSClustersResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method EnrollEKSClusters not implemented")
}
func (UnimplementedAWSOIDCServiceServer) ListEC2(context.Context, *ListEC2Request) (*ListEC2Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListEC2 not implemented")
}
func (UnimplementedAWSOIDCServiceServer) ListEKSClusters(context.Context, *ListEKSClustersRequest) (*ListEKSClustersResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListEKSClusters not implemented")
}
func (UnimplementedAWSOIDCServiceServer) mustEmbedUnimplementedAWSOIDCServiceServer() {}

// UnsafeAWSOIDCServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AWSOIDCServiceServer will
// result in compilation errors.
type UnsafeAWSOIDCServiceServer interface {
	mustEmbedUnimplementedAWSOIDCServiceServer()
}

func RegisterAWSOIDCServiceServer(s grpc.ServiceRegistrar, srv AWSOIDCServiceServer) {
	s.RegisterService(&AWSOIDCService_ServiceDesc, srv)
}

func _AWSOIDCService_ListEICE_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListEICERequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AWSOIDCServiceServer).ListEICE(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AWSOIDCService_ListEICE_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AWSOIDCServiceServer).ListEICE(ctx, req.(*ListEICERequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AWSOIDCService_CreateEICE_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateEICERequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AWSOIDCServiceServer).CreateEICE(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AWSOIDCService_CreateEICE_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AWSOIDCServiceServer).CreateEICE(ctx, req.(*CreateEICERequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AWSOIDCService_ListDatabases_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListDatabasesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AWSOIDCServiceServer).ListDatabases(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AWSOIDCService_ListDatabases_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AWSOIDCServiceServer).ListDatabases(ctx, req.(*ListDatabasesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AWSOIDCService_ListSecurityGroups_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListSecurityGroupsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AWSOIDCServiceServer).ListSecurityGroups(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AWSOIDCService_ListSecurityGroups_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AWSOIDCServiceServer).ListSecurityGroups(ctx, req.(*ListSecurityGroupsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AWSOIDCService_DeployDatabaseService_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeployDatabaseServiceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AWSOIDCServiceServer).DeployDatabaseService(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AWSOIDCService_DeployDatabaseService_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AWSOIDCServiceServer).DeployDatabaseService(ctx, req.(*DeployDatabaseServiceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AWSOIDCService_DeployService_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeployServiceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AWSOIDCServiceServer).DeployService(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AWSOIDCService_DeployService_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AWSOIDCServiceServer).DeployService(ctx, req.(*DeployServiceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AWSOIDCService_EnrollEKSClusters_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EnrollEKSClustersRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AWSOIDCServiceServer).EnrollEKSClusters(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AWSOIDCService_EnrollEKSClusters_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AWSOIDCServiceServer).EnrollEKSClusters(ctx, req.(*EnrollEKSClustersRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AWSOIDCService_ListEC2_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListEC2Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AWSOIDCServiceServer).ListEC2(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AWSOIDCService_ListEC2_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AWSOIDCServiceServer).ListEC2(ctx, req.(*ListEC2Request))
	}
	return interceptor(ctx, in, info, handler)
}

func _AWSOIDCService_ListEKSClusters_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListEKSClustersRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AWSOIDCServiceServer).ListEKSClusters(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AWSOIDCService_ListEKSClusters_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AWSOIDCServiceServer).ListEKSClusters(ctx, req.(*ListEKSClustersRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// AWSOIDCService_ServiceDesc is the grpc.ServiceDesc for AWSOIDCService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AWSOIDCService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "teleport.integration.v1.AWSOIDCService",
	HandlerType: (*AWSOIDCServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ListEICE",
			Handler:    _AWSOIDCService_ListEICE_Handler,
		},
		{
			MethodName: "CreateEICE",
			Handler:    _AWSOIDCService_CreateEICE_Handler,
		},
		{
			MethodName: "ListDatabases",
			Handler:    _AWSOIDCService_ListDatabases_Handler,
		},
		{
			MethodName: "ListSecurityGroups",
			Handler:    _AWSOIDCService_ListSecurityGroups_Handler,
		},
		{
			MethodName: "DeployDatabaseService",
			Handler:    _AWSOIDCService_DeployDatabaseService_Handler,
		},
		{
			MethodName: "DeployService",
			Handler:    _AWSOIDCService_DeployService_Handler,
		},
		{
			MethodName: "EnrollEKSClusters",
			Handler:    _AWSOIDCService_EnrollEKSClusters_Handler,
		},
		{
			MethodName: "ListEC2",
			Handler:    _AWSOIDCService_ListEC2_Handler,
		},
		{
			MethodName: "ListEKSClusters",
			Handler:    _AWSOIDCService_ListEKSClusters_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "teleport/integration/v1/awsoidc_service.proto",
}
