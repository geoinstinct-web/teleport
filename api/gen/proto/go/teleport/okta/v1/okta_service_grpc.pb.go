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
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: teleport/okta/v1/okta_service.proto

package v1

import (
	context "context"
	types "github.com/gravitational/teleport/api/types"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	OktaService_ListOktaImportRules_FullMethodName                = "/teleport.okta.v1.OktaService/ListOktaImportRules"
	OktaService_GetOktaImportRule_FullMethodName                  = "/teleport.okta.v1.OktaService/GetOktaImportRule"
	OktaService_CreateOktaImportRule_FullMethodName               = "/teleport.okta.v1.OktaService/CreateOktaImportRule"
	OktaService_UpdateOktaImportRule_FullMethodName               = "/teleport.okta.v1.OktaService/UpdateOktaImportRule"
	OktaService_DeleteOktaImportRule_FullMethodName               = "/teleport.okta.v1.OktaService/DeleteOktaImportRule"
	OktaService_DeleteAllOktaImportRules_FullMethodName           = "/teleport.okta.v1.OktaService/DeleteAllOktaImportRules"
	OktaService_ListOktaAssignments_FullMethodName                = "/teleport.okta.v1.OktaService/ListOktaAssignments"
	OktaService_GetOktaAssignment_FullMethodName                  = "/teleport.okta.v1.OktaService/GetOktaAssignment"
	OktaService_CreateOktaAssignment_FullMethodName               = "/teleport.okta.v1.OktaService/CreateOktaAssignment"
	OktaService_UpdateOktaAssignment_FullMethodName               = "/teleport.okta.v1.OktaService/UpdateOktaAssignment"
	OktaService_UpdateOktaAssignmentActionStatuses_FullMethodName = "/teleport.okta.v1.OktaService/UpdateOktaAssignmentActionStatuses"
	OktaService_DeleteOktaAssignment_FullMethodName               = "/teleport.okta.v1.OktaService/DeleteOktaAssignment"
	OktaService_DeleteAllOktaAssignments_FullMethodName           = "/teleport.okta.v1.OktaService/DeleteAllOktaAssignments"
)

// OktaServiceClient is the client API for OktaService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type OktaServiceClient interface {
	// ListOktaImportRules returns a paginated list of all Okta import rule resources.
	ListOktaImportRules(ctx context.Context, in *ListOktaImportRulesRequest, opts ...grpc.CallOption) (*ListOktaImportRulesResponse, error)
	// GetOktaImportRule returns the specified Okta import rule resources.
	GetOktaImportRule(ctx context.Context, in *GetOktaImportRuleRequest, opts ...grpc.CallOption) (*types.OktaImportRuleV1, error)
	// CreateOktaImportRule creates a new Okta import rule resource.
	CreateOktaImportRule(ctx context.Context, in *CreateOktaImportRuleRequest, opts ...grpc.CallOption) (*types.OktaImportRuleV1, error)
	// UpdateOktaImportRule updates an existing Okta import rule resource.
	UpdateOktaImportRule(ctx context.Context, in *UpdateOktaImportRuleRequest, opts ...grpc.CallOption) (*types.OktaImportRuleV1, error)
	// DeleteOktaImportRule removes the specified Okta import rule resource.
	DeleteOktaImportRule(ctx context.Context, in *DeleteOktaImportRuleRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	// DeleteAllOktaImportRules removes all Okta import rules.
	DeleteAllOktaImportRules(ctx context.Context, in *DeleteAllOktaImportRulesRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	// ListOktaAssignments returns a paginated list of all Okta assignment resources.
	ListOktaAssignments(ctx context.Context, in *ListOktaAssignmentsRequest, opts ...grpc.CallOption) (*ListOktaAssignmentsResponse, error)
	// GetOktaAssignment returns the specified Okta assignment resources.
	GetOktaAssignment(ctx context.Context, in *GetOktaAssignmentRequest, opts ...grpc.CallOption) (*types.OktaAssignmentV1, error)
	// CreateOktaAssignment creates a new Okta assignment resource.
	CreateOktaAssignment(ctx context.Context, in *CreateOktaAssignmentRequest, opts ...grpc.CallOption) (*types.OktaAssignmentV1, error)
	// UpdateOktaAssignment updates an existing Okta assignment resource.
	UpdateOktaAssignment(ctx context.Context, in *UpdateOktaAssignmentRequest, opts ...grpc.CallOption) (*types.OktaAssignmentV1, error)
	// UpdateOktaAssignmentActionStatuses will update the statuses for all actions in an Okta assignment if the
	// status is a valid transition. Invalid transitions will be skipped.
	UpdateOktaAssignmentActionStatuses(ctx context.Context, in *UpdateOktaAssignmentActionStatusesRequest, opts ...grpc.CallOption) (*types.OktaAssignmentV1, error)
	// DeleteOktaAssignment removes the specified Okta assignment resource.
	DeleteOktaAssignment(ctx context.Context, in *DeleteOktaAssignmentRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	// DeleteAllOktaAssignments removes all Okta assignments.
	DeleteAllOktaAssignments(ctx context.Context, in *DeleteAllOktaAssignmentsRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type oktaServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewOktaServiceClient(cc grpc.ClientConnInterface) OktaServiceClient {
	return &oktaServiceClient{cc}
}

func (c *oktaServiceClient) ListOktaImportRules(ctx context.Context, in *ListOktaImportRulesRequest, opts ...grpc.CallOption) (*ListOktaImportRulesResponse, error) {
	out := new(ListOktaImportRulesResponse)
	err := c.cc.Invoke(ctx, OktaService_ListOktaImportRules_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *oktaServiceClient) GetOktaImportRule(ctx context.Context, in *GetOktaImportRuleRequest, opts ...grpc.CallOption) (*types.OktaImportRuleV1, error) {
	out := new(types.OktaImportRuleV1)
	err := c.cc.Invoke(ctx, OktaService_GetOktaImportRule_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *oktaServiceClient) CreateOktaImportRule(ctx context.Context, in *CreateOktaImportRuleRequest, opts ...grpc.CallOption) (*types.OktaImportRuleV1, error) {
	out := new(types.OktaImportRuleV1)
	err := c.cc.Invoke(ctx, OktaService_CreateOktaImportRule_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *oktaServiceClient) UpdateOktaImportRule(ctx context.Context, in *UpdateOktaImportRuleRequest, opts ...grpc.CallOption) (*types.OktaImportRuleV1, error) {
	out := new(types.OktaImportRuleV1)
	err := c.cc.Invoke(ctx, OktaService_UpdateOktaImportRule_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *oktaServiceClient) DeleteOktaImportRule(ctx context.Context, in *DeleteOktaImportRuleRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, OktaService_DeleteOktaImportRule_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *oktaServiceClient) DeleteAllOktaImportRules(ctx context.Context, in *DeleteAllOktaImportRulesRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, OktaService_DeleteAllOktaImportRules_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *oktaServiceClient) ListOktaAssignments(ctx context.Context, in *ListOktaAssignmentsRequest, opts ...grpc.CallOption) (*ListOktaAssignmentsResponse, error) {
	out := new(ListOktaAssignmentsResponse)
	err := c.cc.Invoke(ctx, OktaService_ListOktaAssignments_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *oktaServiceClient) GetOktaAssignment(ctx context.Context, in *GetOktaAssignmentRequest, opts ...grpc.CallOption) (*types.OktaAssignmentV1, error) {
	out := new(types.OktaAssignmentV1)
	err := c.cc.Invoke(ctx, OktaService_GetOktaAssignment_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *oktaServiceClient) CreateOktaAssignment(ctx context.Context, in *CreateOktaAssignmentRequest, opts ...grpc.CallOption) (*types.OktaAssignmentV1, error) {
	out := new(types.OktaAssignmentV1)
	err := c.cc.Invoke(ctx, OktaService_CreateOktaAssignment_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *oktaServiceClient) UpdateOktaAssignment(ctx context.Context, in *UpdateOktaAssignmentRequest, opts ...grpc.CallOption) (*types.OktaAssignmentV1, error) {
	out := new(types.OktaAssignmentV1)
	err := c.cc.Invoke(ctx, OktaService_UpdateOktaAssignment_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *oktaServiceClient) UpdateOktaAssignmentActionStatuses(ctx context.Context, in *UpdateOktaAssignmentActionStatusesRequest, opts ...grpc.CallOption) (*types.OktaAssignmentV1, error) {
	out := new(types.OktaAssignmentV1)
	err := c.cc.Invoke(ctx, OktaService_UpdateOktaAssignmentActionStatuses_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *oktaServiceClient) DeleteOktaAssignment(ctx context.Context, in *DeleteOktaAssignmentRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, OktaService_DeleteOktaAssignment_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *oktaServiceClient) DeleteAllOktaAssignments(ctx context.Context, in *DeleteAllOktaAssignmentsRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, OktaService_DeleteAllOktaAssignments_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// OktaServiceServer is the server API for OktaService service.
// All implementations must embed UnimplementedOktaServiceServer
// for forward compatibility
type OktaServiceServer interface {
	// ListOktaImportRules returns a paginated list of all Okta import rule resources.
	ListOktaImportRules(context.Context, *ListOktaImportRulesRequest) (*ListOktaImportRulesResponse, error)
	// GetOktaImportRule returns the specified Okta import rule resources.
	GetOktaImportRule(context.Context, *GetOktaImportRuleRequest) (*types.OktaImportRuleV1, error)
	// CreateOktaImportRule creates a new Okta import rule resource.
	CreateOktaImportRule(context.Context, *CreateOktaImportRuleRequest) (*types.OktaImportRuleV1, error)
	// UpdateOktaImportRule updates an existing Okta import rule resource.
	UpdateOktaImportRule(context.Context, *UpdateOktaImportRuleRequest) (*types.OktaImportRuleV1, error)
	// DeleteOktaImportRule removes the specified Okta import rule resource.
	DeleteOktaImportRule(context.Context, *DeleteOktaImportRuleRequest) (*emptypb.Empty, error)
	// DeleteAllOktaImportRules removes all Okta import rules.
	DeleteAllOktaImportRules(context.Context, *DeleteAllOktaImportRulesRequest) (*emptypb.Empty, error)
	// ListOktaAssignments returns a paginated list of all Okta assignment resources.
	ListOktaAssignments(context.Context, *ListOktaAssignmentsRequest) (*ListOktaAssignmentsResponse, error)
	// GetOktaAssignment returns the specified Okta assignment resources.
	GetOktaAssignment(context.Context, *GetOktaAssignmentRequest) (*types.OktaAssignmentV1, error)
	// CreateOktaAssignment creates a new Okta assignment resource.
	CreateOktaAssignment(context.Context, *CreateOktaAssignmentRequest) (*types.OktaAssignmentV1, error)
	// UpdateOktaAssignment updates an existing Okta assignment resource.
	UpdateOktaAssignment(context.Context, *UpdateOktaAssignmentRequest) (*types.OktaAssignmentV1, error)
	// UpdateOktaAssignmentActionStatuses will update the statuses for all actions in an Okta assignment if the
	// status is a valid transition. Invalid transitions will be skipped.
	UpdateOktaAssignmentActionStatuses(context.Context, *UpdateOktaAssignmentActionStatusesRequest) (*types.OktaAssignmentV1, error)
	// DeleteOktaAssignment removes the specified Okta assignment resource.
	DeleteOktaAssignment(context.Context, *DeleteOktaAssignmentRequest) (*emptypb.Empty, error)
	// DeleteAllOktaAssignments removes all Okta assignments.
	DeleteAllOktaAssignments(context.Context, *DeleteAllOktaAssignmentsRequest) (*emptypb.Empty, error)
	mustEmbedUnimplementedOktaServiceServer()
}

// UnimplementedOktaServiceServer must be embedded to have forward compatible implementations.
type UnimplementedOktaServiceServer struct {
}

func (UnimplementedOktaServiceServer) ListOktaImportRules(context.Context, *ListOktaImportRulesRequest) (*ListOktaImportRulesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListOktaImportRules not implemented")
}
func (UnimplementedOktaServiceServer) GetOktaImportRule(context.Context, *GetOktaImportRuleRequest) (*types.OktaImportRuleV1, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetOktaImportRule not implemented")
}
func (UnimplementedOktaServiceServer) CreateOktaImportRule(context.Context, *CreateOktaImportRuleRequest) (*types.OktaImportRuleV1, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateOktaImportRule not implemented")
}
func (UnimplementedOktaServiceServer) UpdateOktaImportRule(context.Context, *UpdateOktaImportRuleRequest) (*types.OktaImportRuleV1, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateOktaImportRule not implemented")
}
func (UnimplementedOktaServiceServer) DeleteOktaImportRule(context.Context, *DeleteOktaImportRuleRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteOktaImportRule not implemented")
}
func (UnimplementedOktaServiceServer) DeleteAllOktaImportRules(context.Context, *DeleteAllOktaImportRulesRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteAllOktaImportRules not implemented")
}
func (UnimplementedOktaServiceServer) ListOktaAssignments(context.Context, *ListOktaAssignmentsRequest) (*ListOktaAssignmentsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListOktaAssignments not implemented")
}
func (UnimplementedOktaServiceServer) GetOktaAssignment(context.Context, *GetOktaAssignmentRequest) (*types.OktaAssignmentV1, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetOktaAssignment not implemented")
}
func (UnimplementedOktaServiceServer) CreateOktaAssignment(context.Context, *CreateOktaAssignmentRequest) (*types.OktaAssignmentV1, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateOktaAssignment not implemented")
}
func (UnimplementedOktaServiceServer) UpdateOktaAssignment(context.Context, *UpdateOktaAssignmentRequest) (*types.OktaAssignmentV1, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateOktaAssignment not implemented")
}
func (UnimplementedOktaServiceServer) UpdateOktaAssignmentActionStatuses(context.Context, *UpdateOktaAssignmentActionStatusesRequest) (*types.OktaAssignmentV1, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateOktaAssignmentActionStatuses not implemented")
}
func (UnimplementedOktaServiceServer) DeleteOktaAssignment(context.Context, *DeleteOktaAssignmentRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteOktaAssignment not implemented")
}
func (UnimplementedOktaServiceServer) DeleteAllOktaAssignments(context.Context, *DeleteAllOktaAssignmentsRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteAllOktaAssignments not implemented")
}
func (UnimplementedOktaServiceServer) mustEmbedUnimplementedOktaServiceServer() {}

// UnsafeOktaServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to OktaServiceServer will
// result in compilation errors.
type UnsafeOktaServiceServer interface {
	mustEmbedUnimplementedOktaServiceServer()
}

func RegisterOktaServiceServer(s grpc.ServiceRegistrar, srv OktaServiceServer) {
	s.RegisterService(&OktaService_ServiceDesc, srv)
}

func _OktaService_ListOktaImportRules_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListOktaImportRulesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OktaServiceServer).ListOktaImportRules(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: OktaService_ListOktaImportRules_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OktaServiceServer).ListOktaImportRules(ctx, req.(*ListOktaImportRulesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _OktaService_GetOktaImportRule_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetOktaImportRuleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OktaServiceServer).GetOktaImportRule(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: OktaService_GetOktaImportRule_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OktaServiceServer).GetOktaImportRule(ctx, req.(*GetOktaImportRuleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _OktaService_CreateOktaImportRule_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateOktaImportRuleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OktaServiceServer).CreateOktaImportRule(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: OktaService_CreateOktaImportRule_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OktaServiceServer).CreateOktaImportRule(ctx, req.(*CreateOktaImportRuleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _OktaService_UpdateOktaImportRule_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateOktaImportRuleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OktaServiceServer).UpdateOktaImportRule(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: OktaService_UpdateOktaImportRule_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OktaServiceServer).UpdateOktaImportRule(ctx, req.(*UpdateOktaImportRuleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _OktaService_DeleteOktaImportRule_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteOktaImportRuleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OktaServiceServer).DeleteOktaImportRule(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: OktaService_DeleteOktaImportRule_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OktaServiceServer).DeleteOktaImportRule(ctx, req.(*DeleteOktaImportRuleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _OktaService_DeleteAllOktaImportRules_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteAllOktaImportRulesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OktaServiceServer).DeleteAllOktaImportRules(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: OktaService_DeleteAllOktaImportRules_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OktaServiceServer).DeleteAllOktaImportRules(ctx, req.(*DeleteAllOktaImportRulesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _OktaService_ListOktaAssignments_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListOktaAssignmentsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OktaServiceServer).ListOktaAssignments(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: OktaService_ListOktaAssignments_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OktaServiceServer).ListOktaAssignments(ctx, req.(*ListOktaAssignmentsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _OktaService_GetOktaAssignment_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetOktaAssignmentRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OktaServiceServer).GetOktaAssignment(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: OktaService_GetOktaAssignment_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OktaServiceServer).GetOktaAssignment(ctx, req.(*GetOktaAssignmentRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _OktaService_CreateOktaAssignment_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateOktaAssignmentRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OktaServiceServer).CreateOktaAssignment(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: OktaService_CreateOktaAssignment_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OktaServiceServer).CreateOktaAssignment(ctx, req.(*CreateOktaAssignmentRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _OktaService_UpdateOktaAssignment_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateOktaAssignmentRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OktaServiceServer).UpdateOktaAssignment(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: OktaService_UpdateOktaAssignment_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OktaServiceServer).UpdateOktaAssignment(ctx, req.(*UpdateOktaAssignmentRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _OktaService_UpdateOktaAssignmentActionStatuses_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateOktaAssignmentActionStatusesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OktaServiceServer).UpdateOktaAssignmentActionStatuses(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: OktaService_UpdateOktaAssignmentActionStatuses_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OktaServiceServer).UpdateOktaAssignmentActionStatuses(ctx, req.(*UpdateOktaAssignmentActionStatusesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _OktaService_DeleteOktaAssignment_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteOktaAssignmentRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OktaServiceServer).DeleteOktaAssignment(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: OktaService_DeleteOktaAssignment_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OktaServiceServer).DeleteOktaAssignment(ctx, req.(*DeleteOktaAssignmentRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _OktaService_DeleteAllOktaAssignments_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteAllOktaAssignmentsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OktaServiceServer).DeleteAllOktaAssignments(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: OktaService_DeleteAllOktaAssignments_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OktaServiceServer).DeleteAllOktaAssignments(ctx, req.(*DeleteAllOktaAssignmentsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// OktaService_ServiceDesc is the grpc.ServiceDesc for OktaService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var OktaService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "teleport.okta.v1.OktaService",
	HandlerType: (*OktaServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ListOktaImportRules",
			Handler:    _OktaService_ListOktaImportRules_Handler,
		},
		{
			MethodName: "GetOktaImportRule",
			Handler:    _OktaService_GetOktaImportRule_Handler,
		},
		{
			MethodName: "CreateOktaImportRule",
			Handler:    _OktaService_CreateOktaImportRule_Handler,
		},
		{
			MethodName: "UpdateOktaImportRule",
			Handler:    _OktaService_UpdateOktaImportRule_Handler,
		},
		{
			MethodName: "DeleteOktaImportRule",
			Handler:    _OktaService_DeleteOktaImportRule_Handler,
		},
		{
			MethodName: "DeleteAllOktaImportRules",
			Handler:    _OktaService_DeleteAllOktaImportRules_Handler,
		},
		{
			MethodName: "ListOktaAssignments",
			Handler:    _OktaService_ListOktaAssignments_Handler,
		},
		{
			MethodName: "GetOktaAssignment",
			Handler:    _OktaService_GetOktaAssignment_Handler,
		},
		{
			MethodName: "CreateOktaAssignment",
			Handler:    _OktaService_CreateOktaAssignment_Handler,
		},
		{
			MethodName: "UpdateOktaAssignment",
			Handler:    _OktaService_UpdateOktaAssignment_Handler,
		},
		{
			MethodName: "UpdateOktaAssignmentActionStatuses",
			Handler:    _OktaService_UpdateOktaAssignmentActionStatuses_Handler,
		},
		{
			MethodName: "DeleteOktaAssignment",
			Handler:    _OktaService_DeleteOktaAssignment_Handler,
		},
		{
			MethodName: "DeleteAllOktaAssignments",
			Handler:    _OktaService_DeleteAllOktaAssignments_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "teleport/okta/v1/okta_service.proto",
}
