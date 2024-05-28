//
// Teleport
// Copyright (C) 2023  Gravitational, Inc.
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

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: teleport/lib/teleterm/v1/tshd_events_service.proto

package teletermv1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	TshdEventsService_Relogin_FullMethodName                           = "/teleport.lib.teleterm.v1.TshdEventsService/Relogin"
	TshdEventsService_SendNotification_FullMethodName                  = "/teleport.lib.teleterm.v1.TshdEventsService/SendNotification"
	TshdEventsService_SendPendingHeadlessAuthentication_FullMethodName = "/teleport.lib.teleterm.v1.TshdEventsService/SendPendingHeadlessAuthentication"
	TshdEventsService_PromptMFA_FullMethodName                         = "/teleport.lib.teleterm.v1.TshdEventsService/PromptMFA"
	TshdEventsService_GetUsageReportingSettings_FullMethodName         = "/teleport.lib.teleterm.v1.TshdEventsService/GetUsageReportingSettings"
	TshdEventsService_ReportUnexpectedVnetShutdown_FullMethodName      = "/teleport.lib.teleterm.v1.TshdEventsService/ReportUnexpectedVnetShutdown"
)

// TshdEventsServiceClient is the client API for TshdEventsService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TshdEventsServiceClient interface {
	// Relogin makes the Electron app display a login modal for the specific root cluster. The request
	// returns a response after the relogin procedure has been successfully finished.
	Relogin(ctx context.Context, in *ReloginRequest, opts ...grpc.CallOption) (*ReloginResponse, error)
	// SendNotification causes the Electron app to display a notification in the UI. The request
	// accepts a specific message rather than a generic string so that the Electron is in control as
	// to what message is displayed and how exactly it looks.
	SendNotification(ctx context.Context, in *SendNotificationRequest, opts ...grpc.CallOption) (*SendNotificationResponse, error)
	// SendPendingHeadlessAuthentication notifies the Electron app of a pending headless authentication,
	// which it can use to initiate headless authentication resolution in the UI.
	SendPendingHeadlessAuthentication(ctx context.Context, in *SendPendingHeadlessAuthenticationRequest, opts ...grpc.CallOption) (*SendPendingHeadlessAuthenticationResponse, error)
	// PromptMFA notifies the Electron app that the daemon is waiting for the user to answer an MFA prompt.
	// If Webauthn is supported, tsh daemon starts another goroutine which readies the hardware key.
	// If TOTP is supported, tsh daemon expects that the Electron app responds to this RPC with the
	// code.
	PromptMFA(ctx context.Context, in *PromptMFARequest, opts ...grpc.CallOption) (*PromptMFAResponse, error)
	// GetUsageReportingSettings returns the current state of usage reporting.
	// At the moment, the user cannot toggle usage reporting on and off without shutting down the app,
	// with the only exception being the first start of the app when they're prompted about telemetry.
	// Hence why this is an RPC and not information passed over argv to tsh daemon.
	GetUsageReportingSettings(ctx context.Context, in *GetUsageReportingSettingsRequest, opts ...grpc.CallOption) (*GetUsageReportingSettingsResponse, error)
	// ReportUnexpectedVnetShutdown is sent by tsh daemon when VNet exits outside of the
	// request-response cycle of Start and Stop RPCs of VnetService. The Electron app is then able to
	// update the state of VNet in the UI.
	ReportUnexpectedVnetShutdown(ctx context.Context, in *ReportUnexpectedVnetShutdownRequest, opts ...grpc.CallOption) (*ReportUnexpectedVnetShutdownResponse, error)
}

type tshdEventsServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewTshdEventsServiceClient(cc grpc.ClientConnInterface) TshdEventsServiceClient {
	return &tshdEventsServiceClient{cc}
}

func (c *tshdEventsServiceClient) Relogin(ctx context.Context, in *ReloginRequest, opts ...grpc.CallOption) (*ReloginResponse, error) {
	out := new(ReloginResponse)
	err := c.cc.Invoke(ctx, TshdEventsService_Relogin_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tshdEventsServiceClient) SendNotification(ctx context.Context, in *SendNotificationRequest, opts ...grpc.CallOption) (*SendNotificationResponse, error) {
	out := new(SendNotificationResponse)
	err := c.cc.Invoke(ctx, TshdEventsService_SendNotification_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tshdEventsServiceClient) SendPendingHeadlessAuthentication(ctx context.Context, in *SendPendingHeadlessAuthenticationRequest, opts ...grpc.CallOption) (*SendPendingHeadlessAuthenticationResponse, error) {
	out := new(SendPendingHeadlessAuthenticationResponse)
	err := c.cc.Invoke(ctx, TshdEventsService_SendPendingHeadlessAuthentication_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tshdEventsServiceClient) PromptMFA(ctx context.Context, in *PromptMFARequest, opts ...grpc.CallOption) (*PromptMFAResponse, error) {
	out := new(PromptMFAResponse)
	err := c.cc.Invoke(ctx, TshdEventsService_PromptMFA_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tshdEventsServiceClient) GetUsageReportingSettings(ctx context.Context, in *GetUsageReportingSettingsRequest, opts ...grpc.CallOption) (*GetUsageReportingSettingsResponse, error) {
	out := new(GetUsageReportingSettingsResponse)
	err := c.cc.Invoke(ctx, TshdEventsService_GetUsageReportingSettings_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tshdEventsServiceClient) ReportUnexpectedVnetShutdown(ctx context.Context, in *ReportUnexpectedVnetShutdownRequest, opts ...grpc.CallOption) (*ReportUnexpectedVnetShutdownResponse, error) {
	out := new(ReportUnexpectedVnetShutdownResponse)
	err := c.cc.Invoke(ctx, TshdEventsService_ReportUnexpectedVnetShutdown_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TshdEventsServiceServer is the server API for TshdEventsService service.
// All implementations must embed UnimplementedTshdEventsServiceServer
// for forward compatibility
type TshdEventsServiceServer interface {
	// Relogin makes the Electron app display a login modal for the specific root cluster. The request
	// returns a response after the relogin procedure has been successfully finished.
	Relogin(context.Context, *ReloginRequest) (*ReloginResponse, error)
	// SendNotification causes the Electron app to display a notification in the UI. The request
	// accepts a specific message rather than a generic string so that the Electron is in control as
	// to what message is displayed and how exactly it looks.
	SendNotification(context.Context, *SendNotificationRequest) (*SendNotificationResponse, error)
	// SendPendingHeadlessAuthentication notifies the Electron app of a pending headless authentication,
	// which it can use to initiate headless authentication resolution in the UI.
	SendPendingHeadlessAuthentication(context.Context, *SendPendingHeadlessAuthenticationRequest) (*SendPendingHeadlessAuthenticationResponse, error)
	// PromptMFA notifies the Electron app that the daemon is waiting for the user to answer an MFA prompt.
	// If Webauthn is supported, tsh daemon starts another goroutine which readies the hardware key.
	// If TOTP is supported, tsh daemon expects that the Electron app responds to this RPC with the
	// code.
	PromptMFA(context.Context, *PromptMFARequest) (*PromptMFAResponse, error)
	// GetUsageReportingSettings returns the current state of usage reporting.
	// At the moment, the user cannot toggle usage reporting on and off without shutting down the app,
	// with the only exception being the first start of the app when they're prompted about telemetry.
	// Hence why this is an RPC and not information passed over argv to tsh daemon.
	GetUsageReportingSettings(context.Context, *GetUsageReportingSettingsRequest) (*GetUsageReportingSettingsResponse, error)
	// ReportUnexpectedVnetShutdown is sent by tsh daemon when VNet exits outside of the
	// request-response cycle of Start and Stop RPCs of VnetService. The Electron app is then able to
	// update the state of VNet in the UI.
	ReportUnexpectedVnetShutdown(context.Context, *ReportUnexpectedVnetShutdownRequest) (*ReportUnexpectedVnetShutdownResponse, error)
	mustEmbedUnimplementedTshdEventsServiceServer()
}

// UnimplementedTshdEventsServiceServer must be embedded to have forward compatible implementations.
type UnimplementedTshdEventsServiceServer struct {
}

func (UnimplementedTshdEventsServiceServer) Relogin(context.Context, *ReloginRequest) (*ReloginResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Relogin not implemented")
}
func (UnimplementedTshdEventsServiceServer) SendNotification(context.Context, *SendNotificationRequest) (*SendNotificationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendNotification not implemented")
}
func (UnimplementedTshdEventsServiceServer) SendPendingHeadlessAuthentication(context.Context, *SendPendingHeadlessAuthenticationRequest) (*SendPendingHeadlessAuthenticationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendPendingHeadlessAuthentication not implemented")
}
func (UnimplementedTshdEventsServiceServer) PromptMFA(context.Context, *PromptMFARequest) (*PromptMFAResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PromptMFA not implemented")
}
func (UnimplementedTshdEventsServiceServer) GetUsageReportingSettings(context.Context, *GetUsageReportingSettingsRequest) (*GetUsageReportingSettingsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUsageReportingSettings not implemented")
}
func (UnimplementedTshdEventsServiceServer) ReportUnexpectedVnetShutdown(context.Context, *ReportUnexpectedVnetShutdownRequest) (*ReportUnexpectedVnetShutdownResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReportUnexpectedVnetShutdown not implemented")
}
func (UnimplementedTshdEventsServiceServer) mustEmbedUnimplementedTshdEventsServiceServer() {}

// UnsafeTshdEventsServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to TshdEventsServiceServer will
// result in compilation errors.
type UnsafeTshdEventsServiceServer interface {
	mustEmbedUnimplementedTshdEventsServiceServer()
}

func RegisterTshdEventsServiceServer(s grpc.ServiceRegistrar, srv TshdEventsServiceServer) {
	s.RegisterService(&TshdEventsService_ServiceDesc, srv)
}

func _TshdEventsService_Relogin_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReloginRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TshdEventsServiceServer).Relogin(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TshdEventsService_Relogin_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TshdEventsServiceServer).Relogin(ctx, req.(*ReloginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TshdEventsService_SendNotification_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SendNotificationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TshdEventsServiceServer).SendNotification(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TshdEventsService_SendNotification_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TshdEventsServiceServer).SendNotification(ctx, req.(*SendNotificationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TshdEventsService_SendPendingHeadlessAuthentication_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SendPendingHeadlessAuthenticationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TshdEventsServiceServer).SendPendingHeadlessAuthentication(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TshdEventsService_SendPendingHeadlessAuthentication_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TshdEventsServiceServer).SendPendingHeadlessAuthentication(ctx, req.(*SendPendingHeadlessAuthenticationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TshdEventsService_PromptMFA_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PromptMFARequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TshdEventsServiceServer).PromptMFA(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TshdEventsService_PromptMFA_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TshdEventsServiceServer).PromptMFA(ctx, req.(*PromptMFARequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TshdEventsService_GetUsageReportingSettings_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetUsageReportingSettingsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TshdEventsServiceServer).GetUsageReportingSettings(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TshdEventsService_GetUsageReportingSettings_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TshdEventsServiceServer).GetUsageReportingSettings(ctx, req.(*GetUsageReportingSettingsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TshdEventsService_ReportUnexpectedVnetShutdown_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReportUnexpectedVnetShutdownRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TshdEventsServiceServer).ReportUnexpectedVnetShutdown(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TshdEventsService_ReportUnexpectedVnetShutdown_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TshdEventsServiceServer).ReportUnexpectedVnetShutdown(ctx, req.(*ReportUnexpectedVnetShutdownRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// TshdEventsService_ServiceDesc is the grpc.ServiceDesc for TshdEventsService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var TshdEventsService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "teleport.lib.teleterm.v1.TshdEventsService",
	HandlerType: (*TshdEventsServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Relogin",
			Handler:    _TshdEventsService_Relogin_Handler,
		},
		{
			MethodName: "SendNotification",
			Handler:    _TshdEventsService_SendNotification_Handler,
		},
		{
			MethodName: "SendPendingHeadlessAuthentication",
			Handler:    _TshdEventsService_SendPendingHeadlessAuthentication_Handler,
		},
		{
			MethodName: "PromptMFA",
			Handler:    _TshdEventsService_PromptMFA_Handler,
		},
		{
			MethodName: "GetUsageReportingSettings",
			Handler:    _TshdEventsService_GetUsageReportingSettings_Handler,
		},
		{
			MethodName: "ReportUnexpectedVnetShutdown",
			Handler:    _TshdEventsService_ReportUnexpectedVnetShutdown_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "teleport/lib/teleterm/v1/tshd_events_service.proto",
}
