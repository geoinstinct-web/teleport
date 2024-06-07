/* eslint-disable */
// @generated by protobuf-ts 2.9.3 with parameter eslint_disable,add_pb_suffix,server_grpc1,ts_nocheck
// @generated from protobuf file "teleport/lib/teleterm/v1/tshd_events_service.proto" (package "teleport.lib.teleterm.v1", syntax proto3)
// tslint:disable
// @ts-nocheck
//
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
//
import { ReportUnexpectedVnetShutdownResponse } from "./tshd_events_service_pb";
import { ReportUnexpectedVnetShutdownRequest } from "./tshd_events_service_pb";
import { GetUsageReportingSettingsResponse } from "./tshd_events_service_pb";
import { GetUsageReportingSettingsRequest } from "./tshd_events_service_pb";
import { PromptMFAResponse } from "./tshd_events_service_pb";
import { PromptMFARequest } from "./tshd_events_service_pb";
import { SendPendingHeadlessAuthenticationResponse } from "./tshd_events_service_pb";
import { SendPendingHeadlessAuthenticationRequest } from "./tshd_events_service_pb";
import { SendNotificationResponse } from "./tshd_events_service_pb";
import { SendNotificationRequest } from "./tshd_events_service_pb";
import { ReloginResponse } from "./tshd_events_service_pb";
import { ReloginRequest } from "./tshd_events_service_pb";
import type * as grpc from "@grpc/grpc-js";
/**
 * TshdEventsService is served by the Electron app. The tsh daemon calls this service to notify the
 * app about actions that happen outside of the app itself.
 *
 * @generated from protobuf service teleport.lib.teleterm.v1.TshdEventsService
 */
export interface ITshdEventsService extends grpc.UntypedServiceImplementation {
    /**
     * Relogin makes the Electron app display a login modal for the specific root cluster. The request
     * returns a response after the relogin procedure has been successfully finished.
     *
     * @generated from protobuf rpc: Relogin(teleport.lib.teleterm.v1.ReloginRequest) returns (teleport.lib.teleterm.v1.ReloginResponse);
     */
    relogin: grpc.handleUnaryCall<ReloginRequest, ReloginResponse>;
    /**
     * SendNotification causes the Electron app to display a notification in the UI. The request
     * accepts a specific message rather than a generic string so that the Electron is in control as
     * to what message is displayed and how exactly it looks.
     *
     * @generated from protobuf rpc: SendNotification(teleport.lib.teleterm.v1.SendNotificationRequest) returns (teleport.lib.teleterm.v1.SendNotificationResponse);
     */
    sendNotification: grpc.handleUnaryCall<SendNotificationRequest, SendNotificationResponse>;
    /**
     * SendPendingHeadlessAuthentication notifies the Electron app of a pending headless authentication,
     * which it can use to initiate headless authentication resolution in the UI.
     *
     * @generated from protobuf rpc: SendPendingHeadlessAuthentication(teleport.lib.teleterm.v1.SendPendingHeadlessAuthenticationRequest) returns (teleport.lib.teleterm.v1.SendPendingHeadlessAuthenticationResponse);
     */
    sendPendingHeadlessAuthentication: grpc.handleUnaryCall<SendPendingHeadlessAuthenticationRequest, SendPendingHeadlessAuthenticationResponse>;
    /**
     * PromptMFA notifies the Electron app that the daemon is waiting for the user to answer an MFA prompt.
     * If Webauthn is supported, tsh daemon starts another goroutine which readies the hardware key.
     * If TOTP is supported, tsh daemon expects that the Electron app responds to this RPC with the
     * code.
     *
     * @generated from protobuf rpc: PromptMFA(teleport.lib.teleterm.v1.PromptMFARequest) returns (teleport.lib.teleterm.v1.PromptMFAResponse);
     */
    promptMFA: grpc.handleUnaryCall<PromptMFARequest, PromptMFAResponse>;
    /**
     * GetUsageReportingSettings returns the current state of usage reporting.
     * At the moment, the user cannot toggle usage reporting on and off without shutting down the app,
     * with the only exception being the first start of the app when they're prompted about telemetry.
     * Hence why this is an RPC and not information passed over argv to tsh daemon.
     *
     * @generated from protobuf rpc: GetUsageReportingSettings(teleport.lib.teleterm.v1.GetUsageReportingSettingsRequest) returns (teleport.lib.teleterm.v1.GetUsageReportingSettingsResponse);
     */
    getUsageReportingSettings: grpc.handleUnaryCall<GetUsageReportingSettingsRequest, GetUsageReportingSettingsResponse>;
    /**
     * ReportUnexpectedVnetShutdown is sent by tsh daemon when VNet exits outside of the
     * request-response cycle of Start and Stop RPCs of VnetService. The Electron app is then able to
     * update the state of VNet in the UI.
     *
     * @generated from protobuf rpc: ReportUnexpectedVnetShutdown(teleport.lib.teleterm.v1.ReportUnexpectedVnetShutdownRequest) returns (teleport.lib.teleterm.v1.ReportUnexpectedVnetShutdownResponse);
     */
    reportUnexpectedVnetShutdown: grpc.handleUnaryCall<ReportUnexpectedVnetShutdownRequest, ReportUnexpectedVnetShutdownResponse>;
}
/**
 * @grpc/grpc-js definition for the protobuf service teleport.lib.teleterm.v1.TshdEventsService.
 *
 * Usage: Implement the interface ITshdEventsService and add to a grpc server.
 *
 * ```typescript
 * const server = new grpc.Server();
 * const service: ITshdEventsService = ...
 * server.addService(tshdEventsServiceDefinition, service);
 * ```
 */
export const tshdEventsServiceDefinition: grpc.ServiceDefinition<ITshdEventsService> = {
    relogin: {
        path: "/teleport.lib.teleterm.v1.TshdEventsService/Relogin",
        originalName: "Relogin",
        requestStream: false,
        responseStream: false,
        responseDeserialize: bytes => ReloginResponse.fromBinary(bytes),
        requestDeserialize: bytes => ReloginRequest.fromBinary(bytes),
        responseSerialize: value => Buffer.from(ReloginResponse.toBinary(value)),
        requestSerialize: value => Buffer.from(ReloginRequest.toBinary(value))
    },
    sendNotification: {
        path: "/teleport.lib.teleterm.v1.TshdEventsService/SendNotification",
        originalName: "SendNotification",
        requestStream: false,
        responseStream: false,
        responseDeserialize: bytes => SendNotificationResponse.fromBinary(bytes),
        requestDeserialize: bytes => SendNotificationRequest.fromBinary(bytes),
        responseSerialize: value => Buffer.from(SendNotificationResponse.toBinary(value)),
        requestSerialize: value => Buffer.from(SendNotificationRequest.toBinary(value))
    },
    sendPendingHeadlessAuthentication: {
        path: "/teleport.lib.teleterm.v1.TshdEventsService/SendPendingHeadlessAuthentication",
        originalName: "SendPendingHeadlessAuthentication",
        requestStream: false,
        responseStream: false,
        responseDeserialize: bytes => SendPendingHeadlessAuthenticationResponse.fromBinary(bytes),
        requestDeserialize: bytes => SendPendingHeadlessAuthenticationRequest.fromBinary(bytes),
        responseSerialize: value => Buffer.from(SendPendingHeadlessAuthenticationResponse.toBinary(value)),
        requestSerialize: value => Buffer.from(SendPendingHeadlessAuthenticationRequest.toBinary(value))
    },
    promptMFA: {
        path: "/teleport.lib.teleterm.v1.TshdEventsService/PromptMFA",
        originalName: "PromptMFA",
        requestStream: false,
        responseStream: false,
        responseDeserialize: bytes => PromptMFAResponse.fromBinary(bytes),
        requestDeserialize: bytes => PromptMFARequest.fromBinary(bytes),
        responseSerialize: value => Buffer.from(PromptMFAResponse.toBinary(value)),
        requestSerialize: value => Buffer.from(PromptMFARequest.toBinary(value))
    },
    getUsageReportingSettings: {
        path: "/teleport.lib.teleterm.v1.TshdEventsService/GetUsageReportingSettings",
        originalName: "GetUsageReportingSettings",
        requestStream: false,
        responseStream: false,
        responseDeserialize: bytes => GetUsageReportingSettingsResponse.fromBinary(bytes),
        requestDeserialize: bytes => GetUsageReportingSettingsRequest.fromBinary(bytes),
        responseSerialize: value => Buffer.from(GetUsageReportingSettingsResponse.toBinary(value)),
        requestSerialize: value => Buffer.from(GetUsageReportingSettingsRequest.toBinary(value))
    },
    reportUnexpectedVnetShutdown: {
        path: "/teleport.lib.teleterm.v1.TshdEventsService/ReportUnexpectedVnetShutdown",
        originalName: "ReportUnexpectedVnetShutdown",
        requestStream: false,
        responseStream: false,
        responseDeserialize: bytes => ReportUnexpectedVnetShutdownResponse.fromBinary(bytes),
        requestDeserialize: bytes => ReportUnexpectedVnetShutdownRequest.fromBinary(bytes),
        responseSerialize: value => Buffer.from(ReportUnexpectedVnetShutdownResponse.toBinary(value)),
        requestSerialize: value => Buffer.from(ReportUnexpectedVnetShutdownRequest.toBinary(value))
    }
};
