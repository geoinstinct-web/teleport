/* eslint-disable */
// @generated by protobuf-ts 2.9.3 with parameter long_type_number,eslint_disable,add_pb_suffix,client_grpc1,server_grpc1,ts_nocheck
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
import { TshdEventsService } from "./tshd_events_service_pb";
import type { BinaryWriteOptions } from "@protobuf-ts/runtime";
import type { BinaryReadOptions } from "@protobuf-ts/runtime";
import type { PromptMFAResponse } from "./tshd_events_service_pb";
import type { PromptMFARequest } from "./tshd_events_service_pb";
import type { SendPendingHeadlessAuthenticationResponse } from "./tshd_events_service_pb";
import type { SendPendingHeadlessAuthenticationRequest } from "./tshd_events_service_pb";
import type { SendNotificationResponse } from "./tshd_events_service_pb";
import type { SendNotificationRequest } from "./tshd_events_service_pb";
import type { ReloginResponse } from "./tshd_events_service_pb";
import type { ReloginRequest } from "./tshd_events_service_pb";
import * as grpc from "@grpc/grpc-js";
/**
 * TshdEventsService is served by the Electron app. The tsh daemon calls this service to notify the
 * app about actions that happen outside of the app itself.
 *
 * @generated from protobuf service teleport.lib.teleterm.v1.TshdEventsService
 */
export interface ITshdEventsServiceClient {
    /**
     * Relogin makes the Electron app display a login modal for the specific root cluster. The request
     * returns a response after the relogin procedure has been successfully finished.
     *
     * @generated from protobuf rpc: Relogin(teleport.lib.teleterm.v1.ReloginRequest) returns (teleport.lib.teleterm.v1.ReloginResponse);
     */
    relogin(input: ReloginRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: (err: grpc.ServiceError | null, value?: ReloginResponse) => void): grpc.ClientUnaryCall;
    relogin(input: ReloginRequest, metadata: grpc.Metadata, callback: (err: grpc.ServiceError | null, value?: ReloginResponse) => void): grpc.ClientUnaryCall;
    relogin(input: ReloginRequest, options: grpc.CallOptions, callback: (err: grpc.ServiceError | null, value?: ReloginResponse) => void): grpc.ClientUnaryCall;
    relogin(input: ReloginRequest, callback: (err: grpc.ServiceError | null, value?: ReloginResponse) => void): grpc.ClientUnaryCall;
    /**
     * SendNotification causes the Electron app to display a notification in the UI. The request
     * accepts a specific message rather than a generic string so that the Electron is in control as
     * to what message is displayed and how exactly it looks.
     *
     * @generated from protobuf rpc: SendNotification(teleport.lib.teleterm.v1.SendNotificationRequest) returns (teleport.lib.teleterm.v1.SendNotificationResponse);
     */
    sendNotification(input: SendNotificationRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: (err: grpc.ServiceError | null, value?: SendNotificationResponse) => void): grpc.ClientUnaryCall;
    sendNotification(input: SendNotificationRequest, metadata: grpc.Metadata, callback: (err: grpc.ServiceError | null, value?: SendNotificationResponse) => void): grpc.ClientUnaryCall;
    sendNotification(input: SendNotificationRequest, options: grpc.CallOptions, callback: (err: grpc.ServiceError | null, value?: SendNotificationResponse) => void): grpc.ClientUnaryCall;
    sendNotification(input: SendNotificationRequest, callback: (err: grpc.ServiceError | null, value?: SendNotificationResponse) => void): grpc.ClientUnaryCall;
    /**
     * SendPendingHeadlessAuthentication notifies the Electron app of a pending headless authentication,
     * which it can use to initiate headless authentication resolution in the UI.
     *
     * @generated from protobuf rpc: SendPendingHeadlessAuthentication(teleport.lib.teleterm.v1.SendPendingHeadlessAuthenticationRequest) returns (teleport.lib.teleterm.v1.SendPendingHeadlessAuthenticationResponse);
     */
    sendPendingHeadlessAuthentication(input: SendPendingHeadlessAuthenticationRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: (err: grpc.ServiceError | null, value?: SendPendingHeadlessAuthenticationResponse) => void): grpc.ClientUnaryCall;
    sendPendingHeadlessAuthentication(input: SendPendingHeadlessAuthenticationRequest, metadata: grpc.Metadata, callback: (err: grpc.ServiceError | null, value?: SendPendingHeadlessAuthenticationResponse) => void): grpc.ClientUnaryCall;
    sendPendingHeadlessAuthentication(input: SendPendingHeadlessAuthenticationRequest, options: grpc.CallOptions, callback: (err: grpc.ServiceError | null, value?: SendPendingHeadlessAuthenticationResponse) => void): grpc.ClientUnaryCall;
    sendPendingHeadlessAuthentication(input: SendPendingHeadlessAuthenticationRequest, callback: (err: grpc.ServiceError | null, value?: SendPendingHeadlessAuthenticationResponse) => void): grpc.ClientUnaryCall;
    /**
     * PromptMFA notifies the Electron app that the daemon is waiting for the user to answer an MFA prompt.
     *
     * @generated from protobuf rpc: PromptMFA(teleport.lib.teleterm.v1.PromptMFARequest) returns (teleport.lib.teleterm.v1.PromptMFAResponse);
     */
    promptMFA(input: PromptMFARequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: (err: grpc.ServiceError | null, value?: PromptMFAResponse) => void): grpc.ClientUnaryCall;
    promptMFA(input: PromptMFARequest, metadata: grpc.Metadata, callback: (err: grpc.ServiceError | null, value?: PromptMFAResponse) => void): grpc.ClientUnaryCall;
    promptMFA(input: PromptMFARequest, options: grpc.CallOptions, callback: (err: grpc.ServiceError | null, value?: PromptMFAResponse) => void): grpc.ClientUnaryCall;
    promptMFA(input: PromptMFARequest, callback: (err: grpc.ServiceError | null, value?: PromptMFAResponse) => void): grpc.ClientUnaryCall;
}
/**
 * TshdEventsService is served by the Electron app. The tsh daemon calls this service to notify the
 * app about actions that happen outside of the app itself.
 *
 * @generated from protobuf service teleport.lib.teleterm.v1.TshdEventsService
 */
export class TshdEventsServiceClient extends grpc.Client implements ITshdEventsServiceClient {
    private readonly _binaryOptions: Partial<BinaryReadOptions & BinaryWriteOptions>;
    constructor(address: string, credentials: grpc.ChannelCredentials, options: grpc.ClientOptions = {}, binaryOptions: Partial<BinaryReadOptions & BinaryWriteOptions> = {}) {
        super(address, credentials, options);
        this._binaryOptions = binaryOptions;
    }
    /**
     * Relogin makes the Electron app display a login modal for the specific root cluster. The request
     * returns a response after the relogin procedure has been successfully finished.
     *
     * @generated from protobuf rpc: Relogin(teleport.lib.teleterm.v1.ReloginRequest) returns (teleport.lib.teleterm.v1.ReloginResponse);
     */
    relogin(input: ReloginRequest, metadata: grpc.Metadata | grpc.CallOptions | ((err: grpc.ServiceError | null, value?: ReloginResponse) => void), options?: grpc.CallOptions | ((err: grpc.ServiceError | null, value?: ReloginResponse) => void), callback?: ((err: grpc.ServiceError | null, value?: ReloginResponse) => void)): grpc.ClientUnaryCall {
        const method = TshdEventsService.methods[0];
        return this.makeUnaryRequest<ReloginRequest, ReloginResponse>(`/${TshdEventsService.typeName}/${method.name}`, (value: ReloginRequest): Buffer => Buffer.from(method.I.toBinary(value, this._binaryOptions)), (value: Buffer): ReloginResponse => method.O.fromBinary(value, this._binaryOptions), input, (metadata as any), (options as any), (callback as any));
    }
    /**
     * SendNotification causes the Electron app to display a notification in the UI. The request
     * accepts a specific message rather than a generic string so that the Electron is in control as
     * to what message is displayed and how exactly it looks.
     *
     * @generated from protobuf rpc: SendNotification(teleport.lib.teleterm.v1.SendNotificationRequest) returns (teleport.lib.teleterm.v1.SendNotificationResponse);
     */
    sendNotification(input: SendNotificationRequest, metadata: grpc.Metadata | grpc.CallOptions | ((err: grpc.ServiceError | null, value?: SendNotificationResponse) => void), options?: grpc.CallOptions | ((err: grpc.ServiceError | null, value?: SendNotificationResponse) => void), callback?: ((err: grpc.ServiceError | null, value?: SendNotificationResponse) => void)): grpc.ClientUnaryCall {
        const method = TshdEventsService.methods[1];
        return this.makeUnaryRequest<SendNotificationRequest, SendNotificationResponse>(`/${TshdEventsService.typeName}/${method.name}`, (value: SendNotificationRequest): Buffer => Buffer.from(method.I.toBinary(value, this._binaryOptions)), (value: Buffer): SendNotificationResponse => method.O.fromBinary(value, this._binaryOptions), input, (metadata as any), (options as any), (callback as any));
    }
    /**
     * SendPendingHeadlessAuthentication notifies the Electron app of a pending headless authentication,
     * which it can use to initiate headless authentication resolution in the UI.
     *
     * @generated from protobuf rpc: SendPendingHeadlessAuthentication(teleport.lib.teleterm.v1.SendPendingHeadlessAuthenticationRequest) returns (teleport.lib.teleterm.v1.SendPendingHeadlessAuthenticationResponse);
     */
    sendPendingHeadlessAuthentication(input: SendPendingHeadlessAuthenticationRequest, metadata: grpc.Metadata | grpc.CallOptions | ((err: grpc.ServiceError | null, value?: SendPendingHeadlessAuthenticationResponse) => void), options?: grpc.CallOptions | ((err: grpc.ServiceError | null, value?: SendPendingHeadlessAuthenticationResponse) => void), callback?: ((err: grpc.ServiceError | null, value?: SendPendingHeadlessAuthenticationResponse) => void)): grpc.ClientUnaryCall {
        const method = TshdEventsService.methods[2];
        return this.makeUnaryRequest<SendPendingHeadlessAuthenticationRequest, SendPendingHeadlessAuthenticationResponse>(`/${TshdEventsService.typeName}/${method.name}`, (value: SendPendingHeadlessAuthenticationRequest): Buffer => Buffer.from(method.I.toBinary(value, this._binaryOptions)), (value: Buffer): SendPendingHeadlessAuthenticationResponse => method.O.fromBinary(value, this._binaryOptions), input, (metadata as any), (options as any), (callback as any));
    }
    /**
     * PromptMFA notifies the Electron app that the daemon is waiting for the user to answer an MFA prompt.
     *
     * @generated from protobuf rpc: PromptMFA(teleport.lib.teleterm.v1.PromptMFARequest) returns (teleport.lib.teleterm.v1.PromptMFAResponse);
     */
    promptMFA(input: PromptMFARequest, metadata: grpc.Metadata | grpc.CallOptions | ((err: grpc.ServiceError | null, value?: PromptMFAResponse) => void), options?: grpc.CallOptions | ((err: grpc.ServiceError | null, value?: PromptMFAResponse) => void), callback?: ((err: grpc.ServiceError | null, value?: PromptMFAResponse) => void)): grpc.ClientUnaryCall {
        const method = TshdEventsService.methods[3];
        return this.makeUnaryRequest<PromptMFARequest, PromptMFAResponse>(`/${TshdEventsService.typeName}/${method.name}`, (value: PromptMFARequest): Buffer => Buffer.from(method.I.toBinary(value, this._binaryOptions)), (value: Buffer): PromptMFAResponse => method.O.fromBinary(value, this._binaryOptions), input, (metadata as any), (options as any), (callback as any));
    }
}
