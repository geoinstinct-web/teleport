/* eslint-disable */
// @generated by protobuf-ts 2.9.3 with parameter long_type_number,eslint_disable,add_pb_suffix,server_grpc1,ts_nocheck
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
import { ServiceType } from "@protobuf-ts/runtime-rpc";
import type { BinaryWriteOptions } from "@protobuf-ts/runtime";
import type { IBinaryWriter } from "@protobuf-ts/runtime";
import { WireType } from "@protobuf-ts/runtime";
import type { BinaryReadOptions } from "@protobuf-ts/runtime";
import type { IBinaryReader } from "@protobuf-ts/runtime";
import { UnknownFieldHandler } from "@protobuf-ts/runtime";
import type { PartialMessage } from "@protobuf-ts/runtime";
import { reflectionMergePartial } from "@protobuf-ts/runtime";
import { MessageType } from "@protobuf-ts/runtime";
// Relogin

/**
 * @generated from protobuf message teleport.lib.teleterm.v1.ReloginRequest
 */
export interface ReloginRequest {
    /**
     * @generated from protobuf field: string root_cluster_uri = 1;
     */
    rootClusterUri: string;
    /**
     * @generated from protobuf oneof: reason
     */
    reason: {
        oneofKind: "gatewayCertExpired";
        /**
         * @generated from protobuf field: teleport.lib.teleterm.v1.GatewayCertExpired gateway_cert_expired = 2;
         */
        gatewayCertExpired: GatewayCertExpired;
    } | {
        oneofKind: undefined;
    };
}
/**
 * GatewayCertExpired is given as the reason when a database client attempts to make a connection
 * through the gateway, the gateway middleware notices that the db cert has expired and tries to
 * connect to the cluster to reissue the cert, but fails because the user cert has expired as well.
 *
 * At that point in order to let the connection through, tshd needs the Electron app to refresh the
 * user cert by asking the user to log in again.
 *
 * @generated from protobuf message teleport.lib.teleterm.v1.GatewayCertExpired
 */
export interface GatewayCertExpired {
    /**
     * @generated from protobuf field: string gateway_uri = 1;
     */
    gatewayUri: string;
    /**
     * @generated from protobuf field: string target_uri = 2;
     */
    targetUri: string;
}
/**
 * @generated from protobuf message teleport.lib.teleterm.v1.ReloginResponse
 */
export interface ReloginResponse {
}
// SendNotification

/**
 * @generated from protobuf message teleport.lib.teleterm.v1.SendNotificationRequest
 */
export interface SendNotificationRequest {
    /**
     * @generated from protobuf oneof: subject
     */
    subject: {
        oneofKind: "cannotProxyGatewayConnection";
        /**
         * @generated from protobuf field: teleport.lib.teleterm.v1.CannotProxyGatewayConnection cannot_proxy_gateway_connection = 1;
         */
        cannotProxyGatewayConnection: CannotProxyGatewayConnection;
    } | {
        oneofKind: undefined;
    };
}
/**
 * CannotProxyGatewayConnection is the subject when the middleware used by the gateway encounters an
 * unrecoverable error and cannot let the connection through. The middleware code is executed within
 * a separate goroutine so if the error wasn't passed to the Electron app, it would have been
 * visible only in the logs.
 *
 * @generated from protobuf message teleport.lib.teleterm.v1.CannotProxyGatewayConnection
 */
export interface CannotProxyGatewayConnection {
    /**
     * @generated from protobuf field: string gateway_uri = 1;
     */
    gatewayUri: string;
    /**
     * @generated from protobuf field: string target_uri = 2;
     */
    targetUri: string;
    /**
     * @generated from protobuf field: string error = 3;
     */
    error: string;
}
/**
 * @generated from protobuf message teleport.lib.teleterm.v1.SendNotificationResponse
 */
export interface SendNotificationResponse {
}
// SendPendingHeadlessAuthentication

/**
 * @generated from protobuf message teleport.lib.teleterm.v1.SendPendingHeadlessAuthenticationRequest
 */
export interface SendPendingHeadlessAuthenticationRequest {
    /**
     * @generated from protobuf field: string root_cluster_uri = 1;
     */
    rootClusterUri: string;
    /**
     * @generated from protobuf field: string headless_authentication_id = 2;
     */
    headlessAuthenticationId: string;
    /**
     * @generated from protobuf field: string headless_authentication_client_ip = 3;
     */
    headlessAuthenticationClientIp: string;
}
/**
 * @generated from protobuf message teleport.lib.teleterm.v1.SendPendingHeadlessAuthenticationResponse
 */
export interface SendPendingHeadlessAuthenticationResponse {
}
// PromptMFA

/**
 * @generated from protobuf message teleport.lib.teleterm.v1.PromptMFARequest
 */
export interface PromptMFARequest {
    /**
     * @generated from protobuf field: string root_cluster_uri = 1;
     */
    rootClusterUri: string;
    /**
     * @generated from protobuf field: string reason = 2;
     */
    reason: string;
    /**
     * @generated from protobuf field: bool totp = 3;
     */
    totp: boolean;
    /**
     * @generated from protobuf field: bool webauthn = 4;
     */
    webauthn: boolean;
}
/**
 * @generated from protobuf message teleport.lib.teleterm.v1.PromptMFAResponse
 */
export interface PromptMFAResponse {
    /**
     * @generated from protobuf field: string totp_code = 1;
     */
    totpCode: string;
}
// @generated message type with reflection information, may provide speed optimized methods
class ReloginRequest$Type extends MessageType<ReloginRequest> {
    constructor() {
        super("teleport.lib.teleterm.v1.ReloginRequest", [
            { no: 1, name: "root_cluster_uri", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 2, name: "gateway_cert_expired", kind: "message", oneof: "reason", T: () => GatewayCertExpired }
        ]);
    }
    create(value?: PartialMessage<ReloginRequest>): ReloginRequest {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.rootClusterUri = "";
        message.reason = { oneofKind: undefined };
        if (value !== undefined)
            reflectionMergePartial<ReloginRequest>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: ReloginRequest): ReloginRequest {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* string root_cluster_uri */ 1:
                    message.rootClusterUri = reader.string();
                    break;
                case /* teleport.lib.teleterm.v1.GatewayCertExpired gateway_cert_expired */ 2:
                    message.reason = {
                        oneofKind: "gatewayCertExpired",
                        gatewayCertExpired: GatewayCertExpired.internalBinaryRead(reader, reader.uint32(), options, (message.reason as any).gatewayCertExpired)
                    };
                    break;
                default:
                    let u = options.readUnknownField;
                    if (u === "throw")
                        throw new globalThis.Error(`Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`);
                    let d = reader.skip(wireType);
                    if (u !== false)
                        (u === true ? UnknownFieldHandler.onRead : u)(this.typeName, message, fieldNo, wireType, d);
            }
        }
        return message;
    }
    internalBinaryWrite(message: ReloginRequest, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* string root_cluster_uri = 1; */
        if (message.rootClusterUri !== "")
            writer.tag(1, WireType.LengthDelimited).string(message.rootClusterUri);
        /* teleport.lib.teleterm.v1.GatewayCertExpired gateway_cert_expired = 2; */
        if (message.reason.oneofKind === "gatewayCertExpired")
            GatewayCertExpired.internalBinaryWrite(message.reason.gatewayCertExpired, writer.tag(2, WireType.LengthDelimited).fork(), options).join();
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.v1.ReloginRequest
 */
export const ReloginRequest = new ReloginRequest$Type();
// @generated message type with reflection information, may provide speed optimized methods
class GatewayCertExpired$Type extends MessageType<GatewayCertExpired> {
    constructor() {
        super("teleport.lib.teleterm.v1.GatewayCertExpired", [
            { no: 1, name: "gateway_uri", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 2, name: "target_uri", kind: "scalar", T: 9 /*ScalarType.STRING*/ }
        ]);
    }
    create(value?: PartialMessage<GatewayCertExpired>): GatewayCertExpired {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.gatewayUri = "";
        message.targetUri = "";
        if (value !== undefined)
            reflectionMergePartial<GatewayCertExpired>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: GatewayCertExpired): GatewayCertExpired {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* string gateway_uri */ 1:
                    message.gatewayUri = reader.string();
                    break;
                case /* string target_uri */ 2:
                    message.targetUri = reader.string();
                    break;
                default:
                    let u = options.readUnknownField;
                    if (u === "throw")
                        throw new globalThis.Error(`Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`);
                    let d = reader.skip(wireType);
                    if (u !== false)
                        (u === true ? UnknownFieldHandler.onRead : u)(this.typeName, message, fieldNo, wireType, d);
            }
        }
        return message;
    }
    internalBinaryWrite(message: GatewayCertExpired, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* string gateway_uri = 1; */
        if (message.gatewayUri !== "")
            writer.tag(1, WireType.LengthDelimited).string(message.gatewayUri);
        /* string target_uri = 2; */
        if (message.targetUri !== "")
            writer.tag(2, WireType.LengthDelimited).string(message.targetUri);
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.v1.GatewayCertExpired
 */
export const GatewayCertExpired = new GatewayCertExpired$Type();
// @generated message type with reflection information, may provide speed optimized methods
class ReloginResponse$Type extends MessageType<ReloginResponse> {
    constructor() {
        super("teleport.lib.teleterm.v1.ReloginResponse", []);
    }
    create(value?: PartialMessage<ReloginResponse>): ReloginResponse {
        const message = globalThis.Object.create((this.messagePrototype!));
        if (value !== undefined)
            reflectionMergePartial<ReloginResponse>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: ReloginResponse): ReloginResponse {
        return target ?? this.create();
    }
    internalBinaryWrite(message: ReloginResponse, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.v1.ReloginResponse
 */
export const ReloginResponse = new ReloginResponse$Type();
// @generated message type with reflection information, may provide speed optimized methods
class SendNotificationRequest$Type extends MessageType<SendNotificationRequest> {
    constructor() {
        super("teleport.lib.teleterm.v1.SendNotificationRequest", [
            { no: 1, name: "cannot_proxy_gateway_connection", kind: "message", oneof: "subject", T: () => CannotProxyGatewayConnection }
        ]);
    }
    create(value?: PartialMessage<SendNotificationRequest>): SendNotificationRequest {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.subject = { oneofKind: undefined };
        if (value !== undefined)
            reflectionMergePartial<SendNotificationRequest>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: SendNotificationRequest): SendNotificationRequest {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* teleport.lib.teleterm.v1.CannotProxyGatewayConnection cannot_proxy_gateway_connection */ 1:
                    message.subject = {
                        oneofKind: "cannotProxyGatewayConnection",
                        cannotProxyGatewayConnection: CannotProxyGatewayConnection.internalBinaryRead(reader, reader.uint32(), options, (message.subject as any).cannotProxyGatewayConnection)
                    };
                    break;
                default:
                    let u = options.readUnknownField;
                    if (u === "throw")
                        throw new globalThis.Error(`Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`);
                    let d = reader.skip(wireType);
                    if (u !== false)
                        (u === true ? UnknownFieldHandler.onRead : u)(this.typeName, message, fieldNo, wireType, d);
            }
        }
        return message;
    }
    internalBinaryWrite(message: SendNotificationRequest, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* teleport.lib.teleterm.v1.CannotProxyGatewayConnection cannot_proxy_gateway_connection = 1; */
        if (message.subject.oneofKind === "cannotProxyGatewayConnection")
            CannotProxyGatewayConnection.internalBinaryWrite(message.subject.cannotProxyGatewayConnection, writer.tag(1, WireType.LengthDelimited).fork(), options).join();
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.v1.SendNotificationRequest
 */
export const SendNotificationRequest = new SendNotificationRequest$Type();
// @generated message type with reflection information, may provide speed optimized methods
class CannotProxyGatewayConnection$Type extends MessageType<CannotProxyGatewayConnection> {
    constructor() {
        super("teleport.lib.teleterm.v1.CannotProxyGatewayConnection", [
            { no: 1, name: "gateway_uri", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 2, name: "target_uri", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 3, name: "error", kind: "scalar", T: 9 /*ScalarType.STRING*/ }
        ]);
    }
    create(value?: PartialMessage<CannotProxyGatewayConnection>): CannotProxyGatewayConnection {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.gatewayUri = "";
        message.targetUri = "";
        message.error = "";
        if (value !== undefined)
            reflectionMergePartial<CannotProxyGatewayConnection>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: CannotProxyGatewayConnection): CannotProxyGatewayConnection {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* string gateway_uri */ 1:
                    message.gatewayUri = reader.string();
                    break;
                case /* string target_uri */ 2:
                    message.targetUri = reader.string();
                    break;
                case /* string error */ 3:
                    message.error = reader.string();
                    break;
                default:
                    let u = options.readUnknownField;
                    if (u === "throw")
                        throw new globalThis.Error(`Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`);
                    let d = reader.skip(wireType);
                    if (u !== false)
                        (u === true ? UnknownFieldHandler.onRead : u)(this.typeName, message, fieldNo, wireType, d);
            }
        }
        return message;
    }
    internalBinaryWrite(message: CannotProxyGatewayConnection, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* string gateway_uri = 1; */
        if (message.gatewayUri !== "")
            writer.tag(1, WireType.LengthDelimited).string(message.gatewayUri);
        /* string target_uri = 2; */
        if (message.targetUri !== "")
            writer.tag(2, WireType.LengthDelimited).string(message.targetUri);
        /* string error = 3; */
        if (message.error !== "")
            writer.tag(3, WireType.LengthDelimited).string(message.error);
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.v1.CannotProxyGatewayConnection
 */
export const CannotProxyGatewayConnection = new CannotProxyGatewayConnection$Type();
// @generated message type with reflection information, may provide speed optimized methods
class SendNotificationResponse$Type extends MessageType<SendNotificationResponse> {
    constructor() {
        super("teleport.lib.teleterm.v1.SendNotificationResponse", []);
    }
    create(value?: PartialMessage<SendNotificationResponse>): SendNotificationResponse {
        const message = globalThis.Object.create((this.messagePrototype!));
        if (value !== undefined)
            reflectionMergePartial<SendNotificationResponse>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: SendNotificationResponse): SendNotificationResponse {
        return target ?? this.create();
    }
    internalBinaryWrite(message: SendNotificationResponse, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.v1.SendNotificationResponse
 */
export const SendNotificationResponse = new SendNotificationResponse$Type();
// @generated message type with reflection information, may provide speed optimized methods
class SendPendingHeadlessAuthenticationRequest$Type extends MessageType<SendPendingHeadlessAuthenticationRequest> {
    constructor() {
        super("teleport.lib.teleterm.v1.SendPendingHeadlessAuthenticationRequest", [
            { no: 1, name: "root_cluster_uri", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 2, name: "headless_authentication_id", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 3, name: "headless_authentication_client_ip", kind: "scalar", T: 9 /*ScalarType.STRING*/ }
        ]);
    }
    create(value?: PartialMessage<SendPendingHeadlessAuthenticationRequest>): SendPendingHeadlessAuthenticationRequest {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.rootClusterUri = "";
        message.headlessAuthenticationId = "";
        message.headlessAuthenticationClientIp = "";
        if (value !== undefined)
            reflectionMergePartial<SendPendingHeadlessAuthenticationRequest>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: SendPendingHeadlessAuthenticationRequest): SendPendingHeadlessAuthenticationRequest {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* string root_cluster_uri */ 1:
                    message.rootClusterUri = reader.string();
                    break;
                case /* string headless_authentication_id */ 2:
                    message.headlessAuthenticationId = reader.string();
                    break;
                case /* string headless_authentication_client_ip */ 3:
                    message.headlessAuthenticationClientIp = reader.string();
                    break;
                default:
                    let u = options.readUnknownField;
                    if (u === "throw")
                        throw new globalThis.Error(`Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`);
                    let d = reader.skip(wireType);
                    if (u !== false)
                        (u === true ? UnknownFieldHandler.onRead : u)(this.typeName, message, fieldNo, wireType, d);
            }
        }
        return message;
    }
    internalBinaryWrite(message: SendPendingHeadlessAuthenticationRequest, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* string root_cluster_uri = 1; */
        if (message.rootClusterUri !== "")
            writer.tag(1, WireType.LengthDelimited).string(message.rootClusterUri);
        /* string headless_authentication_id = 2; */
        if (message.headlessAuthenticationId !== "")
            writer.tag(2, WireType.LengthDelimited).string(message.headlessAuthenticationId);
        /* string headless_authentication_client_ip = 3; */
        if (message.headlessAuthenticationClientIp !== "")
            writer.tag(3, WireType.LengthDelimited).string(message.headlessAuthenticationClientIp);
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.v1.SendPendingHeadlessAuthenticationRequest
 */
export const SendPendingHeadlessAuthenticationRequest = new SendPendingHeadlessAuthenticationRequest$Type();
// @generated message type with reflection information, may provide speed optimized methods
class SendPendingHeadlessAuthenticationResponse$Type extends MessageType<SendPendingHeadlessAuthenticationResponse> {
    constructor() {
        super("teleport.lib.teleterm.v1.SendPendingHeadlessAuthenticationResponse", []);
    }
    create(value?: PartialMessage<SendPendingHeadlessAuthenticationResponse>): SendPendingHeadlessAuthenticationResponse {
        const message = globalThis.Object.create((this.messagePrototype!));
        if (value !== undefined)
            reflectionMergePartial<SendPendingHeadlessAuthenticationResponse>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: SendPendingHeadlessAuthenticationResponse): SendPendingHeadlessAuthenticationResponse {
        return target ?? this.create();
    }
    internalBinaryWrite(message: SendPendingHeadlessAuthenticationResponse, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.v1.SendPendingHeadlessAuthenticationResponse
 */
export const SendPendingHeadlessAuthenticationResponse = new SendPendingHeadlessAuthenticationResponse$Type();
// @generated message type with reflection information, may provide speed optimized methods
class PromptMFARequest$Type extends MessageType<PromptMFARequest> {
    constructor() {
        super("teleport.lib.teleterm.v1.PromptMFARequest", [
            { no: 1, name: "root_cluster_uri", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 2, name: "reason", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 3, name: "totp", kind: "scalar", T: 8 /*ScalarType.BOOL*/ },
            { no: 4, name: "webauthn", kind: "scalar", T: 8 /*ScalarType.BOOL*/ }
        ]);
    }
    create(value?: PartialMessage<PromptMFARequest>): PromptMFARequest {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.rootClusterUri = "";
        message.reason = "";
        message.totp = false;
        message.webauthn = false;
        if (value !== undefined)
            reflectionMergePartial<PromptMFARequest>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: PromptMFARequest): PromptMFARequest {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* string root_cluster_uri */ 1:
                    message.rootClusterUri = reader.string();
                    break;
                case /* string reason */ 2:
                    message.reason = reader.string();
                    break;
                case /* bool totp */ 3:
                    message.totp = reader.bool();
                    break;
                case /* bool webauthn */ 4:
                    message.webauthn = reader.bool();
                    break;
                default:
                    let u = options.readUnknownField;
                    if (u === "throw")
                        throw new globalThis.Error(`Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`);
                    let d = reader.skip(wireType);
                    if (u !== false)
                        (u === true ? UnknownFieldHandler.onRead : u)(this.typeName, message, fieldNo, wireType, d);
            }
        }
        return message;
    }
    internalBinaryWrite(message: PromptMFARequest, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* string root_cluster_uri = 1; */
        if (message.rootClusterUri !== "")
            writer.tag(1, WireType.LengthDelimited).string(message.rootClusterUri);
        /* string reason = 2; */
        if (message.reason !== "")
            writer.tag(2, WireType.LengthDelimited).string(message.reason);
        /* bool totp = 3; */
        if (message.totp !== false)
            writer.tag(3, WireType.Varint).bool(message.totp);
        /* bool webauthn = 4; */
        if (message.webauthn !== false)
            writer.tag(4, WireType.Varint).bool(message.webauthn);
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.v1.PromptMFARequest
 */
export const PromptMFARequest = new PromptMFARequest$Type();
// @generated message type with reflection information, may provide speed optimized methods
class PromptMFAResponse$Type extends MessageType<PromptMFAResponse> {
    constructor() {
        super("teleport.lib.teleterm.v1.PromptMFAResponse", [
            { no: 1, name: "totp_code", kind: "scalar", T: 9 /*ScalarType.STRING*/ }
        ]);
    }
    create(value?: PartialMessage<PromptMFAResponse>): PromptMFAResponse {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.totpCode = "";
        if (value !== undefined)
            reflectionMergePartial<PromptMFAResponse>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: PromptMFAResponse): PromptMFAResponse {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* string totp_code */ 1:
                    message.totpCode = reader.string();
                    break;
                default:
                    let u = options.readUnknownField;
                    if (u === "throw")
                        throw new globalThis.Error(`Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`);
                    let d = reader.skip(wireType);
                    if (u !== false)
                        (u === true ? UnknownFieldHandler.onRead : u)(this.typeName, message, fieldNo, wireType, d);
            }
        }
        return message;
    }
    internalBinaryWrite(message: PromptMFAResponse, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* string totp_code = 1; */
        if (message.totpCode !== "")
            writer.tag(1, WireType.LengthDelimited).string(message.totpCode);
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.v1.PromptMFAResponse
 */
export const PromptMFAResponse = new PromptMFAResponse$Type();
/**
 * @generated ServiceType for protobuf service teleport.lib.teleterm.v1.TshdEventsService
 */
export const TshdEventsService = new ServiceType("teleport.lib.teleterm.v1.TshdEventsService", [
    { name: "Relogin", options: {}, I: ReloginRequest, O: ReloginResponse },
    { name: "SendNotification", options: {}, I: SendNotificationRequest, O: SendNotificationResponse },
    { name: "SendPendingHeadlessAuthentication", options: {}, I: SendPendingHeadlessAuthenticationRequest, O: SendPendingHeadlessAuthenticationResponse },
    { name: "PromptMFA", options: {}, I: PromptMFARequest, O: PromptMFAResponse }
]);
