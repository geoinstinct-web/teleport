/* eslint-disable */
// @generated by protobuf-ts 2.9.3 with parameter eslint_disable,add_pb_suffix,server_grpc1,ts_nocheck
// @generated from protobuf file "prehog/v1alpha/teleport.proto" (package "prehog.v1alpha", syntax proto3)
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
import type { RpcTransport } from "@protobuf-ts/runtime-rpc";
import type { ServiceInfo } from "@protobuf-ts/runtime-rpc";
import { TeleportReportingService } from "./teleport_pb";
import type { HelloTeleportResponse } from "./teleport_pb";
import type { HelloTeleportRequest } from "./teleport_pb";
import type { SubmitEventsResponse } from "./teleport_pb";
import type { SubmitEventsRequest } from "./teleport_pb";
import { stackIntercept } from "@protobuf-ts/runtime-rpc";
import type { SubmitEventResponse } from "./teleport_pb";
import type { SubmitEventRequest } from "./teleport_pb";
import type { UnaryCall } from "@protobuf-ts/runtime-rpc";
import type { RpcOptions } from "@protobuf-ts/runtime-rpc";
/**
 * @generated from protobuf service prehog.v1alpha.TeleportReportingService
 */
export interface ITeleportReportingServiceClient {
    /**
     * equivalent to SubmitEvents with a single event, should be unused by now
     *
     * @deprecated
     * @generated from protobuf rpc: SubmitEvent(prehog.v1alpha.SubmitEventRequest) returns (prehog.v1alpha.SubmitEventResponse);
     */
    submitEvent(input: SubmitEventRequest, options?: RpcOptions): UnaryCall<SubmitEventRequest, SubmitEventResponse>;
    /**
     * encodes and forwards usage events to the PostHog event database; each
     * event is annotated with some properties that depend on the identity of the
     * caller:
     * - tp.account_id (UUID in string form, can be empty if missing from the
     *   license)
     * - tp.license_name (should always be a UUID)
     * - tp.license_authority (name of the authority that signed the license file
     *   used for authentication)
     * - tp.is_cloud (boolean)
     *
     * @generated from protobuf rpc: SubmitEvents(prehog.v1alpha.SubmitEventsRequest) returns (prehog.v1alpha.SubmitEventsResponse);
     */
    submitEvents(input: SubmitEventsRequest, options?: RpcOptions): UnaryCall<SubmitEventsRequest, SubmitEventsResponse>;
    /**
     * @generated from protobuf rpc: HelloTeleport(prehog.v1alpha.HelloTeleportRequest) returns (prehog.v1alpha.HelloTeleportResponse);
     */
    helloTeleport(input: HelloTeleportRequest, options?: RpcOptions): UnaryCall<HelloTeleportRequest, HelloTeleportResponse>;
}
/**
 * @generated from protobuf service prehog.v1alpha.TeleportReportingService
 */
export class TeleportReportingServiceClient implements ITeleportReportingServiceClient, ServiceInfo {
    typeName = TeleportReportingService.typeName;
    methods = TeleportReportingService.methods;
    options = TeleportReportingService.options;
    constructor(private readonly _transport: RpcTransport) {
    }
    /**
     * equivalent to SubmitEvents with a single event, should be unused by now
     *
     * @deprecated
     * @generated from protobuf rpc: SubmitEvent(prehog.v1alpha.SubmitEventRequest) returns (prehog.v1alpha.SubmitEventResponse);
     */
    submitEvent(input: SubmitEventRequest, options?: RpcOptions): UnaryCall<SubmitEventRequest, SubmitEventResponse> {
        const method = this.methods[0], opt = this._transport.mergeOptions(options);
        return stackIntercept<SubmitEventRequest, SubmitEventResponse>("unary", this._transport, method, opt, input);
    }
    /**
     * encodes and forwards usage events to the PostHog event database; each
     * event is annotated with some properties that depend on the identity of the
     * caller:
     * - tp.account_id (UUID in string form, can be empty if missing from the
     *   license)
     * - tp.license_name (should always be a UUID)
     * - tp.license_authority (name of the authority that signed the license file
     *   used for authentication)
     * - tp.is_cloud (boolean)
     *
     * @generated from protobuf rpc: SubmitEvents(prehog.v1alpha.SubmitEventsRequest) returns (prehog.v1alpha.SubmitEventsResponse);
     */
    submitEvents(input: SubmitEventsRequest, options?: RpcOptions): UnaryCall<SubmitEventsRequest, SubmitEventsResponse> {
        const method = this.methods[1], opt = this._transport.mergeOptions(options);
        return stackIntercept<SubmitEventsRequest, SubmitEventsResponse>("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: HelloTeleport(prehog.v1alpha.HelloTeleportRequest) returns (prehog.v1alpha.HelloTeleportResponse);
     */
    helloTeleport(input: HelloTeleportRequest, options?: RpcOptions): UnaryCall<HelloTeleportRequest, HelloTeleportResponse> {
        const method = this.methods[2], opt = this._transport.mergeOptions(options);
        return stackIntercept<HelloTeleportRequest, HelloTeleportResponse>("unary", this._transport, method, opt, input);
    }
}
