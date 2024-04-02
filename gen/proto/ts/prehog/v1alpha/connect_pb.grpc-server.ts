/* eslint-disable */
// @generated by protobuf-ts 2.9.3 with parameter long_type_number,eslint_disable,add_pb_suffix,server_grpc1,ts_nocheck
// @generated from protobuf file "prehog/v1alpha/connect.proto" (package "prehog.v1alpha", syntax proto3)
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
import { SubmitConnectEventResponse } from "./connect_pb";
import { SubmitConnectEventRequest } from "./connect_pb";
import type * as grpc from "@grpc/grpc-js";
/**
 * @generated from protobuf service prehog.v1alpha.ConnectReportingService
 */
export interface IConnectReportingService extends grpc.UntypedServiceImplementation {
    /**
     * @generated from protobuf rpc: SubmitConnectEvent(prehog.v1alpha.SubmitConnectEventRequest) returns (prehog.v1alpha.SubmitConnectEventResponse);
     */
    submitConnectEvent: grpc.handleUnaryCall<SubmitConnectEventRequest, SubmitConnectEventResponse>;
}
/**
 * @grpc/grpc-js definition for the protobuf service prehog.v1alpha.ConnectReportingService.
 *
 * Usage: Implement the interface IConnectReportingService and add to a grpc server.
 *
 * ```typescript
 * const server = new grpc.Server();
 * const service: IConnectReportingService = ...
 * server.addService(connectReportingServiceDefinition, service);
 * ```
 */
export const connectReportingServiceDefinition: grpc.ServiceDefinition<IConnectReportingService> = {
    submitConnectEvent: {
        path: "/prehog.v1alpha.ConnectReportingService/SubmitConnectEvent",
        originalName: "SubmitConnectEvent",
        requestStream: false,
        responseStream: false,
        responseDeserialize: bytes => SubmitConnectEventResponse.fromBinary(bytes),
        requestDeserialize: bytes => SubmitConnectEventRequest.fromBinary(bytes),
        responseSerialize: value => Buffer.from(SubmitConnectEventResponse.toBinary(value)),
        requestSerialize: value => Buffer.from(SubmitConnectEventRequest.toBinary(value))
    }
};
