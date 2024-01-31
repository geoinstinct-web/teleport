/* eslint-disable */
// @generated by protobuf-ts 2.9.3 with parameter long_type_number,eslint_disable,add_pb_suffix,client_grpc1,server_grpc1,ts_nocheck
// @generated from protobuf file "prehog/v1/teleport.proto" (package "prehog.v1", syntax proto3)
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
import { TeleportReportingService } from "./teleport_pb";
import type { BinaryWriteOptions } from "@protobuf-ts/runtime";
import type { BinaryReadOptions } from "@protobuf-ts/runtime";
import type { SubmitUsageReportsResponse } from "./teleport_pb";
import type { SubmitUsageReportsRequest } from "./teleport_pb";
import * as grpc from "@grpc/grpc-js";
/**
 * @generated from protobuf service prehog.v1.TeleportReportingService
 */
export interface ITeleportReportingServiceClient {
    /**
     * encodes and forwards usage reports to the PostHog event database; each
     * event is annotated with some properties that depend on the identity of the
     * caller:
     * - tp.account_id (UUID in string form, can be empty if missing from the
     *   license)
     * - tp.license_name (should always be a UUID)
     * - tp.license_authority (name of the authority that signed the license file
     *   used for authentication)
     * - tp.is_cloud (boolean)
     *
     * @generated from protobuf rpc: SubmitUsageReports(prehog.v1.SubmitUsageReportsRequest) returns (prehog.v1.SubmitUsageReportsResponse);
     */
    submitUsageReports(input: SubmitUsageReportsRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: (err: grpc.ServiceError | null, value?: SubmitUsageReportsResponse) => void): grpc.ClientUnaryCall;
    submitUsageReports(input: SubmitUsageReportsRequest, metadata: grpc.Metadata, callback: (err: grpc.ServiceError | null, value?: SubmitUsageReportsResponse) => void): grpc.ClientUnaryCall;
    submitUsageReports(input: SubmitUsageReportsRequest, options: grpc.CallOptions, callback: (err: grpc.ServiceError | null, value?: SubmitUsageReportsResponse) => void): grpc.ClientUnaryCall;
    submitUsageReports(input: SubmitUsageReportsRequest, callback: (err: grpc.ServiceError | null, value?: SubmitUsageReportsResponse) => void): grpc.ClientUnaryCall;
}
/**
 * @generated from protobuf service prehog.v1.TeleportReportingService
 */
export class TeleportReportingServiceClient extends grpc.Client implements ITeleportReportingServiceClient {
    private readonly _binaryOptions: Partial<BinaryReadOptions & BinaryWriteOptions>;
    constructor(address: string, credentials: grpc.ChannelCredentials, options: grpc.ClientOptions = {}, binaryOptions: Partial<BinaryReadOptions & BinaryWriteOptions> = {}) {
        super(address, credentials, options);
        this._binaryOptions = binaryOptions;
    }
    /**
     * encodes and forwards usage reports to the PostHog event database; each
     * event is annotated with some properties that depend on the identity of the
     * caller:
     * - tp.account_id (UUID in string form, can be empty if missing from the
     *   license)
     * - tp.license_name (should always be a UUID)
     * - tp.license_authority (name of the authority that signed the license file
     *   used for authentication)
     * - tp.is_cloud (boolean)
     *
     * @generated from protobuf rpc: SubmitUsageReports(prehog.v1.SubmitUsageReportsRequest) returns (prehog.v1.SubmitUsageReportsResponse);
     */
    submitUsageReports(input: SubmitUsageReportsRequest, metadata: grpc.Metadata | grpc.CallOptions | ((err: grpc.ServiceError | null, value?: SubmitUsageReportsResponse) => void), options?: grpc.CallOptions | ((err: grpc.ServiceError | null, value?: SubmitUsageReportsResponse) => void), callback?: ((err: grpc.ServiceError | null, value?: SubmitUsageReportsResponse) => void)): grpc.ClientUnaryCall {
        const method = TeleportReportingService.methods[0];
        return this.makeUnaryRequest<SubmitUsageReportsRequest, SubmitUsageReportsResponse>(`/${TeleportReportingService.typeName}/${method.name}`, (value: SubmitUsageReportsRequest): Buffer => Buffer.from(method.I.toBinary(value, this._binaryOptions)), (value: Buffer): SubmitUsageReportsResponse => method.O.fromBinary(value, this._binaryOptions), input, (metadata as any), (options as any), (callback as any));
    }
}
