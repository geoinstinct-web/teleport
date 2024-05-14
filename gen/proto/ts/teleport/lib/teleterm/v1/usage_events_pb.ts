/* eslint-disable */
// @generated by protobuf-ts 2.9.3 with parameter eslint_disable,add_pb_suffix,server_grpc1,ts_nocheck
// @generated from protobuf file "teleport/lib/teleterm/v1/usage_events.proto" (package "teleport.lib.teleterm.v1", syntax proto3)
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
import type { BinaryWriteOptions } from "@protobuf-ts/runtime";
import type { IBinaryWriter } from "@protobuf-ts/runtime";
import { WireType } from "@protobuf-ts/runtime";
import type { BinaryReadOptions } from "@protobuf-ts/runtime";
import type { IBinaryReader } from "@protobuf-ts/runtime";
import { UnknownFieldHandler } from "@protobuf-ts/runtime";
import type { PartialMessage } from "@protobuf-ts/runtime";
import { reflectionMergePartial } from "@protobuf-ts/runtime";
import { MessageType } from "@protobuf-ts/runtime";
import { SubmitConnectEventRequest } from "../../../../prehog/v1alpha/connect_pb";
/**
 * @generated from protobuf message teleport.lib.teleterm.v1.ReportUsageEventRequest
 */
export interface ReportUsageEventRequest {
    /**
     * @generated from protobuf field: string auth_cluster_id = 1;
     */
    authClusterId: string;
    /**
     * @generated from protobuf field: prehog.v1alpha.SubmitConnectEventRequest prehog_req = 2;
     */
    prehogReq?: SubmitConnectEventRequest;
}
// @generated message type with reflection information, may provide speed optimized methods
class ReportUsageEventRequest$Type extends MessageType<ReportUsageEventRequest> {
    constructor() {
        super("teleport.lib.teleterm.v1.ReportUsageEventRequest", [
            { no: 1, name: "auth_cluster_id", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 2, name: "prehog_req", kind: "message", T: () => SubmitConnectEventRequest }
        ]);
    }
    create(value?: PartialMessage<ReportUsageEventRequest>): ReportUsageEventRequest {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.authClusterId = "";
        if (value !== undefined)
            reflectionMergePartial<ReportUsageEventRequest>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: ReportUsageEventRequest): ReportUsageEventRequest {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* string auth_cluster_id */ 1:
                    message.authClusterId = reader.string();
                    break;
                case /* prehog.v1alpha.SubmitConnectEventRequest prehog_req */ 2:
                    message.prehogReq = SubmitConnectEventRequest.internalBinaryRead(reader, reader.uint32(), options, message.prehogReq);
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
    internalBinaryWrite(message: ReportUsageEventRequest, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* string auth_cluster_id = 1; */
        if (message.authClusterId !== "")
            writer.tag(1, WireType.LengthDelimited).string(message.authClusterId);
        /* prehog.v1alpha.SubmitConnectEventRequest prehog_req = 2; */
        if (message.prehogReq)
            SubmitConnectEventRequest.internalBinaryWrite(message.prehogReq, writer.tag(2, WireType.LengthDelimited).fork(), options).join();
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.v1.ReportUsageEventRequest
 */
export const ReportUsageEventRequest = new ReportUsageEventRequest$Type();
