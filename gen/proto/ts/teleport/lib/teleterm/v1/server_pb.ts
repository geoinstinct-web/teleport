/* eslint-disable */
// @generated by protobuf-ts 2.9.3 with parameter long_type_number,eslint_disable,add_pb_suffix,client_grpc1,server_grpc1,ts_nocheck
// @generated from protobuf file "teleport/lib/teleterm/v1/server.proto" (package "teleport.lib.teleterm.v1", syntax proto3)
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
import { Label } from "./label_pb";
/**
 * Server describes connected Server
 *
 * @generated from protobuf message teleport.lib.teleterm.v1.Server
 */
export interface Server {
    /**
     * uri is the server uri
     *
     * @generated from protobuf field: string uri = 1;
     */
    uri: string;
    /**
     * tunnel indicates if this server is connected over a reverse tunnel
     *
     * @generated from protobuf field: bool tunnel = 2;
     */
    tunnel: boolean;
    /**
     * name is the server name
     *
     * @generated from protobuf field: string name = 3;
     */
    name: string;
    /**
     * hostname is this server hostname
     *
     * @generated from protobuf field: string hostname = 4;
     */
    hostname: string;
    /**
     * addr is this server ip address
     *
     * @generated from protobuf field: string addr = 5;
     */
    addr: string;
    /**
     * labels is this server list of labels
     *
     * @generated from protobuf field: repeated teleport.lib.teleterm.v1.Label labels = 6;
     */
    labels: Label[];
    /**
     * node sub kind: teleport, openssh, openssh-ec2-ice
     *
     * @generated from protobuf field: string sub_kind = 7;
     */
    subKind: string;
}
// @generated message type with reflection information, may provide speed optimized methods
class Server$Type extends MessageType<Server> {
    constructor() {
        super("teleport.lib.teleterm.v1.Server", [
            { no: 1, name: "uri", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 2, name: "tunnel", kind: "scalar", T: 8 /*ScalarType.BOOL*/ },
            { no: 3, name: "name", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 4, name: "hostname", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 5, name: "addr", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 6, name: "labels", kind: "message", repeat: 1 /*RepeatType.PACKED*/, T: () => Label },
            { no: 7, name: "sub_kind", kind: "scalar", T: 9 /*ScalarType.STRING*/ }
        ]);
    }
    create(value?: PartialMessage<Server>): Server {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.uri = "";
        message.tunnel = false;
        message.name = "";
        message.hostname = "";
        message.addr = "";
        message.labels = [];
        message.subKind = "";
        if (value !== undefined)
            reflectionMergePartial<Server>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: Server): Server {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* string uri */ 1:
                    message.uri = reader.string();
                    break;
                case /* bool tunnel */ 2:
                    message.tunnel = reader.bool();
                    break;
                case /* string name */ 3:
                    message.name = reader.string();
                    break;
                case /* string hostname */ 4:
                    message.hostname = reader.string();
                    break;
                case /* string addr */ 5:
                    message.addr = reader.string();
                    break;
                case /* repeated teleport.lib.teleterm.v1.Label labels */ 6:
                    message.labels.push(Label.internalBinaryRead(reader, reader.uint32(), options));
                    break;
                case /* string sub_kind */ 7:
                    message.subKind = reader.string();
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
    internalBinaryWrite(message: Server, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* string uri = 1; */
        if (message.uri !== "")
            writer.tag(1, WireType.LengthDelimited).string(message.uri);
        /* bool tunnel = 2; */
        if (message.tunnel !== false)
            writer.tag(2, WireType.Varint).bool(message.tunnel);
        /* string name = 3; */
        if (message.name !== "")
            writer.tag(3, WireType.LengthDelimited).string(message.name);
        /* string hostname = 4; */
        if (message.hostname !== "")
            writer.tag(4, WireType.LengthDelimited).string(message.hostname);
        /* string addr = 5; */
        if (message.addr !== "")
            writer.tag(5, WireType.LengthDelimited).string(message.addr);
        /* repeated teleport.lib.teleterm.v1.Label labels = 6; */
        for (let i = 0; i < message.labels.length; i++)
            Label.internalBinaryWrite(message.labels[i], writer.tag(6, WireType.LengthDelimited).fork(), options).join();
        /* string sub_kind = 7; */
        if (message.subKind !== "")
            writer.tag(7, WireType.LengthDelimited).string(message.subKind);
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.v1.Server
 */
export const Server = new Server$Type();
