/* eslint-disable */
// @generated by protobuf-ts 2.9.3 with parameter long_type_number,eslint_disable,add_pb_suffix,client_grpc1,server_grpc1,ts_nocheck
// @generated from protobuf file "teleport/devicetrust/v1/user_certificates.proto" (package "teleport.devicetrust.v1", syntax proto3)
// tslint:disable
// @ts-nocheck
//
// Copyright 2022 Gravitational, Inc
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
/**
 * UserCertificates is used to transport X.509 and SSH certificates during
 * device authentication.
 * See the AuthenticateDevice RPC.
 *
 * @generated from protobuf message teleport.devicetrust.v1.UserCertificates
 */
export interface UserCertificates {
    /**
     * DER-encoded X.509 user certificate.
     *
     * @generated from protobuf field: bytes x509_der = 1;
     */
    x509Der: Uint8Array;
    /**
     * SSH certificate marshaled in the authorized key format.
     *
     * @generated from protobuf field: bytes ssh_authorized_key = 2;
     */
    sshAuthorizedKey: Uint8Array;
}
// @generated message type with reflection information, may provide speed optimized methods
class UserCertificates$Type extends MessageType<UserCertificates> {
    constructor() {
        super("teleport.devicetrust.v1.UserCertificates", [
            { no: 1, name: "x509_der", kind: "scalar", T: 12 /*ScalarType.BYTES*/ },
            { no: 2, name: "ssh_authorized_key", kind: "scalar", T: 12 /*ScalarType.BYTES*/ }
        ]);
    }
    create(value?: PartialMessage<UserCertificates>): UserCertificates {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.x509Der = new Uint8Array(0);
        message.sshAuthorizedKey = new Uint8Array(0);
        if (value !== undefined)
            reflectionMergePartial<UserCertificates>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: UserCertificates): UserCertificates {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* bytes x509_der */ 1:
                    message.x509Der = reader.bytes();
                    break;
                case /* bytes ssh_authorized_key */ 2:
                    message.sshAuthorizedKey = reader.bytes();
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
    internalBinaryWrite(message: UserCertificates, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* bytes x509_der = 1; */
        if (message.x509Der.length)
            writer.tag(1, WireType.LengthDelimited).bytes(message.x509Der);
        /* bytes ssh_authorized_key = 2; */
        if (message.sshAuthorizedKey.length)
            writer.tag(2, WireType.LengthDelimited).bytes(message.sshAuthorizedKey);
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.devicetrust.v1.UserCertificates
 */
export const UserCertificates = new UserCertificates$Type();
