/* eslint-disable */
// @generated by protobuf-ts 2.9.3 with parameter long_type_number,eslint_disable,add_pb_suffix,server_grpc1,ts_nocheck
// @generated from protobuf file "teleport/devicetrust/v1/device_confirmation_token.proto" (package "teleport.devicetrust.v1", syntax proto3)
// tslint:disable
// @ts-nocheck
//
// Copyright 2024 Gravitational, Inc
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
 * A device confirmation token marks the last step of device web authentication.
 * It is acquired at the end of a successful AuthenticateDevice stream and
 * exchanged during the ConfirmDeviceWebAuthentication RPC.
 *
 * See
 * https://github.com/gravitational/teleport.e/blob/master/rfd/0009e-device-trust-web-support.md#device-confirmation-token.
 *
 * @generated from protobuf message teleport.devicetrust.v1.DeviceConfirmationToken
 */
export interface DeviceConfirmationToken {
    /**
     * Opaque token identifier.
     * System-generated.
     *
     * @generated from protobuf field: string id = 1;
     */
    id: string;
    /**
     * Opaque device confirmation token, in plaintext, encoded in
     * base64.RawURLEncoding (so it is inherently safe for URl use).
     * System-generated.
     *
     * @generated from protobuf field: string token = 2;
     */
    token: string;
}
// @generated message type with reflection information, may provide speed optimized methods
class DeviceConfirmationToken$Type extends MessageType<DeviceConfirmationToken> {
    constructor() {
        super("teleport.devicetrust.v1.DeviceConfirmationToken", [
            { no: 1, name: "id", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 2, name: "token", kind: "scalar", T: 9 /*ScalarType.STRING*/ }
        ]);
    }
    create(value?: PartialMessage<DeviceConfirmationToken>): DeviceConfirmationToken {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.id = "";
        message.token = "";
        if (value !== undefined)
            reflectionMergePartial<DeviceConfirmationToken>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: DeviceConfirmationToken): DeviceConfirmationToken {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* string id */ 1:
                    message.id = reader.string();
                    break;
                case /* string token */ 2:
                    message.token = reader.string();
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
    internalBinaryWrite(message: DeviceConfirmationToken, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* string id = 1; */
        if (message.id !== "")
            writer.tag(1, WireType.LengthDelimited).string(message.id);
        /* string token = 2; */
        if (message.token !== "")
            writer.tag(2, WireType.LengthDelimited).string(message.token);
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.devicetrust.v1.DeviceConfirmationToken
 */
export const DeviceConfirmationToken = new DeviceConfirmationToken$Type();
