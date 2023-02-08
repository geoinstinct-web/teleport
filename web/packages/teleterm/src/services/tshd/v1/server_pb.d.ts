/**
 * Copyright 2023 Gravitational, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// package: teleport.terminal.v1
// file: v1/server.proto

/* tslint:disable */
/* eslint-disable */

import * as jspb from "google-protobuf";
import * as v1_label_pb from "../v1/label_pb";

export class Server extends jspb.Message { 
    getUri(): string;
    setUri(value: string): Server;

    getTunnel(): boolean;
    setTunnel(value: boolean): Server;

    getName(): string;
    setName(value: string): Server;

    getHostname(): string;
    setHostname(value: string): Server;

    getAddr(): string;
    setAddr(value: string): Server;

    clearLabelsList(): void;
    getLabelsList(): Array<v1_label_pb.Label>;
    setLabelsList(value: Array<v1_label_pb.Label>): Server;
    addLabels(value?: v1_label_pb.Label, index?: number): v1_label_pb.Label;


    serializeBinary(): Uint8Array;
    toObject(includeInstance?: boolean): Server.AsObject;
    static toObject(includeInstance: boolean, msg: Server): Server.AsObject;
    static extensions: {[key: number]: jspb.ExtensionFieldInfo<jspb.Message>};
    static extensionsBinary: {[key: number]: jspb.ExtensionFieldBinaryInfo<jspb.Message>};
    static serializeBinaryToWriter(message: Server, writer: jspb.BinaryWriter): void;
    static deserializeBinary(bytes: Uint8Array): Server;
    static deserializeBinaryFromReader(message: Server, reader: jspb.BinaryReader): Server;
}

export namespace Server {
    export type AsObject = {
        uri: string,
        tunnel: boolean,
        name: string,
        hostname: string,
        addr: string,
        labelsList: Array<v1_label_pb.Label.AsObject>,
    }
}
