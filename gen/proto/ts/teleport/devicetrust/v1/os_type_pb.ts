/* eslint-disable */
// @generated by protobuf-ts 2.9.3 with parameter eslint_disable,add_pb_suffix,server_grpc1,ts_nocheck
// @generated from protobuf file "teleport/devicetrust/v1/os_type.proto" (package "teleport.devicetrust.v1", syntax proto3)
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
/**
 * OSType represents the operating system of a device.
 *
 * @generated from protobuf enum teleport.devicetrust.v1.OSType
 */
export enum OSType {
    /**
     * @generated from protobuf enum value: OS_TYPE_UNSPECIFIED = 0;
     */
    OS_TYPE_UNSPECIFIED = 0,
    /**
     * Linux.
     *
     * @generated from protobuf enum value: OS_TYPE_LINUX = 1;
     */
    OS_TYPE_LINUX = 1,
    /**
     * macOS.
     *
     * @generated from protobuf enum value: OS_TYPE_MACOS = 2;
     */
    OS_TYPE_MACOS = 2,
    /**
     * Windows.
     *
     * @generated from protobuf enum value: OS_TYPE_WINDOWS = 3;
     */
    OS_TYPE_WINDOWS = 3
}
