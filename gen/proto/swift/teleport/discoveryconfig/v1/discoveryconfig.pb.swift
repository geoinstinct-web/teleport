// DO NOT EDIT.
// swift-format-ignore-file
//
// Generated by the Swift generator plugin for the protocol buffer compiler.
// Source: teleport/discoveryconfig/v1/discoveryconfig.proto
//
// For information on using the generated types, please see the documentation:
//   https://github.com/apple/swift-protobuf/

// Copyright 2023 Gravitational, Inc
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

import Foundation
import SwiftProtobuf

// If the compiler emits an error on this type, it is because this file
// was generated by a version of the `protoc` Swift plug-in that is
// incompatible with the version of SwiftProtobuf to which you are linking.
// Please ensure that you are building against the same version of the API
// that was used to generate this file.
fileprivate struct _GeneratedWithProtocGenSwiftVersion: SwiftProtobuf.ProtobufAPIVersionCheck {
  struct _2: SwiftProtobuf.ProtobufAPIVersion_2 {}
  typealias Version = _2
}

/// DiscoveryConfig is a resource that has Discovery Resource Matchers and a Discovery Group.
///
/// Teleport Discovery Services will load the dynamic DiscoveryConfigs whose Discovery Group matches the discovery_group defined in their configuration.
struct Teleport_Discoveryconfig_V1_DiscoveryConfig {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// Header is the resource header.
  var header: Teleport_Header_V1_ResourceHeader {
    get {return _header ?? Teleport_Header_V1_ResourceHeader()}
    set {_header = newValue}
  }
  /// Returns true if `header` has been explicitly set.
  var hasHeader: Bool {return self._header != nil}
  /// Clears the value of `header`. Subsequent reads from it will return its default value.
  mutating func clearHeader() {self._header = nil}

  /// Spec is an DiscoveryConfig specification.
  var spec: Teleport_Discoveryconfig_V1_DiscoveryConfigSpec {
    get {return _spec ?? Teleport_Discoveryconfig_V1_DiscoveryConfigSpec()}
    set {_spec = newValue}
  }
  /// Returns true if `spec` has been explicitly set.
  var hasSpec: Bool {return self._spec != nil}
  /// Clears the value of `spec`. Subsequent reads from it will return its default value.
  mutating func clearSpec() {self._spec = nil}

  var unknownFields = SwiftProtobuf.UnknownStorage()

  init() {}

  fileprivate var _header: Teleport_Header_V1_ResourceHeader? = nil
  fileprivate var _spec: Teleport_Discoveryconfig_V1_DiscoveryConfigSpec? = nil
}

/// DiscoveryConfigSpec contains properties required to create matchers to be used by discovery_service.
/// Those matchers are used by discovery_service to watch for cloud resources and create them in Teleport.
struct Teleport_Discoveryconfig_V1_DiscoveryConfigSpec {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// DiscoveryGroup is used by discovery_service to add extra matchers.
  /// All the discovery_services that have the same discovery_group, will load the matchers of this resource.
  var discoveryGroup: String = String()

  /// AWS is a list of AWS Matchers.
  var aws: [Types_AWSMatcher] = []

  /// Azure is a list of Azure Matchers.
  var azure: [Types_AzureMatcher] = []

  /// GCP is a list of GCP Matchers.
  var gcp: [Types_GCPMatcher] = []

  /// Kube is a list of Kubernetes Matchers.
  var kube: [Types_KubernetesMatcher] = []

  var unknownFields = SwiftProtobuf.UnknownStorage()

  init() {}
}

#if swift(>=5.5) && canImport(_Concurrency)
extension Teleport_Discoveryconfig_V1_DiscoveryConfig: @unchecked Sendable {}
extension Teleport_Discoveryconfig_V1_DiscoveryConfigSpec: @unchecked Sendable {}
#endif  // swift(>=5.5) && canImport(_Concurrency)

// MARK: - Code below here is support for the SwiftProtobuf runtime.

fileprivate let _protobuf_package = "teleport.discoveryconfig.v1"

extension Teleport_Discoveryconfig_V1_DiscoveryConfig: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  static let protoMessageName: String = _protobuf_package + ".DiscoveryConfig"
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "header"),
    2: .same(proto: "spec"),
  ]

  mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularMessageField(value: &self._header) }()
      case 2: try { try decoder.decodeSingularMessageField(value: &self._spec) }()
      default: break
      }
    }
  }

  func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    // The use of inline closures is to circumvent an issue where the compiler
    // allocates stack space for every if/case branch local when no optimizations
    // are enabled. https://github.com/apple/swift-protobuf/issues/1034 and
    // https://github.com/apple/swift-protobuf/issues/1182
    try { if let v = self._header {
      try visitor.visitSingularMessageField(value: v, fieldNumber: 1)
    } }()
    try { if let v = self._spec {
      try visitor.visitSingularMessageField(value: v, fieldNumber: 2)
    } }()
    try unknownFields.traverse(visitor: &visitor)
  }

  static func ==(lhs: Teleport_Discoveryconfig_V1_DiscoveryConfig, rhs: Teleport_Discoveryconfig_V1_DiscoveryConfig) -> Bool {
    if lhs._header != rhs._header {return false}
    if lhs._spec != rhs._spec {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Teleport_Discoveryconfig_V1_DiscoveryConfigSpec: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  static let protoMessageName: String = _protobuf_package + ".DiscoveryConfigSpec"
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .standard(proto: "discovery_group"),
    2: .same(proto: "aws"),
    3: .same(proto: "azure"),
    4: .same(proto: "gcp"),
    5: .same(proto: "kube"),
  ]

  mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularStringField(value: &self.discoveryGroup) }()
      case 2: try { try decoder.decodeRepeatedMessageField(value: &self.aws) }()
      case 3: try { try decoder.decodeRepeatedMessageField(value: &self.azure) }()
      case 4: try { try decoder.decodeRepeatedMessageField(value: &self.gcp) }()
      case 5: try { try decoder.decodeRepeatedMessageField(value: &self.kube) }()
      default: break
      }
    }
  }

  func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if !self.discoveryGroup.isEmpty {
      try visitor.visitSingularStringField(value: self.discoveryGroup, fieldNumber: 1)
    }
    if !self.aws.isEmpty {
      try visitor.visitRepeatedMessageField(value: self.aws, fieldNumber: 2)
    }
    if !self.azure.isEmpty {
      try visitor.visitRepeatedMessageField(value: self.azure, fieldNumber: 3)
    }
    if !self.gcp.isEmpty {
      try visitor.visitRepeatedMessageField(value: self.gcp, fieldNumber: 4)
    }
    if !self.kube.isEmpty {
      try visitor.visitRepeatedMessageField(value: self.kube, fieldNumber: 5)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  static func ==(lhs: Teleport_Discoveryconfig_V1_DiscoveryConfigSpec, rhs: Teleport_Discoveryconfig_V1_DiscoveryConfigSpec) -> Bool {
    if lhs.discoveryGroup != rhs.discoveryGroup {return false}
    if lhs.aws != rhs.aws {return false}
    if lhs.azure != rhs.azure {return false}
    if lhs.gcp != rhs.gcp {return false}
    if lhs.kube != rhs.kube {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}
