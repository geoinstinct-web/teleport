# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: teleport/discoveryconfig/v1/discoveryconfig.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from teleport.header.v1 import resourceheader_pb2 as teleport_dot_header_dot_v1_dot_resourceheader__pb2
from teleport.legacy.types import types_pb2 as teleport_dot_legacy_dot_types_dot_types__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n1teleport/discoveryconfig/v1/discoveryconfig.proto\x12\x1bteleport.discoveryconfig.v1\x1a\'teleport/header/v1/resourceheader.proto\x1a!teleport/legacy/types/types.proto\"\x93\x01\n\x0f\x44iscoveryConfig\x12:\n\x06header\x18\x01 \x01(\x0b\x32\".teleport.header.v1.ResourceHeaderR\x06header\x12\x44\n\x04spec\x18\x02 \x01(\x0b\x32\x30.teleport.discoveryconfig.v1.DiscoveryConfigSpecR\x04spec\"\xe1\x01\n\x13\x44iscoveryConfigSpec\x12\'\n\x0f\x64iscovery_group\x18\x01 \x01(\tR\x0e\x64iscoveryGroup\x12#\n\x03\x61ws\x18\x02 \x03(\x0b\x32\x11.types.AWSMatcherR\x03\x61ws\x12)\n\x05\x61zure\x18\x03 \x03(\x0b\x32\x13.types.AzureMatcherR\x05\x61zure\x12#\n\x03gcp\x18\x04 \x03(\x0b\x32\x11.types.GCPMatcherR\x03gcp\x12,\n\x04kube\x18\x05 \x03(\x0b\x32\x18.types.KubernetesMatcherR\x04kubeBbZ`github.com/gravitational/teleport/api/gen/proto/go/teleport/discoveryconfig/v1;discoveryconfigv1b\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'teleport.discoveryconfig.v1.discoveryconfig_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'Z`github.com/gravitational/teleport/api/gen/proto/go/teleport/discoveryconfig/v1;discoveryconfigv1'
  _DISCOVERYCONFIG._serialized_start=159
  _DISCOVERYCONFIG._serialized_end=306
  _DISCOVERYCONFIGSPEC._serialized_start=309
  _DISCOVERYCONFIGSPEC._serialized_end=534
# @@protoc_insertion_point(module_scope)
