# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: teleport/transport/v1/transport_service.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n-teleport/transport/v1/transport_service.proto\x12\x15teleport.transport.v1\"\xc6\x01\n\x0fProxySSHRequest\x12\x42\n\x0b\x64ial_target\x18\x01 \x01(\x0b\x32!.teleport.transport.v1.TargetHostR\ndialTarget\x12\x30\n\x03ssh\x18\x02 \x01(\x0b\x32\x1c.teleport.transport.v1.FrameH\x00R\x03ssh\x12\x34\n\x05\x61gent\x18\x03 \x01(\x0b\x32\x1c.teleport.transport.v1.FrameH\x00R\x05\x61gentB\x07\n\x05\x66rame\"\xc4\x01\n\x10ProxySSHResponse\x12?\n\x07\x64\x65tails\x18\x01 \x01(\x0b\x32%.teleport.transport.v1.ClusterDetailsR\x07\x64\x65tails\x12\x30\n\x03ssh\x18\x02 \x01(\x0b\x32\x1c.teleport.transport.v1.FrameH\x00R\x03ssh\x12\x34\n\x05\x61gent\x18\x03 \x01(\x0b\x32\x1c.teleport.transport.v1.FrameH\x00R\x05\x61gentB\x07\n\x05\x66rame\"c\n\x13ProxyClusterRequest\x12\x18\n\x07\x63luster\x18\x01 \x01(\tR\x07\x63luster\x12\x32\n\x05\x66rame\x18\x02 \x01(\x0b\x32\x1c.teleport.transport.v1.FrameR\x05\x66rame\"J\n\x14ProxyClusterResponse\x12\x32\n\x05\x66rame\x18\x01 \x01(\x0b\x32\x1c.teleport.transport.v1.FrameR\x05\x66rame\"!\n\x05\x46rame\x12\x18\n\x07payload\x18\x01 \x01(\x0cR\x07payload\"C\n\nTargetHost\x12\x1b\n\thost_port\x18\x01 \x01(\tR\x08hostPort\x12\x18\n\x07\x63luster\x18\x02 \x01(\tR\x07\x63luster\"\x1a\n\x18GetClusterDetailsRequest\"\\\n\x19GetClusterDetailsResponse\x12?\n\x07\x64\x65tails\x18\x01 \x01(\x0b\x32%.teleport.transport.v1.ClusterDetailsR\x07\x64\x65tails\"3\n\x0e\x43lusterDetails\x12!\n\x0c\x66ips_enabled\x18\x01 \x01(\x08R\x0b\x66ipsEnabled2\xd8\x02\n\x10TransportService\x12v\n\x11GetClusterDetails\x12/.teleport.transport.v1.GetClusterDetailsRequest\x1a\x30.teleport.transport.v1.GetClusterDetailsResponse\x12_\n\x08ProxySSH\x12&.teleport.transport.v1.ProxySSHRequest\x1a\'.teleport.transport.v1.ProxySSHResponse(\x01\x30\x01\x12k\n\x0cProxyCluster\x12*.teleport.transport.v1.ProxyClusterRequest\x1a+.teleport.transport.v1.ProxyClusterResponse(\x01\x30\x01\x42VZTgithub.com/gravitational/teleport/api/gen/proto/go/teleport/transport/v1;transportv1b\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'teleport.transport.v1.transport_service_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'ZTgithub.com/gravitational/teleport/api/gen/proto/go/teleport/transport/v1;transportv1'
  _PROXYSSHREQUEST._serialized_start=73
  _PROXYSSHREQUEST._serialized_end=271
  _PROXYSSHRESPONSE._serialized_start=274
  _PROXYSSHRESPONSE._serialized_end=470
  _PROXYCLUSTERREQUEST._serialized_start=472
  _PROXYCLUSTERREQUEST._serialized_end=571
  _PROXYCLUSTERRESPONSE._serialized_start=573
  _PROXYCLUSTERRESPONSE._serialized_end=647
  _FRAME._serialized_start=649
  _FRAME._serialized_end=682
  _TARGETHOST._serialized_start=684
  _TARGETHOST._serialized_end=751
  _GETCLUSTERDETAILSREQUEST._serialized_start=753
  _GETCLUSTERDETAILSREQUEST._serialized_end=779
  _GETCLUSTERDETAILSRESPONSE._serialized_start=781
  _GETCLUSTERDETAILSRESPONSE._serialized_end=873
  _CLUSTERDETAILS._serialized_start=875
  _CLUSTERDETAILS._serialized_end=926
  _TRANSPORTSERVICE._serialized_start=929
  _TRANSPORTSERVICE._serialized_end=1273
# @@protoc_insertion_point(module_scope)
