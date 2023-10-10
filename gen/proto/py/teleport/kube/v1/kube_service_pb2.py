# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: teleport/kube/v1/kube_service.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from teleport.legacy.types import types_pb2 as teleport_dot_legacy_dot_types_dot_types__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n#teleport/kube/v1/kube_service.proto\x12\x10teleport.kube.v1\x1a!teleport/legacy/types/types.proto\"\xa4\x05\n\x1eListKubernetesResourcesRequest\x12#\n\rresource_type\x18\x01 \x01(\tR\x0cresourceType\x12\x14\n\x05limit\x18\x02 \x01(\x05R\x05limit\x12\x1b\n\tstart_key\x18\x03 \x01(\tR\x08startKey\x12T\n\x06labels\x18\x04 \x03(\x0b\x32<.teleport.kube.v1.ListKubernetesResourcesRequest.LabelsEntryR\x06labels\x12\x31\n\x14predicate_expression\x18\x05 \x01(\tR\x13predicateExpression\x12\'\n\x0fsearch_keywords\x18\x06 \x03(\tR\x0esearchKeywords\x12&\n\x07sort_by\x18\x07 \x01(\x0b\x32\r.types.SortByR\x06sortBy\x12(\n\x10need_total_count\x18\x08 \x01(\x08R\x0eneedTotalCount\x12-\n\x13use_search_as_roles\x18\t \x01(\x08R\x10useSearchAsRoles\x12/\n\x14use_preview_as_roles\x18\x0b \x01(\x08R\x11usePreviewAsRoles\x12)\n\x10teleport_cluster\x18\x0c \x01(\tR\x0fteleportCluster\x12-\n\x12kubernetes_cluster\x18\r \x01(\tR\x11kubernetesCluster\x12\x31\n\x14kubernetes_namespace\x18\x0e \x01(\tR\x13kubernetesNamespace\x1a\x39\n\x0bLabelsEntry\x12\x10\n\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n\x05value\x18\x02 \x01(\tR\x05value:\x02\x38\x01\"\x98\x01\n\x1fListKubernetesResourcesResponse\x12\x39\n\tresources\x18\x01 \x03(\x0b\x32\x1b.types.KubernetesResourceV1R\tresources\x12\x19\n\x08next_key\x18\x02 \x01(\tR\x07nextKey\x12\x1f\n\x0btotal_count\x18\x03 \x01(\x05R\ntotalCount2\x8d\x01\n\x0bKubeService\x12~\n\x17ListKubernetesResources\x12\x30.teleport.kube.v1.ListKubernetesResourcesRequest\x1a\x31.teleport.kube.v1.ListKubernetesResourcesResponseBLZJgithub.com/gravitational/teleport/api/gen/proto/go/teleport/kube/v1;kubev1b\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'teleport.kube.v1.kube_service_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'ZJgithub.com/gravitational/teleport/api/gen/proto/go/teleport/kube/v1;kubev1'
  _LISTKUBERNETESRESOURCESREQUEST_LABELSENTRY._options = None
  _LISTKUBERNETESRESOURCESREQUEST_LABELSENTRY._serialized_options = b'8\001'
  _LISTKUBERNETESRESOURCESREQUEST._serialized_start=93
  _LISTKUBERNETESRESOURCESREQUEST._serialized_end=769
  _LISTKUBERNETESRESOURCESREQUEST_LABELSENTRY._serialized_start=712
  _LISTKUBERNETESRESOURCESREQUEST_LABELSENTRY._serialized_end=769
  _LISTKUBERNETESRESOURCESRESPONSE._serialized_start=772
  _LISTKUBERNETESRESOURCESRESPONSE._serialized_end=924
  _KUBESERVICE._serialized_start=927
  _KUBESERVICE._serialized_end=1068
# @@protoc_insertion_point(module_scope)
