# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: teleport/assistant/v1/assistant.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n%teleport/assistant/v1/assistant.proto\x12\x15teleport.assistant.v1\"D\n\x15\x43hatCompletionMessage\x12\x0c\n\x04role\x18\x01 \x01(\t\x12\x0f\n\x07\x63ontent\x18\x02 \x01(\t\x12\x0c\n\x04name\x18\x03 \x01(\t\"c\n\x0f\x43ompleteRequest\x12\x10\n\x08username\x18\x01 \x01(\t\x12>\n\x08messages\x18\x02 \x03(\x0b\x32,.teleport.assistant.v1.ChatCompletionMessage\"#\n\x05Label\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t\"\x81\x01\n\x12\x43ompletionResponse\x12\x0c\n\x04kind\x18\x01 \x01(\t\x12\x0f\n\x07\x63ontent\x18\x02 \x01(\t\x12\x0f\n\x07\x63ommand\x18\x03 \x01(\t\x12\r\n\x05nodes\x18\x04 \x03(\t\x12,\n\x06labels\x18\x05 \x03(\x0b\x32\x1c.teleport.assistant.v1.Label2q\n\x10\x41ssistantService\x12]\n\x08\x43omplete\x12&.teleport.assistant.v1.CompleteRequest\x1a).teleport.assistant.v1.CompletionResponseBAZ?github.com/gravitational/teleport/api/gen/proto/go/assistant/v1b\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'teleport.assistant.v1.assistant_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'Z?github.com/gravitational/teleport/api/gen/proto/go/assistant/v1'
  _CHATCOMPLETIONMESSAGE._serialized_start=64
  _CHATCOMPLETIONMESSAGE._serialized_end=132
  _COMPLETEREQUEST._serialized_start=134
  _COMPLETEREQUEST._serialized_end=233
  _LABEL._serialized_start=235
  _LABEL._serialized_end=270
  _COMPLETIONRESPONSE._serialized_start=273
  _COMPLETIONRESPONSE._serialized_end=402
  _ASSISTANTSERVICE._serialized_start=404
  _ASSISTANTSERVICE._serialized_end=517
# @@protoc_insertion_point(module_scope)
