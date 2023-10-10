# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

from google.protobuf import empty_pb2 as google_dot_protobuf_dot_empty__pb2
from teleport.legacy.types import types_pb2 as teleport_dot_legacy_dot_types_dot_types__pb2
from teleport.trust.v1 import trust_service_pb2 as teleport_dot_trust_dot_v1_dot_trust__service__pb2


class TrustServiceStub(object):
    """TrustService provides methods to manage certificate authorities.
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.GetCertAuthority = channel.unary_unary(
                '/teleport.trust.v1.TrustService/GetCertAuthority',
                request_serializer=teleport_dot_trust_dot_v1_dot_trust__service__pb2.GetCertAuthorityRequest.SerializeToString,
                response_deserializer=teleport_dot_legacy_dot_types_dot_types__pb2.CertAuthorityV2.FromString,
                )
        self.GetCertAuthorities = channel.unary_unary(
                '/teleport.trust.v1.TrustService/GetCertAuthorities',
                request_serializer=teleport_dot_trust_dot_v1_dot_trust__service__pb2.GetCertAuthoritiesRequest.SerializeToString,
                response_deserializer=teleport_dot_trust_dot_v1_dot_trust__service__pb2.GetCertAuthoritiesResponse.FromString,
                )
        self.DeleteCertAuthority = channel.unary_unary(
                '/teleport.trust.v1.TrustService/DeleteCertAuthority',
                request_serializer=teleport_dot_trust_dot_v1_dot_trust__service__pb2.DeleteCertAuthorityRequest.SerializeToString,
                response_deserializer=google_dot_protobuf_dot_empty__pb2.Empty.FromString,
                )
        self.UpsertCertAuthority = channel.unary_unary(
                '/teleport.trust.v1.TrustService/UpsertCertAuthority',
                request_serializer=teleport_dot_trust_dot_v1_dot_trust__service__pb2.UpsertCertAuthorityRequest.SerializeToString,
                response_deserializer=teleport_dot_legacy_dot_types_dot_types__pb2.CertAuthorityV2.FromString,
                )


class TrustServiceServicer(object):
    """TrustService provides methods to manage certificate authorities.
    """

    def GetCertAuthority(self, request, context):
        """GetCertAuthority returns a cert authority by type and domain.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetCertAuthorities(self, request, context):
        """GetCertAuthorities returns all cert authorities with the specified type.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def DeleteCertAuthority(self, request, context):
        """DeleteCertAuthority deletes the matching cert authority.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def UpsertCertAuthority(self, request, context):
        """UpsertCertAuthority creates or updates the provided cert authority.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_TrustServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'GetCertAuthority': grpc.unary_unary_rpc_method_handler(
                    servicer.GetCertAuthority,
                    request_deserializer=teleport_dot_trust_dot_v1_dot_trust__service__pb2.GetCertAuthorityRequest.FromString,
                    response_serializer=teleport_dot_legacy_dot_types_dot_types__pb2.CertAuthorityV2.SerializeToString,
            ),
            'GetCertAuthorities': grpc.unary_unary_rpc_method_handler(
                    servicer.GetCertAuthorities,
                    request_deserializer=teleport_dot_trust_dot_v1_dot_trust__service__pb2.GetCertAuthoritiesRequest.FromString,
                    response_serializer=teleport_dot_trust_dot_v1_dot_trust__service__pb2.GetCertAuthoritiesResponse.SerializeToString,
            ),
            'DeleteCertAuthority': grpc.unary_unary_rpc_method_handler(
                    servicer.DeleteCertAuthority,
                    request_deserializer=teleport_dot_trust_dot_v1_dot_trust__service__pb2.DeleteCertAuthorityRequest.FromString,
                    response_serializer=google_dot_protobuf_dot_empty__pb2.Empty.SerializeToString,
            ),
            'UpsertCertAuthority': grpc.unary_unary_rpc_method_handler(
                    servicer.UpsertCertAuthority,
                    request_deserializer=teleport_dot_trust_dot_v1_dot_trust__service__pb2.UpsertCertAuthorityRequest.FromString,
                    response_serializer=teleport_dot_legacy_dot_types_dot_types__pb2.CertAuthorityV2.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'teleport.trust.v1.TrustService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class TrustService(object):
    """TrustService provides methods to manage certificate authorities.
    """

    @staticmethod
    def GetCertAuthority(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/teleport.trust.v1.TrustService/GetCertAuthority',
            teleport_dot_trust_dot_v1_dot_trust__service__pb2.GetCertAuthorityRequest.SerializeToString,
            teleport_dot_legacy_dot_types_dot_types__pb2.CertAuthorityV2.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def GetCertAuthorities(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/teleport.trust.v1.TrustService/GetCertAuthorities',
            teleport_dot_trust_dot_v1_dot_trust__service__pb2.GetCertAuthoritiesRequest.SerializeToString,
            teleport_dot_trust_dot_v1_dot_trust__service__pb2.GetCertAuthoritiesResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def DeleteCertAuthority(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/teleport.trust.v1.TrustService/DeleteCertAuthority',
            teleport_dot_trust_dot_v1_dot_trust__service__pb2.DeleteCertAuthorityRequest.SerializeToString,
            google_dot_protobuf_dot_empty__pb2.Empty.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def UpsertCertAuthority(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/teleport.trust.v1.TrustService/UpsertCertAuthority',
            teleport_dot_trust_dot_v1_dot_trust__service__pb2.UpsertCertAuthorityRequest.SerializeToString,
            teleport_dot_legacy_dot_types_dot_types__pb2.CertAuthorityV2.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
