// package: prehog.v1alpha
// file: teleport/lib/prehog/v1alpha/teleport.proto

/* tslint:disable */
/* eslint-disable */

import * as grpc from "grpc";
import * as teleport_lib_prehog_v1alpha_teleport_pb from "../../../../teleport/lib/prehog/v1alpha/teleport_pb";
import * as google_protobuf_timestamp_pb from "google-protobuf/google/protobuf/timestamp_pb";

interface ITeleportReportingServiceService extends grpc.ServiceDefinition<grpc.UntypedServiceImplementation> {
    submitEvent: ITeleportReportingServiceService_ISubmitEvent;
    helloTeleport: ITeleportReportingServiceService_IHelloTeleport;
}

interface ITeleportReportingServiceService_ISubmitEvent extends grpc.MethodDefinition<teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventRequest, teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventResponse> {
    path: "/prehog.v1alpha.TeleportReportingService/SubmitEvent";
    requestStream: false;
    responseStream: false;
    requestSerialize: grpc.serialize<teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventRequest>;
    requestDeserialize: grpc.deserialize<teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventRequest>;
    responseSerialize: grpc.serialize<teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventResponse>;
    responseDeserialize: grpc.deserialize<teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventResponse>;
}
interface ITeleportReportingServiceService_IHelloTeleport extends grpc.MethodDefinition<teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportRequest, teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportResponse> {
    path: "/prehog.v1alpha.TeleportReportingService/HelloTeleport";
    requestStream: false;
    responseStream: false;
    requestSerialize: grpc.serialize<teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportRequest>;
    requestDeserialize: grpc.deserialize<teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportRequest>;
    responseSerialize: grpc.serialize<teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportResponse>;
    responseDeserialize: grpc.deserialize<teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportResponse>;
}

export const TeleportReportingServiceService: ITeleportReportingServiceService;

export interface ITeleportReportingServiceServer {
    submitEvent: grpc.handleUnaryCall<teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventRequest, teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventResponse>;
    helloTeleport: grpc.handleUnaryCall<teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportRequest, teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportResponse>;
}

export interface ITeleportReportingServiceClient {
    submitEvent(request: teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventRequest, callback: (error: grpc.ServiceError | null, response: teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventResponse) => void): grpc.ClientUnaryCall;
    submitEvent(request: teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventRequest, metadata: grpc.Metadata, callback: (error: grpc.ServiceError | null, response: teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventResponse) => void): grpc.ClientUnaryCall;
    submitEvent(request: teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventRequest, metadata: grpc.Metadata, options: Partial<grpc.CallOptions>, callback: (error: grpc.ServiceError | null, response: teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventResponse) => void): grpc.ClientUnaryCall;
    helloTeleport(request: teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportRequest, callback: (error: grpc.ServiceError | null, response: teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportResponse) => void): grpc.ClientUnaryCall;
    helloTeleport(request: teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportRequest, metadata: grpc.Metadata, callback: (error: grpc.ServiceError | null, response: teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportResponse) => void): grpc.ClientUnaryCall;
    helloTeleport(request: teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportRequest, metadata: grpc.Metadata, options: Partial<grpc.CallOptions>, callback: (error: grpc.ServiceError | null, response: teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportResponse) => void): grpc.ClientUnaryCall;
}

export class TeleportReportingServiceClient extends grpc.Client implements ITeleportReportingServiceClient {
    constructor(address: string, credentials: grpc.ChannelCredentials, options?: object);
    public submitEvent(request: teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventRequest, callback: (error: grpc.ServiceError | null, response: teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventResponse) => void): grpc.ClientUnaryCall;
    public submitEvent(request: teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventRequest, metadata: grpc.Metadata, callback: (error: grpc.ServiceError | null, response: teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventResponse) => void): grpc.ClientUnaryCall;
    public submitEvent(request: teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventRequest, metadata: grpc.Metadata, options: Partial<grpc.CallOptions>, callback: (error: grpc.ServiceError | null, response: teleport_lib_prehog_v1alpha_teleport_pb.SubmitEventResponse) => void): grpc.ClientUnaryCall;
    public helloTeleport(request: teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportRequest, callback: (error: grpc.ServiceError | null, response: teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportResponse) => void): grpc.ClientUnaryCall;
    public helloTeleport(request: teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportRequest, metadata: grpc.Metadata, callback: (error: grpc.ServiceError | null, response: teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportResponse) => void): grpc.ClientUnaryCall;
    public helloTeleport(request: teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportRequest, metadata: grpc.Metadata, options: Partial<grpc.CallOptions>, callback: (error: grpc.ServiceError | null, response: teleport_lib_prehog_v1alpha_teleport_pb.HelloTeleportResponse) => void): grpc.ClientUnaryCall;
}
