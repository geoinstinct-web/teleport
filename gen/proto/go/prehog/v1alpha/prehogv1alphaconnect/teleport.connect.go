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

// Code generated by protoc-gen-connect-go. DO NOT EDIT.
//
// Source: prehog/v1alpha/teleport.proto

package prehogv1alphaconnect

import (
	connect "connectrpc.com/connect"
	context "context"
	errors "errors"
	v1alpha "github.com/gravitational/teleport/gen/proto/go/prehog/v1alpha"
	http "net/http"
	strings "strings"
)

// This is a compile-time assertion to ensure that this generated file and the connect package are
// compatible. If you get a compiler error that this constant is not defined, this code was
// generated with a version of connect newer than the one compiled into your binary. You can fix the
// problem by either regenerating this code with an older version of connect or updating the connect
// version compiled into your binary.
const _ = connect.IsAtLeastVersion1_13_0

const (
	// TeleportReportingServiceName is the fully-qualified name of the TeleportReportingService service.
	TeleportReportingServiceName = "prehog.v1alpha.TeleportReportingService"
)

// These constants are the fully-qualified names of the RPCs defined in this package. They're
// exposed at runtime as Spec.Procedure and as the final two segments of the HTTP route.
//
// Note that these are different from the fully-qualified method names used by
// google.golang.org/protobuf/reflect/protoreflect. To convert from these constants to
// reflection-formatted method names, remove the leading slash and convert the remaining slash to a
// period.
const (
	// TeleportReportingServiceSubmitEventProcedure is the fully-qualified name of the
	// TeleportReportingService's SubmitEvent RPC.
	TeleportReportingServiceSubmitEventProcedure = "/prehog.v1alpha.TeleportReportingService/SubmitEvent"
	// TeleportReportingServiceSubmitEventsProcedure is the fully-qualified name of the
	// TeleportReportingService's SubmitEvents RPC.
	TeleportReportingServiceSubmitEventsProcedure = "/prehog.v1alpha.TeleportReportingService/SubmitEvents"
	// TeleportReportingServiceHelloTeleportProcedure is the fully-qualified name of the
	// TeleportReportingService's HelloTeleport RPC.
	TeleportReportingServiceHelloTeleportProcedure = "/prehog.v1alpha.TeleportReportingService/HelloTeleport"
)

// These variables are the protoreflect.Descriptor objects for the RPCs defined in this package.
var (
	teleportReportingServiceServiceDescriptor             = v1alpha.File_prehog_v1alpha_teleport_proto.Services().ByName("TeleportReportingService")
	teleportReportingServiceSubmitEventMethodDescriptor   = teleportReportingServiceServiceDescriptor.Methods().ByName("SubmitEvent")
	teleportReportingServiceSubmitEventsMethodDescriptor  = teleportReportingServiceServiceDescriptor.Methods().ByName("SubmitEvents")
	teleportReportingServiceHelloTeleportMethodDescriptor = teleportReportingServiceServiceDescriptor.Methods().ByName("HelloTeleport")
)

// TeleportReportingServiceClient is a client for the prehog.v1alpha.TeleportReportingService
// service.
type TeleportReportingServiceClient interface {
	// equivalent to SubmitEvents with a single event, should be unused by now
	//
	// Deprecated: do not use.
	SubmitEvent(context.Context, *connect.Request[v1alpha.SubmitEventRequest]) (*connect.Response[v1alpha.SubmitEventResponse], error)
	// encodes and forwards usage events to the PostHog event database; each
	// event is annotated with some properties that depend on the identity of the
	// caller:
	//   - tp.account_id (UUID in string form, can be empty if missing from the
	//     license)
	//   - tp.license_name (should always be a UUID)
	//   - tp.license_authority (name of the authority that signed the license file
	//     used for authentication)
	//   - tp.is_cloud (boolean)
	SubmitEvents(context.Context, *connect.Request[v1alpha.SubmitEventsRequest]) (*connect.Response[v1alpha.SubmitEventsResponse], error)
	HelloTeleport(context.Context, *connect.Request[v1alpha.HelloTeleportRequest]) (*connect.Response[v1alpha.HelloTeleportResponse], error)
}

// NewTeleportReportingServiceClient constructs a client for the
// prehog.v1alpha.TeleportReportingService service. By default, it uses the Connect protocol with
// the binary Protobuf Codec, asks for gzipped responses, and sends uncompressed requests. To use
// the gRPC or gRPC-Web protocols, supply the connect.WithGRPC() or connect.WithGRPCWeb() options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewTeleportReportingServiceClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) TeleportReportingServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	return &teleportReportingServiceClient{
		submitEvent: connect.NewClient[v1alpha.SubmitEventRequest, v1alpha.SubmitEventResponse](
			httpClient,
			baseURL+TeleportReportingServiceSubmitEventProcedure,
			connect.WithSchema(teleportReportingServiceSubmitEventMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		submitEvents: connect.NewClient[v1alpha.SubmitEventsRequest, v1alpha.SubmitEventsResponse](
			httpClient,
			baseURL+TeleportReportingServiceSubmitEventsProcedure,
			connect.WithSchema(teleportReportingServiceSubmitEventsMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		helloTeleport: connect.NewClient[v1alpha.HelloTeleportRequest, v1alpha.HelloTeleportResponse](
			httpClient,
			baseURL+TeleportReportingServiceHelloTeleportProcedure,
			connect.WithSchema(teleportReportingServiceHelloTeleportMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
	}
}

// teleportReportingServiceClient implements TeleportReportingServiceClient.
type teleportReportingServiceClient struct {
	submitEvent   *connect.Client[v1alpha.SubmitEventRequest, v1alpha.SubmitEventResponse]
	submitEvents  *connect.Client[v1alpha.SubmitEventsRequest, v1alpha.SubmitEventsResponse]
	helloTeleport *connect.Client[v1alpha.HelloTeleportRequest, v1alpha.HelloTeleportResponse]
}

// SubmitEvent calls prehog.v1alpha.TeleportReportingService.SubmitEvent.
//
// Deprecated: do not use.
func (c *teleportReportingServiceClient) SubmitEvent(ctx context.Context, req *connect.Request[v1alpha.SubmitEventRequest]) (*connect.Response[v1alpha.SubmitEventResponse], error) {
	return c.submitEvent.CallUnary(ctx, req)
}

// SubmitEvents calls prehog.v1alpha.TeleportReportingService.SubmitEvents.
func (c *teleportReportingServiceClient) SubmitEvents(ctx context.Context, req *connect.Request[v1alpha.SubmitEventsRequest]) (*connect.Response[v1alpha.SubmitEventsResponse], error) {
	return c.submitEvents.CallUnary(ctx, req)
}

// HelloTeleport calls prehog.v1alpha.TeleportReportingService.HelloTeleport.
func (c *teleportReportingServiceClient) HelloTeleport(ctx context.Context, req *connect.Request[v1alpha.HelloTeleportRequest]) (*connect.Response[v1alpha.HelloTeleportResponse], error) {
	return c.helloTeleport.CallUnary(ctx, req)
}

// TeleportReportingServiceHandler is an implementation of the
// prehog.v1alpha.TeleportReportingService service.
type TeleportReportingServiceHandler interface {
	// equivalent to SubmitEvents with a single event, should be unused by now
	//
	// Deprecated: do not use.
	SubmitEvent(context.Context, *connect.Request[v1alpha.SubmitEventRequest]) (*connect.Response[v1alpha.SubmitEventResponse], error)
	// encodes and forwards usage events to the PostHog event database; each
	// event is annotated with some properties that depend on the identity of the
	// caller:
	//   - tp.account_id (UUID in string form, can be empty if missing from the
	//     license)
	//   - tp.license_name (should always be a UUID)
	//   - tp.license_authority (name of the authority that signed the license file
	//     used for authentication)
	//   - tp.is_cloud (boolean)
	SubmitEvents(context.Context, *connect.Request[v1alpha.SubmitEventsRequest]) (*connect.Response[v1alpha.SubmitEventsResponse], error)
	HelloTeleport(context.Context, *connect.Request[v1alpha.HelloTeleportRequest]) (*connect.Response[v1alpha.HelloTeleportResponse], error)
}

// NewTeleportReportingServiceHandler builds an HTTP handler from the service implementation. It
// returns the path on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewTeleportReportingServiceHandler(svc TeleportReportingServiceHandler, opts ...connect.HandlerOption) (string, http.Handler) {
	teleportReportingServiceSubmitEventHandler := connect.NewUnaryHandler(
		TeleportReportingServiceSubmitEventProcedure,
		svc.SubmitEvent,
		connect.WithSchema(teleportReportingServiceSubmitEventMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	teleportReportingServiceSubmitEventsHandler := connect.NewUnaryHandler(
		TeleportReportingServiceSubmitEventsProcedure,
		svc.SubmitEvents,
		connect.WithSchema(teleportReportingServiceSubmitEventsMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	teleportReportingServiceHelloTeleportHandler := connect.NewUnaryHandler(
		TeleportReportingServiceHelloTeleportProcedure,
		svc.HelloTeleport,
		connect.WithSchema(teleportReportingServiceHelloTeleportMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	return "/prehog.v1alpha.TeleportReportingService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case TeleportReportingServiceSubmitEventProcedure:
			teleportReportingServiceSubmitEventHandler.ServeHTTP(w, r)
		case TeleportReportingServiceSubmitEventsProcedure:
			teleportReportingServiceSubmitEventsHandler.ServeHTTP(w, r)
		case TeleportReportingServiceHelloTeleportProcedure:
			teleportReportingServiceHelloTeleportHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// UnimplementedTeleportReportingServiceHandler returns CodeUnimplemented from all methods.
type UnimplementedTeleportReportingServiceHandler struct{}

func (UnimplementedTeleportReportingServiceHandler) SubmitEvent(context.Context, *connect.Request[v1alpha.SubmitEventRequest]) (*connect.Response[v1alpha.SubmitEventResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("prehog.v1alpha.TeleportReportingService.SubmitEvent is not implemented"))
}

func (UnimplementedTeleportReportingServiceHandler) SubmitEvents(context.Context, *connect.Request[v1alpha.SubmitEventsRequest]) (*connect.Response[v1alpha.SubmitEventsResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("prehog.v1alpha.TeleportReportingService.SubmitEvents is not implemented"))
}

func (UnimplementedTeleportReportingServiceHandler) HelloTeleport(context.Context, *connect.Request[v1alpha.HelloTeleportRequest]) (*connect.Response[v1alpha.HelloTeleportResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("prehog.v1alpha.TeleportReportingService.HelloTeleport is not implemented"))
}
