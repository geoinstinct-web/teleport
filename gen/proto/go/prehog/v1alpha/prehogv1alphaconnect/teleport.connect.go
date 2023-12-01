//
// Teleport
// Copyright (C) 2023  Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Code generated by protoc-gen-connect-go. DO NOT EDIT.
//
// Source: prehog/v1alpha/teleport.proto

package prehogv1alphaconnect

import (
	context "context"
	errors "errors"
	connect_go "github.com/bufbuild/connect-go"
	v1alpha "github.com/gravitational/teleport/gen/proto/go/prehog/v1alpha"
	http "net/http"
	strings "strings"
)

// This is a compile-time assertion to ensure that this generated file and the connect package are
// compatible. If you get a compiler error that this constant is not defined, this code was
// generated with a version of connect newer than the one compiled into your binary. You can fix the
// problem by either regenerating this code with an older version of connect or updating the connect
// version compiled into your binary.
const _ = connect_go.IsAtLeastVersion0_1_0

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

// TeleportReportingServiceClient is a client for the prehog.v1alpha.TeleportReportingService
// service.
type TeleportReportingServiceClient interface {
	// equivalent to SubmitEvents with a single event, should be unused by now
	//
	// Deprecated: do not use.
	SubmitEvent(context.Context, *connect_go.Request[v1alpha.SubmitEventRequest]) (*connect_go.Response[v1alpha.SubmitEventResponse], error)
	// encodes and forwards usage events to the PostHog event database; each
	// event is annotated with some properties that depend on the identity of the
	// caller:
	//   - tp.account_id (UUID in string form, can be empty if missing from the
	//     license)
	//   - tp.license_name (should always be a UUID)
	//   - tp.license_authority (name of the authority that signed the license file
	//     used for authentication)
	//   - tp.is_cloud (boolean)
	SubmitEvents(context.Context, *connect_go.Request[v1alpha.SubmitEventsRequest]) (*connect_go.Response[v1alpha.SubmitEventsResponse], error)
	HelloTeleport(context.Context, *connect_go.Request[v1alpha.HelloTeleportRequest]) (*connect_go.Response[v1alpha.HelloTeleportResponse], error)
}

// NewTeleportReportingServiceClient constructs a client for the
// prehog.v1alpha.TeleportReportingService service. By default, it uses the Connect protocol with
// the binary Protobuf Codec, asks for gzipped responses, and sends uncompressed requests. To use
// the gRPC or gRPC-Web protocols, supply the connect.WithGRPC() or connect.WithGRPCWeb() options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewTeleportReportingServiceClient(httpClient connect_go.HTTPClient, baseURL string, opts ...connect_go.ClientOption) TeleportReportingServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	return &teleportReportingServiceClient{
		submitEvent: connect_go.NewClient[v1alpha.SubmitEventRequest, v1alpha.SubmitEventResponse](
			httpClient,
			baseURL+TeleportReportingServiceSubmitEventProcedure,
			opts...,
		),
		submitEvents: connect_go.NewClient[v1alpha.SubmitEventsRequest, v1alpha.SubmitEventsResponse](
			httpClient,
			baseURL+TeleportReportingServiceSubmitEventsProcedure,
			opts...,
		),
		helloTeleport: connect_go.NewClient[v1alpha.HelloTeleportRequest, v1alpha.HelloTeleportResponse](
			httpClient,
			baseURL+TeleportReportingServiceHelloTeleportProcedure,
			opts...,
		),
	}
}

// teleportReportingServiceClient implements TeleportReportingServiceClient.
type teleportReportingServiceClient struct {
	submitEvent   *connect_go.Client[v1alpha.SubmitEventRequest, v1alpha.SubmitEventResponse]
	submitEvents  *connect_go.Client[v1alpha.SubmitEventsRequest, v1alpha.SubmitEventsResponse]
	helloTeleport *connect_go.Client[v1alpha.HelloTeleportRequest, v1alpha.HelloTeleportResponse]
}

// SubmitEvent calls prehog.v1alpha.TeleportReportingService.SubmitEvent.
//
// Deprecated: do not use.
func (c *teleportReportingServiceClient) SubmitEvent(ctx context.Context, req *connect_go.Request[v1alpha.SubmitEventRequest]) (*connect_go.Response[v1alpha.SubmitEventResponse], error) {
	return c.submitEvent.CallUnary(ctx, req)
}

// SubmitEvents calls prehog.v1alpha.TeleportReportingService.SubmitEvents.
func (c *teleportReportingServiceClient) SubmitEvents(ctx context.Context, req *connect_go.Request[v1alpha.SubmitEventsRequest]) (*connect_go.Response[v1alpha.SubmitEventsResponse], error) {
	return c.submitEvents.CallUnary(ctx, req)
}

// HelloTeleport calls prehog.v1alpha.TeleportReportingService.HelloTeleport.
func (c *teleportReportingServiceClient) HelloTeleport(ctx context.Context, req *connect_go.Request[v1alpha.HelloTeleportRequest]) (*connect_go.Response[v1alpha.HelloTeleportResponse], error) {
	return c.helloTeleport.CallUnary(ctx, req)
}

// TeleportReportingServiceHandler is an implementation of the
// prehog.v1alpha.TeleportReportingService service.
type TeleportReportingServiceHandler interface {
	// equivalent to SubmitEvents with a single event, should be unused by now
	//
	// Deprecated: do not use.
	SubmitEvent(context.Context, *connect_go.Request[v1alpha.SubmitEventRequest]) (*connect_go.Response[v1alpha.SubmitEventResponse], error)
	// encodes and forwards usage events to the PostHog event database; each
	// event is annotated with some properties that depend on the identity of the
	// caller:
	//   - tp.account_id (UUID in string form, can be empty if missing from the
	//     license)
	//   - tp.license_name (should always be a UUID)
	//   - tp.license_authority (name of the authority that signed the license file
	//     used for authentication)
	//   - tp.is_cloud (boolean)
	SubmitEvents(context.Context, *connect_go.Request[v1alpha.SubmitEventsRequest]) (*connect_go.Response[v1alpha.SubmitEventsResponse], error)
	HelloTeleport(context.Context, *connect_go.Request[v1alpha.HelloTeleportRequest]) (*connect_go.Response[v1alpha.HelloTeleportResponse], error)
}

// NewTeleportReportingServiceHandler builds an HTTP handler from the service implementation. It
// returns the path on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewTeleportReportingServiceHandler(svc TeleportReportingServiceHandler, opts ...connect_go.HandlerOption) (string, http.Handler) {
	teleportReportingServiceSubmitEventHandler := connect_go.NewUnaryHandler(
		TeleportReportingServiceSubmitEventProcedure,
		svc.SubmitEvent,
		opts...,
	)
	teleportReportingServiceSubmitEventsHandler := connect_go.NewUnaryHandler(
		TeleportReportingServiceSubmitEventsProcedure,
		svc.SubmitEvents,
		opts...,
	)
	teleportReportingServiceHelloTeleportHandler := connect_go.NewUnaryHandler(
		TeleportReportingServiceHelloTeleportProcedure,
		svc.HelloTeleport,
		opts...,
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

func (UnimplementedTeleportReportingServiceHandler) SubmitEvent(context.Context, *connect_go.Request[v1alpha.SubmitEventRequest]) (*connect_go.Response[v1alpha.SubmitEventResponse], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("prehog.v1alpha.TeleportReportingService.SubmitEvent is not implemented"))
}

func (UnimplementedTeleportReportingServiceHandler) SubmitEvents(context.Context, *connect_go.Request[v1alpha.SubmitEventsRequest]) (*connect_go.Response[v1alpha.SubmitEventsResponse], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("prehog.v1alpha.TeleportReportingService.SubmitEvents is not implemented"))
}

func (UnimplementedTeleportReportingServiceHandler) HelloTeleport(context.Context, *connect_go.Request[v1alpha.HelloTeleportRequest]) (*connect_go.Response[v1alpha.HelloTeleportResponse], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("prehog.v1alpha.TeleportReportingService.HelloTeleport is not implemented"))
}
