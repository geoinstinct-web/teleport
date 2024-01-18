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

package interceptors

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/gravitational/teleport/api/client/proto"
)

// service is used to implement EchoServer
type service struct {
	proto.UnimplementedAuthServiceServer
}

func (s *service) Ping(ctx context.Context, req *proto.PingRequest) (*proto.PingResponse, error) {
	return nil, trace.NotFound("not found")
}

func (s *service) AddMFADevice(stream proto.AuthService_AddMFADeviceServer) error {
	return trace.AlreadyExists("already exists")
}

// TestGRPCErrorWrapping tests the error wrapping capability of the client
// and server unary and stream interceptors
func TestGRPCErrorWrapping(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	server := grpc.NewServer(
		grpc.ChainUnaryInterceptor(GRPCServerUnaryErrorInterceptor),
		grpc.ChainStreamInterceptor(GRPCServerStreamErrorInterceptor),
	)
	proto.RegisterAuthServiceServer(server, &service{})
	go func() {
		server.Serve(listener)
	}()
	defer server.Stop()

	conn, err := grpc.Dial(
		listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(GRPCClientUnaryErrorInterceptor),
		grpc.WithChainStreamInterceptor(GRPCClientStreamErrorInterceptor),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := proto.NewAuthServiceClient(conn)

	t.Run("unary interceptor", func(t *testing.T) {
		resp, err := client.Ping(context.Background(), &proto.PingRequest{})
		assert.Nil(t, resp, "resp is non-nil")
		assert.True(t, trace.IsNotFound(err), "trace.IsNotFound failed: err=%v (%T)", err, trace.Unwrap(err))
		assert.Equal(t, "not found", err.Error())
		_, ok := err.(*trace.TraceErr)
		assert.False(t, ok, "client error should not include traces originating in the middleware")
		var remoteErr *interceptors.RemoteError
		assert.ErrorAs(t, err, &remoteErr, "Remote error is not marked as an interceptors.RemoteError")
	})

	t.Run("stream interceptor", func(t *testing.T) {
		stream, err := client.AddMFADevice(context.Background())
		require.NoError(t, err)

		sendErr := stream.Send(&proto.AddMFADeviceRequest{})

		// io.EOF means the server closed the stream, which can
		// happen depending in timing. In either case, it is
		// still safe to recv from the stream and check for
		// the already exists error.
		if sendErr != nil && !errors.Is(sendErr, io.EOF) {
			t.Fatalf("Unexpected error: %v", sendErr)
		}

		_, err = stream.Recv()
		assert.True(t, trace.IsAlreadyExists(err), "trace.IsAlreadyExists failed: err=%v (%T)", err, trace.Unwrap(err))
		assert.Equal(t, "already exists", err.Error())
		_, ok := err.(*trace.TraceErr)
		assert.False(t, ok, "client error should not include traces originating in the middleware")
		assert.True(t, trace.IsAlreadyExists(err), "trace.IsAlreadyExists failed: err=%v (%T)", err, trace.Unwrap(err))
		var remoteErr *interceptors.RemoteError
		assert.ErrorAs(t, err, &remoteErr, "Remote error is not marked as an interceptors.RemoteError")
	})
}
