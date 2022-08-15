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

package ssh

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/gravitational/teleport/api/observability/tracing"
	"github.com/gravitational/teleport/api/utils/sshutils"

	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	// TracingRequest is sent by clients to server to pass along tracing context.
	TracingRequest = "tracing@goteleport.com"

	// TracingChannel is a SSH channel used to indicate that servers support tracing.
	TracingChannel = "tracing"

	// instrumentationName is the name of this instrumentation package.
	instrumentationName = "otelssh"
)

// ContextFromRequest extracts any tracing data provided via an Envelope
// in the ssh.Request payload. If the payload contains an Envelope, then
// the context returned will have tracing data populated from the remote
// tracing context and the ssh.Request payload will be replaced with the
// original payload from the client.
func ContextFromRequest(req *ssh.Request, opts ...tracing.Option) context.Context {
	ctx := context.Background()

	var envelope Envelope
	if err := json.Unmarshal(req.Payload, &envelope); err != nil {
		return ctx
	}

	ctx = tracing.WithPropagationContext(ctx, envelope.PropagationContext, opts...)
	req.Payload = envelope.Payload

	return ctx
}

// ContextFromNewChannel extracts any tracing data provided via an Envelope
// in the ssh.NewChannel ExtraData. If the ExtraData contains an Envelope, then
// the context returned will have tracing data populated from the remote
// tracing context and the ssh.NewChannel wrapped in a TraceCh so that the
// original ExtraData from the client is exposed instead of the Envelope
// payload.
func ContextFromNewChannel(nch ssh.NewChannel, opts ...tracing.Option) (context.Context, ssh.NewChannel) {
	ch := NewTraceNewChannel(nch)
	ctx := tracing.WithPropagationContext(context.Background(), ch.Envelope.PropagationContext, opts...)

	return ctx, ch
}

// Dial starts a client connection to the given SSH server. It is a
// convenience function that connects to the given network address,
// initiates the SSH handshake, and then sets up a Client.  For access
// to incoming channels and requests, use net.Dial with NewClientConn
// instead.
func Dial(ctx context.Context, network, addr string, config *ssh.ClientConfig) (*Client, error) {
	dialer := net.Dialer{Timeout: config.Timeout}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := NewClientConn(ctx, conn, addr, config)
	if err != nil {
		return nil, err
	}
	return NewClient(c, chans, reqs), nil
}

// NewClientConn creates a new SSH client connection that is passed tracing context so that spans may be correlated
// properly over the ssh connection.
func NewClientConn(ctx context.Context, conn net.Conn, addr string, config *ssh.ClientConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	hp := &sshutils.HandshakePayload{
		TracingContext: tracing.PropagationContextFromContext(ctx),
	}

	if len(hp.TracingContext) > 0 {
		payloadJSON, err := json.Marshal(hp)
		if err == nil {
			payload := fmt.Sprintf("%s%s\x00", sshutils.ProxyHelloSignature, payloadJSON)
			_, err = conn.Write([]byte(payload))
			if err != nil {
				log.WithError(err).Warnf("Failed to pass along tracing context to proxy %v", addr)
			}
		}
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return nil, nil, nil, trace.Wrap(err)
	}

	return c, chans, reqs, nil
}

// NewClientConnWithDeadline establishes new client connection with specified deadline
func NewClientConnWithDeadline(ctx context.Context, conn net.Conn, addr string, config *ssh.ClientConfig) (*Client, error) {
	if config.Timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(config.Timeout)); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	c, chans, reqs, err := NewClientConn(ctx, conn, addr, config)
	if err != nil {
		return nil, err
	}
	if config.Timeout > 0 {
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return NewClient(c, chans, reqs), nil
}

// peerAttr returns attributes about the peer address.
func peerAttr(addr net.Addr) []attribute.KeyValue {
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}

	if host == "" {
		host = "127.0.0.1"
	}

	return []attribute.KeyValue{
		semconv.NetPeerIPKey.String(host),
		semconv.NetPeerPortKey.String(port),
	}
}

// Envelope wraps the payload of all ssh messages with
// tracing context. Any servers that reply to a TracingChannel
// will attempt to parse the Envelope for all received requests and
// ensure that the original payload is provided to the handlers.
type Envelope struct {
	PropagationContext tracing.PropagationContext
	Payload            []byte
}

// createEnvelope wraps the provided payload with a tracing envelope
// that is used to propagate trace context .
func createEnvelope(ctx context.Context, propagator propagation.TextMapPropagator, payload []byte) Envelope {
	envelope := Envelope{
		Payload: payload,
	}

	span := oteltrace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return envelope
	}

	traceCtx := tracing.PropagationContextFromContext(ctx, tracing.WithTextMapPropagator(propagator))
	if len(traceCtx) == 0 {
		return envelope
	}

	envelope.PropagationContext = traceCtx

	return envelope
}

// wrapPayload wraps the provided payload within an envelope if tracing is
// enabled and there is any tracing information to propagate. Otherwise, the
// original payload is returned
func wrapPayload(ctx context.Context, supported tracingCapability, propagator propagation.TextMapPropagator, payload []byte) []byte {
	if supported != tracingSupported {
		return payload
	}

	envelope := createEnvelope(ctx, propagator, payload)
	if len(envelope.PropagationContext) == 0 {
		return payload
	}

	wrappedPayload, err := json.Marshal(envelope)
	if err == nil {
		return wrappedPayload
	}

	return payload
}
