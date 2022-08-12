/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Origin: https://github.com/kubernetes/kubernetes/blob/d5fdf3135e7c99e5f81e67986ae930f6a2ffb047/pkg/kubelet/cri/streaming/remotecommand/websocket.go

package proxy

import (
	"github.com/go-logr/logr"
	"github.com/gravitational/trace"
	"k8s.io/apiserver/pkg/endpoints/responsewriter"
	"k8s.io/apiserver/pkg/util/wsstream"
	"k8s.io/klog/v2"
)

const (
	stdinChannel = iota
	stdoutChannel
	stderrChannel
	errorChannel
	resizeChannel

	preV4BinaryWebsocketProtocol = wsstream.ChannelWebSocketProtocol
	preV4Base64WebsocketProtocol = wsstream.Base64ChannelWebSocketProtocol
	v4BinaryWebsocketProtocol    = "v4." + wsstream.ChannelWebSocketProtocol
	v4Base64WebsocketProtocol    = "v4." + wsstream.Base64ChannelWebSocketProtocol
)

func init() {
	// replaces default logger from Kubernetes klog package with one that does not log anything
	// this is required to suppress log messages from wssstream when forcing the connection close.
	// - use of closed network connection
	// - Error on socket receive: read tcp 192.168.1.236:3027->192.168.1.236:57842: use of closed network connection
	// both logs are emitted because `wssstream` does not properly close websocket connections. Instead of closing the server side
	// it closes the full connection.

	// golang init function order guarantees that the klog package was inited before this package.
	// TODO (tigrato): remove once wsstream package does not have broken behavior when closing websocket connections
	klog.SetLoggerWithOptions(logr.Discard())
}

// createChannels returns the standard channel types for a shell connection (STDIN 0, STDOUT 1, STDERR 2)
// along with the approximate duplex value. It also creates the error (3) and resize (4) channels.
func createChannels(req remoteCommandRequest) []wsstream.ChannelType {
	// open the requested channels, and always open the error channel
	channels := make([]wsstream.ChannelType, 5)
	channels[stdinChannel] = readChannel(req.stdin)
	channels[stdoutChannel] = writeChannel(req.stdout)
	channels[stderrChannel] = writeChannel(req.stderr)
	channels[errorChannel] = wsstream.WriteChannel
	channels[resizeChannel] = wsstream.ReadChannel
	return channels
}

// readChannel returns wsstream.ReadChannel if real is true, or wsstream.IgnoreChannel.
func readChannel(real bool) wsstream.ChannelType {
	if real {
		return wsstream.ReadChannel
	}
	return wsstream.IgnoreChannel
}

// writeChannel returns wsstream.WriteChannel if real is true, or wsstream.IgnoreChannel.
func writeChannel(real bool) wsstream.ChannelType {
	if real {
		return wsstream.WriteChannel
	}
	return wsstream.IgnoreChannel
}

// createWebSocketStreams returns a context containing the websocket connection and
// streams needed to perform an exec or an attach.
func createWebSocketStreams(req remoteCommandRequest) (*remoteCommandProxy, error) {
	channels := createChannels(req)
	conn := wsstream.NewConn(map[string]wsstream.ChannelProtocolConfig{
		"": {
			Binary:   true,
			Channels: channels,
		},
		preV4BinaryWebsocketProtocol: {
			Binary:   true,
			Channels: channels,
		},
		preV4Base64WebsocketProtocol: {
			Binary:   false,
			Channels: channels,
		},
		v4BinaryWebsocketProtocol: {
			Binary:   true,
			Channels: channels,
		},
		v4Base64WebsocketProtocol: {
			Binary:   false,
			Channels: channels,
		},
	})
	conn.SetIdleTimeout(IdleTimeout)
	negotiatedProtocol, streams, err := conn.Open(
		responsewriter.GetOriginal(req.httpResponseWriter),
		req.httpRequest,
	)
	if err != nil {
		return nil, trace.Wrap(err, "unable to upgrade websocket connection")
	}

	// Send an empty message to the lowest writable channel to notify the client the connection is established
	switch {
	case req.stdout:
		streams[stdoutChannel].Write([]byte{})
	case req.stderr:
		streams[stderrChannel].Write([]byte{})
	default:
		streams[errorChannel].Write([]byte{})
	}

	proxy := &remoteCommandProxy{
		conn:         conn,
		stdinStream:  streams[stdinChannel],
		stdoutStream: streams[stdoutChannel],
		stderrStream: streams[stderrChannel],
		tty:          req.tty,
		resizeStream: streams[resizeChannel],
	}

	// when stdin, stdout or stderr are not enabled, websocket creates a io.Pipe for them so they are not nil.
	// since we need to forward to another k8s server (teleport or real kubernetes API) we must disabled the readers
	// because, if defined, the SPDY executor will wait for read/write into the streams and will hang.
	if !req.stdin {
		proxy.stdinStream = nil
	}
	if !req.stdout {
		proxy.stdoutStream = nil
	}

	if !req.stderr {
		proxy.stderrStream = nil
	}

	switch negotiatedProtocol {
	case v4BinaryWebsocketProtocol, v4Base64WebsocketProtocol:
		proxy.writeStatus = v4WriteStatusFunc(streams[errorChannel])
	default:
		proxy.writeStatus = v1WriteStatusFunc(streams[errorChannel])
	}

	return proxy, nil
}
