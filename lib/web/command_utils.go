/*

 Copyright 2023 Gravitational, Inc.

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

package web

import (
	"encoding/json"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gravitational/trace"
)

// WSConn is a gorilla/websocket minimal interface used by our web implementation.
// This interface exists to override the default websocket.Conn implementation,
// currently used by noopCloserWS to prevent WS being closed by wrapping stream.
type WSConn interface {
	Close() error

	LocalAddr() net.Addr
	RemoteAddr() net.Addr

	WriteControl(messageType int, data []byte, deadline time.Time) error
	WriteMessage(messageType int, data []byte) error
	ReadMessage() (messageType int, p []byte, err error)
	SetReadLimit(limit int64)
	SetReadDeadline(t time.Time) error
	SetPongHandler(h func(appData string) error)
}

// outEnvelope is an envelope used to wrap messages send back to the client connected over WS.
type outEnvelope struct {
	NodeID  string `json:"node_id"`
	Type    string `json:"type"`
	Payload []byte `json:"payload"`
}

// payloadWriter is a wrapper around io.Writer, which wraps the given bytes into
// outEnvelope and writes it to the underlying stream.
type payloadWriter struct {
	nodeID string
	// output name, can be stdout, stderr or teleport-error.
	outputName string
	// stream is the underlying stream.
	stream io.Writer
}

// Write writes the given bytes to the underlying stream.
func (p *payloadWriter) Write(b []byte) (n int, err error) {
	out := &outEnvelope{
		NodeID:  p.nodeID,
		Type:    p.outputName,
		Payload: b,
	}
	data, err := json.Marshal(out)
	if err != nil {
		return 0, trace.Wrap(err)
	}

	_, err = p.stream.Write(data)
	// return the size of the original message as a message send over stream
	// is larger due to json marshaling and envelope.
	return len(b), trace.Wrap(err)
}

func newPayloadWriter(nodeID, outputName string, stream io.Writer) *payloadWriter {
	return &payloadWriter{
		nodeID:     nodeID,
		outputName: outputName,
		stream:     stream,
	}
}

// noopCloserWS is a wrapper around websocket.Conn, which does nothing on Close().
// This struct is used to prevent WS being closed by wrapping stream.
// Currently, it is being used in Command web handler to prevent WS being closed
// by any underlying code as we want to keep the connection open until the command
// is executed on all nodes and a single failure should not close the connection.
type noopCloserWS struct {
	WSConn
}

// Close does nothing.
func (ws *noopCloserWS) Close() error {
	return nil
}

// safeThreadWSConn is a wrapper around websocket.Conn, which serializes
// read and write to a web socket connection. This is needed to prevent
// a race conditions and panics in gorilla/websocket.
// Details https://pkg.go.dev/github.com/gorilla/websocket#hdr-Concurrency
type safeThreadWSConn struct {
	// WSConn the underlying websocket connection.
	WSConn
	// rmtx is a mutex used to serialize reads.
	rmtx sync.Mutex
	// wmtx is a mutex used to serialize writes.
	wmtx sync.Mutex
}

func (s *safeThreadWSConn) WriteMessage(messageType int, data []byte) error {
	s.wmtx.Lock()
	defer s.wmtx.Unlock()
	return s.WSConn.WriteMessage(messageType, data)
}

func (s *safeThreadWSConn) ReadMessage() (messageType int, p []byte, err error) {
	s.rmtx.Lock()
	defer s.rmtx.Unlock()
	return s.WSConn.ReadMessage()
}

func (s *safeThreadWSConn) SetReadDeadline(t time.Time) error {
	s.rmtx.Lock()
	defer s.rmtx.Unlock()
	return s.WSConn.SetReadDeadline(t)
}
