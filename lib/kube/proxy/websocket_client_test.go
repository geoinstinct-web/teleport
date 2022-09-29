/*
Copyright 2022 Gravitational, Inc.

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

package proxy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	gwebsocket "github.com/gorilla/websocket"
	testingkubemock "github.com/gravitational/teleport/lib/kube/proxy/testing/kube_server"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	clientremotecommand "k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/transport"
	"k8s.io/utils/strings/slices"
)

var (
	supportedProtocols = []string{v4BinaryWebsocketProtocol, preV4BinaryWebsocketProtocol}
	separator          = "\r\n"
)

const (
	// These constants match:
	// - pkg/kubelet/cri/streaming/remotecommand/websocket.go
	// - staging/src/k8s.io/apiserver/pkg/util/wsstream/conn.go

	streamStdin = iota
	streamStdout
	streamStderr
	streamErr
	streamResize
)

// wsStreamExecutor handles transporting standard shell streams over a websocket connection.
type wsStreamExecutor struct {
	config    *rest.Config
	tlsConfig *tls.Config
	method    string
	url       string
	protocols []string
	cacheBuff *bytes.Buffer
	conn      *gwebsocket.Conn
	mu        *sync.Mutex
}

// newWebSocketExecutor allows running exec commands via Websocket protocol.
// The existing code exists for tests purpose where the final endpoint is a fictional Kubernetes API.
// The code in question should never be used outside testing.
func newWebSocketExecutor(config *rest.Config, method string, u *url.URL) (clientremotecommand.Executor, error) {
	return &wsStreamExecutor{
		config:    config,
		method:    method,
		url:       u.String(),
		protocols: supportedProtocols,
		cacheBuff: bytes.NewBuffer(nil),
		mu:        &sync.Mutex{},
	}, nil
}

func (e *wsStreamExecutor) Stream(options clientremotecommand.StreamOptions) error {
	if options.TerminalSizeQueue != nil || options.Tty {
		return fmt.Errorf("client does not support resizes or Tty shells")
	}
	err := e.connectViaWebsocket()
	if err != nil {
		return err
	}
	conn := e.conn
	// stream will block until execution is finished.
	defer conn.Close()
	streamingProto := conn.Subprotocol()
	if !slices.Contains(supportedProtocols, streamingProto) {
		return fmt.Errorf("unsupported streaming protocol: %q", streamingProto)
	}
	// hang until server closes streams.
	return e.stream(conn, options)
}

// stream copies the contents from stdin into the connection and respective stdout and stderr
// from the connection into the desired buffers.
// This method will block until the server closes the connection.
// Unfortunately, the K8S Websocket protocol does not support half-closed streams,
// i.e. indicating that nothing else will be sent via stdin. If the server
// reads the stdin stream until io.EOF is received, it will block on reading.
// This issue is being tracked by https://github.com/kubernetes/kubernetes/issues/89899
// To prevent this issue, and uniquely for testing, this client will send
// an exit keyword specified by testingkubemock.CloseStreamMessage. Our mock server is expecting that
// keyword and will return once it's received.

// The protocol docs are at https://pkg.go.dev/k8s.io/apiserver/pkg/util/wsstream#pkg-constants
// Bellow we have a copy of the implemented binary protocol specification.

// The Websocket subprotocol "channel.k8s.io" prepends each binary message with a byte indicating
// the channel number (zero indexed) the message was sent on. Messages in both directions should
// prefix their messages with this channel byte. When used for remote execution, the channel numbers
// are by convention defined to match the POSIX file-descriptors assigned to STDIN, STDOUT, and STDERR
// (0, 1, and 2). No other conversion is performed on the raw subprotocol - writes are sent as they
// are received by the server.
//
// Example client session:
//
//	CONNECT http://server.com with subprotocol "channel.k8s.io"
//	WRITE []byte{0, 102, 111, 111, 10} # send "foo\n" on channel 0 (STDIN)
//	READ  []byte{1, 10}                # receive "\n" on channel 1 (STDOUT)
//	CLOSE
func (e *wsStreamExecutor) stream(conn *gwebsocket.Conn, options clientremotecommand.StreamOptions) error {
	errChan := make(chan error, 3)
	wg := sync.WaitGroup{}
	if options.Stdin != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 1025)
			for {
				n, err := options.Stdin.Read(buf)
				if errors.Is(err, io.EOF) && n == 0 {
					// send the close payload indicating that there is nothing else to read from stdin.
					if err := conn.WriteMessage(
						gwebsocket.BinaryMessage,
						append([]byte{streamStdin}, []byte(testingkubemock.CloseStreamMessage)...),
					); err != nil {
						errChan <- err
					}
					return
				} else if err != nil && n == 0 {
					errChan <- err
					return
				}
				if n == 0 {
					continue
				}
				e.mu.Lock()
				// we must cache the last sdtdin line because the server will resend it together
				// with stdout/stderr streams.
				e.cacheBuff.Write([]byte{streamStdin})
				e.cacheBuff.Write(buf[0:n])

				if err := conn.WriteMessage(gwebsocket.BinaryMessage, e.cacheBuff.Bytes()); err != nil {
					e.mu.Unlock()
					errChan <- err
					return
				}
				// append the separator that the server will send
				e.cacheBuff.Write([]byte(separator))
				e.mu.Unlock()
			}
		}()
	}

	// If the client is not using stdout or stderr, we must listen for streamErr.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			_, buf, err := conn.ReadMessage()

			if len(buf) > 1 {
				var w io.Writer
				// We let the server send the stream number and we choose the desired stream accordingly.
				// If the stream is nil, we ignore the payload and continue.
				switch buf[0] {
				case streamStdout:
					w = options.Stdout
				case streamStderr:
					w = options.Stderr
				case streamErr:
					_, err := parseError(buf[1:])
					errChan <- err
					// Once we receive an error from streamErr, we must stop processing.
					// The server also stops the execution and closes the connection.
					return
				case streamResize:
					errChan <- fmt.Errorf("stream resize is not supported")
					return
				}
				if w == nil {
					continue
				}
				e.mu.Lock()
				// the stdout and stderr streams receive the last stdin input and we must trim it.
				s := strings.Replace(string(buf[1:]), e.cacheBuff.String(), "", -1)
				e.mu.Unlock()
				_, err = w.Write([]byte(s))
				if err != nil {
					errChan <- err
					return
				}
			}

			if err != nil {
				// check the connection was properly closed by server, and if true ignore the error.
				var websocketErr *gwebsocket.CloseError
				if errors.As(err, &websocketErr) && websocketErr.Code == gwebsocket.CloseNormalClosure {
					err = nil
				}
				errChan <- err
				return
			}
			e.mu.Lock()
			e.cacheBuff.Reset()
			e.mu.Unlock()

		}
	}()

	wg.Wait()
	close(errChan)
	err := <-errChan
	return err

}

func (e *wsStreamExecutor) connectViaWebsocket() error {
	transportCfg, err := e.config.TransportConfig()
	if err != nil {
		return err
	}
	e.tlsConfig, err = transport.TLSConfigFor(transportCfg)
	if err != nil {
		return err
	}

	wrapper, err := transport.HTTPWrappersForConfig(transportCfg, e)
	if err != nil {
		return err
	}

	err = dial(wrapper, e.method, e.url)
	if err != nil {
		return err
	}

	return nil
}

// dial connects to the server via websocket and sends the supported protocols.
func dial(rt http.RoundTripper, method string, url string) error {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return err
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		if !errors.Is(err, gwebsocket.ErrBadHandshake) {
			return err
		}
		// resp.Body contains (a part of) the response when err == gwebsocket.ErrBadHandshake
		responseErrorBytes, bodyErr := io.ReadAll(resp.Body)
		if bodyErr != nil {
			return err
		}
		// drain response body

		_ = resp.Body.Close()
		isStatusErr, err := parseError(responseErrorBytes)
		if isStatusErr {
			return err
		}
		return fmt.Errorf("unable to upgrade connection: %w", err)
	}
	// if request is successful, ignore body payload and close.
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	return nil
}

// RoundTrip connects to the remote websocket using TLS configuration.
func (e *wsStreamExecutor) RoundTrip(request *http.Request) (retResp *http.Response, retErr error) {
	dialer := gwebsocket.Dialer{
		TLSClientConfig: e.tlsConfig,
		Subprotocols:    supportedProtocols,
	}
	switch request.URL.Scheme {
	case "https":
		request.URL.Scheme = "wss"
	case "http":
		request.URL.Scheme = "ws"
	}
	wsConn, resp, err := dialer.DialContext(request.Context(), request.URL.String(), request.Header)
	e.conn = wsConn

	return resp, err
}

// parseError parses the error received from Kube API and checks if the returned error is *metav1.Status
func parseError(errorBytes []byte) (bool, error) {
	if obj, _, err := statusCodecs.UniversalDecoder().Decode(errorBytes, nil, &metav1.Status{}); err == nil {
		if status, ok := obj.(*metav1.Status); ok && status.Status == metav1.StatusSuccess {
			return true, nil
		} else if ok {
			return true, &apierrors.StatusError{ErrStatus: *status}
		}
		return false, fmt.Errorf("unexpected error type: %T", obj)
	}
	return false, fmt.Errorf("%s", bytes.TrimSpace(errorBytes))
}
