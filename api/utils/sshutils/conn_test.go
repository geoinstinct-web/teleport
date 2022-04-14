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

package sshutils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type server struct {
	listener net.Listener
	config   *ssh.ServerConfig
	handler  func(*ssh.ServerConn)
	t        *testing.T
	mu       sync.RWMutex
	closed   bool

	cSigner ssh.Signer
	hSigner ssh.Signer
}

func (s *server) Run() {
	for {
		conn, err := s.listener.Accept()

		s.mu.RLock()
		if s.closed {
			s.mu.RUnlock()
			return
		}
		s.mu.RUnlock()

		assert.NoError(s.t, err)

		go func() {
			defer conn.Close()
			sconn, _, _, err := ssh.NewServerConn(conn, s.config)
			assert.NoError(s.t, err)
			s.handler(sconn)
		}()
	}
}

func (s *server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return s.listener.Close()
}

func generateSigner(t *testing.T) ssh.Signer {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(private),
	}

	privatePEM := pem.EncodeToMemory(block)
	signer, err := ssh.ParsePrivateKey(privatePEM)
	require.NoError(t, err)

	return signer
}

func (s *server) GetClient() (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request) {
	conn, err := net.Dial("tcp", s.listener.Addr().String())
	require.NoError(s.t, err)

	sconn, nc, r, err := ssh.NewClientConn(conn, "", &ssh.ClientConfig{
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(s.cSigner)},
		HostKeyCallback: ssh.FixedHostKey(s.hSigner.PublicKey()),
	})
	require.NoError(s.t, err)

	return sconn, nc, r
}

func newServer(t *testing.T, handler func(*ssh.ServerConn)) *server {
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	cSigner := generateSigner(t)
	hSigner := generateSigner(t)

	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	config.AddHostKey(hSigner)

	return &server{
		listener: listener,
		config:   config,
		handler:  handler,
		t:        t,
		cSigner:  cSigner,
		hSigner:  hSigner,
	}
}

// TestTransportError ensures ConnectProxyTransport does not block forever
// when an error occurs while opening the transport channel.
func TestTransportError(t *testing.T) {
	errC := make(chan error)

	server := newServer(t, func(sconn *ssh.ServerConn) {
		_, _, err := ConnectProxyTransport(sconn, &DialReq{
			Address: "test", ServerID: "test",
		}, false)
		errC <- err
	})

	go server.Run()
	t.Cleanup(func() { require.NoError(t, server.Stop()) })

	sconn1, nc, _ := server.GetClient()
	t.Cleanup(func() { require.Error(t, sconn1.Close()) })
	channel := <-nc
	require.Equal(t, channel.ChannelType(), constants.ChanTransport)

	sconn1.Close()
	err := timeoutErrC(t, errC, time.Second*5)
	require.Error(t, err)

	sconn2, nc, _ := server.GetClient()
	t.Cleanup(func() { require.NoError(t, sconn2.Close()) })
	channel = <-nc
	require.Equal(t, channel.ChannelType(), constants.ChanTransport)

	err = channel.Reject(ssh.ConnectionFailed, "test reject")
	require.NoError(t, err)

	err = timeoutErrC(t, errC, time.Second*5)
	require.Error(t, err)
}

func timeoutErrC(t *testing.T, errC <-chan error, d time.Duration) error {
	timeout := time.NewTimer(d)
	select {
	case err := <-errC:
		return err
	case <-timeout.C:
		require.FailNow(t, "failed to receive on err channel in time")
	}

	return nil
}
