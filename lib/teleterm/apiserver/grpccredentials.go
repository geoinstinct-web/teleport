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

package apiserver

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"

	"github.com/gravitational/teleport/api/utils/keys"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	// tshdCertFileName is the file name of the cert created by the tshd process. The Electron app
	// expects it to exist under this name in the certs dir passed through a flag to tshd.
	tshdCertFileName = "tshd.crt"
	// rendererCertFileName is the file name of the cert created by the renderer process of the
	// Electron app.
	rendererCertFileName = "renderer.crt"
)

// createServerCredentials creates mTLS credentials for a gRPC server. The client cert file is read
// only on an incoming connection, not upfront.
func createServerCredentials(serverKeyPair tls.Certificate, clientCertPath string) (grpc.ServerOption, error) {
	config := &tls.Config{
		GetConfigForClient: func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
			clientCert, err := os.ReadFile(clientCertPath)
			if err != nil {
				return nil, trace.Wrap(err, "failed to read the client cert file")
			}

			certPool := x509.NewCertPool()
			if !certPool.AppendCertsFromPEM(clientCert) {
				return nil, trace.BadParameter("failed to add the client cert to the pool")
			}

			return &tls.Config{
				ClientAuth:   tls.RequireAndVerifyClientCert,
				Certificates: []tls.Certificate{serverKeyPair},
				ClientCAs:    certPool,
			}, nil
		},
	}

	return grpc.Creds(credentials.NewTLS(config)), nil
}

func generateAndSaveCert(path string) (tls.Certificate, error) {
	// File is first saved using under tempPath and then renamed to fullPath.
	// This prevents other processes from reading a half written file.
	fullPath := filepath.Join(path)
	tempPath := fullPath + ".tmp"

	cert, err := utils.GenerateSelfSignedCert([]string{"localhost"})
	if err != nil {
		return tls.Certificate{}, trace.Wrap(err, "failed to generate the certificate")
	}

	err = os.WriteFile(tempPath, cert.Cert, 0600)
	if err != nil {
		return tls.Certificate{}, trace.Wrap(err)
	}

	err = os.Rename(tempPath, fullPath)
	if err != nil {
		return tls.Certificate{}, trace.Wrap(err)
	}

	certificate, err := keys.X509KeyPair(cert.Cert, cert.PrivateKey)
	if err != nil {
		return tls.Certificate{}, trace.Wrap(err)
	}

	return certificate, nil
}
