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

package clusters

import (
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/sshutils/sftp"
	api "github.com/gravitational/teleport/lib/teleterm/api/protogen/golang/v1"
	"github.com/gravitational/trace"
	"io"
	"os"
	"time"
)

func (c *Cluster) TransferFile(request *api.FileTransferRequest, server api.TerminalService_TransferFileServer) error {
	proxyClient, err := c.clusterClient.ConnectToProxy(server.Context())
	if err != nil {
		return err
	}
	defer proxyClient.Close()

	var config *sftp.Config
	var configErr error

	if request.GetDirection() == api.FileTransferDirection_FILE_TRANSFER_DIRECTION_DOWNLOAD {
		config, configErr = sftp.CreateDownloadConfig(request.GetSource(), request.GetDestination(), sftp.Options{})
	} else {
		config, configErr = sftp.CreateUploadConfig([]string{request.GetSource()}, request.GetDestination(), sftp.Options{})
	}

	if configErr != nil {
		return trace.Wrap(configErr)
	}

	config.ProgressWriter = func(fileInfo os.FileInfo) io.Writer {
		return newGrpcFileTransferProgress(fileInfo.Size(), server)
	}

	clusterServers, err := proxyClient.FindNodesByFilters(server.Context(), proto.ListResourcesRequest{
		Namespace: defaults.Namespace,
	})

	if err != nil {
		return trace.Wrap(err)
	}

	var foundServer types.Server
	for _, clusterServer := range clusterServers {
		if clusterServer.GetName() == request.GetServerId() {
			foundServer = clusterServer
			break
		}
	}

	if foundServer == nil {
		return trace.BadParameter("Requested server does not exist")
	}

	err = c.clusterClient.TransferFiles(server.Context(), request.GetLogin(), foundServer.GetHostname()+":0", config)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func newGrpcFileTransferProgress(fileSize int64, writer api.TerminalService_TransferFileServer) io.Writer {
	return &GrpcFileTransferProgress{
		transferFileServer: writer,
		sentSize:           0,
		fileSize:           fileSize,
	}
}

type GrpcFileTransferProgress struct {
	transferFileServer api.TerminalService_TransferFileServer
	sentSize           int64
	fileSize           int64
	lastSentPercentage uint32
	lastSentAt         time.Time
}

func (progressWriter *GrpcFileTransferProgress) Write(bytes []byte) (n int, err error) {
	bytesLength := len(bytes)
	progressWriter.sentSize += int64(bytesLength)
	percentage := uint32(progressWriter.sentSize * 100 / progressWriter.fileSize)

	if progressWriter.canSendProgress(percentage) {
		writeErr := progressWriter.transferFileServer.Send(&api.FileTransferProgress{Percentage: percentage})
		if writeErr != nil {
			return bytesLength, writeErr
		}
		progressWriter.lastSentAt = time.Now()
		progressWriter.lastSentPercentage = percentage
	}

	return bytesLength, nil
}

func (progressWriter *GrpcFileTransferProgress) canSendProgress(percentage uint32) bool {
	hasIntervalPassed := time.Since(progressWriter.lastSentAt).Milliseconds() > 100
	hasPercentageChanged := percentage != progressWriter.lastSentPercentage
	return hasIntervalPassed && hasPercentageChanged
}
