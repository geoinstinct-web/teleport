/**
 * Copyright 2023 Gravitational, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { useEffect, useState, useCallback } from 'react';
import { useFileTransferContext } from 'shared/components/FileTransfer';

import Tty from 'teleport/lib/term/tty';
import { EventType } from 'teleport/lib/term/enums';
import { Session } from 'teleport/services/session';
import { DocumentSsh } from 'teleport/Console/stores';

import { useConsoleContext } from '../consoleContextProvider';

import { getHttpFileTransferHandlers } from './httpFileTransferHandlers';
import useGetScpUrl from './useGetScpUrl';

export type FileTransferRequest = {
  sid: string;
  requestID: string;
  requester: string;
  approvers: string[];
  location: string;
  filename?: string;
  download: boolean;
};

export const isOwnRequest = (
  request: FileTransferRequest,
  currentUser: string
) => {
  return request.requester === currentUser;
};

export const useFileTransfer = (
  tty: Tty,
  session: Session,
  currentDoc: DocumentSsh,
  addMfaToScpUrls: boolean
) => {
  const { filesStore } = useFileTransferContext();
  const ctx = useConsoleContext();
  const currentUser = ctx.getStoreUser();
  const [fileTransferRequests, setFileTransferRequests] = useState<
    FileTransferRequest[]
  >([]);
  const { getScpUrl, attempt: getMfaResponseAttempt } =
    useGetScpUrl(addMfaToScpUrls);

  const download = useCallback(
    async (
      location: string,
      abortController: AbortController,
      moderatedSessionParams?: ModeratedSessionParams
    ) => {
      const { clusterId, serverId, login } = currentDoc;
      const url = await getScpUrl({
        location,
        clusterId: clusterId,
        serverId: serverId,
        login: login,
        filename: location,
        moderatedSessonId: moderatedSessionParams?.moderatedSessionId,
        fileTransferRequestId: moderatedSessionParams?.fileRequestId,
      });
      if (!url) {
        // if we return nothing here, the file transfer will not be added to the
        // file transfer list. If we add it to the list, the file will continue to
        // start the download and return another here. This prevents a second network
        // request that we know will fail.
        return;
      }
      return getHttpFileTransferHandlers().download(url, abortController);
    },
    [currentDoc, getScpUrl]
  );

  const upload = useCallback(
    async (
      location: string,
      file: File,
      abortController: AbortController,
      moderatedSessionParams?: ModeratedSessionParams
    ) => {
      const { clusterId, serverId, login } = currentDoc;
      const url = await getScpUrl({
        location,
        clusterId: clusterId,
        serverId: serverId,
        login: login,
        filename: file.name,
        moderatedSessonId: moderatedSessionParams?.moderatedSessionId,
        fileTransferRequestId: moderatedSessionParams?.fileRequestId,
      });
      if (!url) {
        // if we return nothing here, the file transfer will not be added to the
        // file transfer list. If we add it to the list, the file will continue to
        // start the download and return another here. This prevents a second network
        // request that we know will fail.
        return;
      }
      return getHttpFileTransferHandlers().upload(url, file, abortController);
    },
    [currentDoc, getScpUrl]
  );

  /*
   * TTY event listeners
   */

  // handleFileTransferDenied is called when a FILE_TRANSFER_REQUEST_DENY event is received
  // from the tty.
  const handleFileTransferDenied = useCallback(
    (request: FileTransferRequest) => {
      removeFileTransferRequest(request.requestID);
    },
    []
  );

  // handleFileTransferApproval is called when a FILE_TRANSFER_REQUEST_APPROVE event is received.
  // This isn't called when a single approval is received, but rather when the request approval policy has been
  // completely fulfilled, i.e. "This request requires two moderators approval and we received both". Any approve that
  // doesn't fulfill the policy will be sent as an update and handled in handleFileTransferUpdate
  const handleFileTransferApproval = useCallback(
    (request: FileTransferRequest, file?: File) => {
      removeFileTransferRequest(request.requestID);
      if (!isOwnRequest(request, currentUser.username)) {
        return;
      }

      if (request.download) {
        return filesStore.start({
          name: request.location,
          runFileTransfer: abortController =>
            download(request.location, abortController, {
              fileRequestId: request.requestID,
              moderatedSessionId: request.sid,
            }),
        });
      }

      // if it gets here, it's an upload
      if (!file) {
        throw new Error('Approved file not found for upload.');
      }
      return filesStore.start({
        name: request.filename,
        runFileTransfer: abortController =>
          upload(request.location, file, abortController, {
            fileRequestId: request.requestID,
            moderatedSessionId: request.sid,
          }),
      });
    },
    [currentUser.username, download, filesStore, upload]
  );

  // handleFileTransferUpdate is called when a FILE_TRANSFER_REQUEST event is received. This is used when
  // we receive a new file transfer request, or when a request has been updated with an approval but its policy isn't
  // completely approved yet. An update in this way generally means that the approver array is updated.
  function handleFileTransferUpdate(data: FileTransferRequest) {
    setFileTransferRequests(prevstate => {
      // We receive the same data type when a file transfer request is created and
      // when an update event happens. Check if we already have this request in our list. If not
      // in our list, we add it
      const foundRequest = prevstate.find(
        ft => ft.requestID === data.requestID
      );
      if (!foundRequest) {
        return [...prevstate, data];
      } else {
        return prevstate.map(ft => {
          if (ft.requestID === data.requestID) {
            return data;
          }
          return ft;
        });
      }
    });
  }

  useEffect(() => {
    // the tty will be init outside of this hook, so we wait until
    // it exists and then attach file transfer handlers to it
    if (!tty) {
      return;
    }
    tty.on(EventType.FILE_TRANSFER_REQUEST, handleFileTransferUpdate);
    tty.on(EventType.FILE_TRANSFER_REQUEST_APPROVE, handleFileTransferApproval);
    tty.on(EventType.FILE_TRANSFER_REQUEST_DENY, handleFileTransferDenied);
    return () => {
      tty.removeListener(
        EventType.FILE_TRANSFER_REQUEST,
        handleFileTransferUpdate
      );
      tty.removeListener(
        EventType.FILE_TRANSFER_REQUEST_APPROVE,
        handleFileTransferApproval
      );
      tty.removeListener(
        EventType.FILE_TRANSFER_REQUEST_DENY,
        handleFileTransferDenied
      );
    };
  }, [tty, handleFileTransferDenied, handleFileTransferApproval]);

  function removeFileTransferRequest(requestId: string) {
    setFileTransferRequests(prevstate =>
      prevstate.filter(ft => ft.requestID !== requestId)
    );
  }

  /*
   * Transfer handlers
   */

  async function getDownloader(
    location: string,
    abortController: AbortController
  ) {
    if (session.moderated) {
      tty.sendFileDownloadRequest(location);
      return;
    }

    return download(location, abortController);
  }

  async function getUploader(
    location: string,
    file: File,
    abortController: AbortController
  ) {
    if (session.moderated) {
      tty.sendFileUploadRequest(location, file);
      return;
    }

    return upload(location, file, abortController);
  }

  return {
    fileTransferRequests,
    getMfaResponseAttempt,
    getUploader,
    getDownloader,
  };
};

type ModeratedSessionParams = {
  fileRequestId: string;
  moderatedSessionId: string;
};
