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

import React from 'react';

import styled from 'styled-components';

import { useAppContext } from 'teleterm/ui/appContextProvider';
import * as types from 'teleterm/ui/services/workspacesService';
import { DocumentsService } from 'teleterm/ui/services/workspacesService';
import DocumentCluster from 'teleterm/ui/DocumentCluster';
import DocumentGateway from 'teleterm/ui/DocumentGateway';
import DocumentTerminal from 'teleterm/ui/DocumentTerminal';
import Document from 'teleterm/ui/Document';

import { WorkspaceDocumentsServiceProvider } from './workspaceDocumentsServiceContext';
import { KeyboardShortcutsPanel } from './KeyboardShortcutsPanel';

export function DocumentsRenderer() {
  const { workspacesService } = useAppContext();

  function renderDocuments(documentsService: DocumentsService) {
    return documentsService.getDocuments().map(doc => {
      const isActiveDoc = workspacesService.isDocumentActive(doc.uri);
      return <MemoizedDocument doc={doc} visible={isActiveDoc} key={doc.uri} />;
    });
  }

  return (
    <>
      {workspacesService
        .getWorkspacesDocumentsServices()
        .map(({ clusterUri, workspaceDocumentsService }) => (
          <DocumentsContainer
            isVisible={clusterUri === workspacesService.getRootClusterUri()}
            key={clusterUri}
          >
            <WorkspaceDocumentsServiceProvider
              value={workspaceDocumentsService}
            >
              {workspaceDocumentsService.getDocuments().length ? (
                renderDocuments(workspaceDocumentsService)
              ) : (
                <KeyboardShortcutsPanel />
              )}
            </WorkspaceDocumentsServiceProvider>
          </DocumentsContainer>
        ))}
    </>
  );
}

const DocumentsContainer = styled.div`
  display: ${props => (props.isVisible ? 'contents' : 'none')};
`;

function MemoizedDocument(props: { doc: types.Document; visible: boolean }) {
  const { doc, visible } = props;
  return React.useMemo(() => {
    switch (doc.kind) {
      case 'doc.cluster':
        return <DocumentCluster doc={doc} visible={visible} />;
      case 'doc.gateway':
        return <DocumentGateway doc={doc} visible={visible} />;
      case 'doc.terminal_shell':
      case 'doc.terminal_tsh_node':
      case 'doc.terminal_tsh_kube':
        return <DocumentTerminal doc={doc} visible={visible} />;
      default:
        return (
          <Document visible={visible}>
            Document kind "{doc.kind}" is not supported
          </Document>
        );
    }
  }, [visible, doc]);
}
