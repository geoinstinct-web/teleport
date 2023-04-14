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

import { routing, ServerUri } from 'teleterm/ui/uri';
import { IAppContext } from 'teleterm/ui/types';

import { DocumentOrigin } from './types';

export async function connectToServer(
  ctx: IAppContext,
  target: {
    uri: ServerUri;
    hostname: string;
    login: string;
  },
  telemetry: {
    origin: DocumentOrigin;
  }
): Promise<void> {
  const rootClusterUri = routing.ensureRootClusterUri(target.uri);
  const documentsService = ctx.workspacesService.getWorkspaceDocumentService(
    routing.ensureRootClusterUri(target.uri)
  );
  const doc = documentsService.createTshNodeDocument(target.uri, {
    origin: telemetry.origin,
  });
  doc.title = `${target.login}@${target.hostname}`;
  doc.login = target.login;

  await ctx.workspacesService.setActiveWorkspace(rootClusterUri);
  documentsService.add(doc);
  documentsService.open(doc.uri);
}
