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
import { renderHook } from '@testing-library/react-hooks';
import 'jest-canvas-mock';
import * as useAsync from 'shared/hooks/useAsync';

import Logger, { NullService } from 'teleterm/logger';
import { PtyCommand, PtyProcessCreationStatus } from 'teleterm/services/pty';
import { MockAppContextProvider } from 'teleterm/ui/fixtures/MockAppContextProvider';
import { MockAppContext } from 'teleterm/ui/fixtures/mocks';
import {
  DocumentTerminal,
  DocumentTshNode,
  DocumentTshNodeWithLoginHost,
  DocumentTshNodeWithServerId,
} from 'teleterm/ui/services/workspacesService';
import {
  ResourcesService,
  AmbiguousHostnameError,
} from 'teleterm/ui/services/resources';
import { NotificationsService } from 'teleterm/ui/services/notifications';

import { WorkspaceContextProvider } from '../Documents';

import useDocumentTerminal from './useDocumentTerminal';

import type { IAppContext } from 'teleterm/ui/types';
import type * as tsh from 'teleterm/services/tshd/types';
import type * as uri from 'teleterm/ui/uri';

beforeAll(() => {
  Logger.init(new NullService());
});

afterEach(() => {
  jest.restoreAllMocks();
});

const rootClusterUri = '/clusters/test' as const;
const leafClusterUri = `${rootClusterUri}/leaves/leaf` as const;
const serverUUID = 'bed30649-3af5-40f1-a832-54ff4adcca41';
const server: tsh.Server = {
  uri: `${rootClusterUri}/servers/${serverUUID}`,
  tunnel: false,
  name: serverUUID,
  hostname: 'foo',
  addr: 'foo.localhost',
  labelsList: [],
};
const leafServer = { ...server };
leafServer.uri = `${leafClusterUri}/servers/${serverUUID}`;

const getDocTshNodeWithServerId: () => DocumentTshNodeWithServerId = () => ({
  kind: 'doc.terminal_tsh_node',
  uri: '/docs/123',
  title: '',
  status: '',
  serverId: serverUUID,
  serverUri: `${rootClusterUri}/servers/${serverUUID}`,
  rootClusterId: 'test',
  leafClusterId: undefined,
  login: 'user',
});

const getDocTshNodeWithLoginHost: () => DocumentTshNodeWithLoginHost = () => {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { serverId, serverUri, login, ...rest } = getDocTshNodeWithServerId();
  return {
    ...rest,
    loginHost: 'user@foo',
  };
};

test('useDocumentTerminal calls TerminalsService during init', async () => {
  const doc = getDocTshNodeWithServerId();
  const { wrapper, appContext } = testSetup(doc);

  const { result, waitForValueToChange } = renderHook(
    () => useDocumentTerminal(doc),
    { wrapper }
  );

  await waitForValueToChange(() => useAsync.hasFinished(result.current));

  const expectedPtyCommand: PtyCommand = {
    kind: 'pty.tsh-login',
    proxyHost: 'localhost:3080',
    clusterName: 'Test',
    login: 'user',
    serverId: serverUUID,
    rootClusterId: 'test',
    leafClusterId: undefined,
  };

  expect(result.current.statusText).toBeFalsy();
  expect(result.current.status).toBe('success');
  expect(appContext.terminalsService.createPtyProcess).toHaveBeenCalledWith(
    expectedPtyCommand
  );
});

test('useDocumentTerminal calls TerminalsService only once', async () => {
  const doc = getDocTshNodeWithServerId();
  const { wrapper, appContext } = testSetup(doc);

  const { result, waitForValueToChange, rerender } = renderHook(
    () => useDocumentTerminal(doc),
    { wrapper }
  );

  await waitForValueToChange(() => useAsync.hasFinished(result.current));
  expect(result.current.statusText).toBeFalsy();
  expect(result.current.status).toBe('success');
  rerender();

  expect(appContext.terminalsService.createPtyProcess).toHaveBeenCalledTimes(1);
});

test('useDocumentTerminal gets leaf cluster ID from ClustersService when the leaf cluster is in ClustersService', async () => {
  const doc = getDocTshNodeWithServerId();
  doc.leafClusterId = 'leaf';
  doc.serverUri = `${leafClusterUri}/servers/${doc.serverId}`;
  const { wrapper, appContext } = testSetup(doc, leafClusterUri);

  const { result, waitForValueToChange } = renderHook(
    () => useDocumentTerminal(doc),
    { wrapper }
  );

  await waitForValueToChange(() => useAsync.hasFinished(result.current));

  const expectedPtyCommand: PtyCommand = {
    kind: 'pty.tsh-login',
    proxyHost: 'localhost:3080',
    clusterName: 'leaf',
    login: 'user',
    serverId: serverUUID,
    rootClusterId: 'test',
    leafClusterId: 'leaf',
  };

  expect(result.current.statusText).toBeFalsy();
  expect(result.current.status).toBe('success');
  expect(appContext.terminalsService.createPtyProcess).toHaveBeenCalledWith(
    expectedPtyCommand
  );
});

test('useDocumentTerminal gets leaf cluster ID from doc.leafClusterId if the leaf cluster is not synced yet', async () => {
  const doc = getDocTshNodeWithServerId();
  doc.leafClusterId = 'leaf';
  doc.serverUri = `${leafClusterUri}/servers/${doc.serverId}`;
  const { wrapper, appContext } = testSetup(doc, leafClusterUri);
  appContext.clustersService.setState(draft => {
    draft.clusters.delete(leafClusterUri);
  });

  const { result, waitForValueToChange } = renderHook(
    () => useDocumentTerminal(doc),
    { wrapper }
  );

  await waitForValueToChange(() => useAsync.hasFinished(result.current));

  const expectedPtyCommand: PtyCommand = {
    kind: 'pty.tsh-login',
    proxyHost: 'localhost:3080',
    clusterName: 'leaf',
    login: 'user',
    serverId: serverUUID,
    rootClusterId: 'test',
    leafClusterId: 'leaf',
  };

  expect(result.current.statusText).toBeFalsy();
  expect(result.current.status).toBe('success');
  expect(appContext.terminalsService.createPtyProcess).toHaveBeenCalledWith(
    expectedPtyCommand
  );
});

test('useDocumentTerminal shows an error notification if the call to TerminalsService fails', async () => {
  const doc = getDocTshNodeWithServerId();
  const { wrapper, appContext } = testSetup(doc);
  const { terminalsService, notificationsService } = appContext;

  (
    terminalsService.createPtyProcess as jest.MockedFunction<
      typeof terminalsService.createPtyProcess
    >
  ).mockReset();
  jest
    .spyOn(terminalsService, 'createPtyProcess')
    .mockRejectedValue(new Error('whoops'));
  jest.spyOn(notificationsService, 'notifyError');

  const { result, waitForValueToChange } = renderHook(
    () => useDocumentTerminal(doc),
    { wrapper }
  );

  await waitForValueToChange(() => useAsync.hasFinished(result.current));
  expect(result.current.statusText).toBeFalsy();
  expect(result.current.status).toBe('success');

  expect(notificationsService.notifyError).toHaveBeenCalledWith('whoops');
  expect(notificationsService.notifyError).toHaveBeenCalledTimes(1);
});

test('useDocumentTerminal shows a warning notification if the call to TerminalsService fails due to resolving env timeout', async () => {
  const doc = getDocTshNodeWithServerId();
  const { wrapper, appContext } = testSetup(doc);
  const { terminalsService, notificationsService } = appContext;

  (
    terminalsService.createPtyProcess as jest.MockedFunction<
      typeof terminalsService.createPtyProcess
    >
  ).mockReset();
  jest.spyOn(terminalsService, 'createPtyProcess').mockResolvedValue({
    process: undefined,
    creationStatus: PtyProcessCreationStatus.ResolveShellEnvTimeout,
  });
  jest.spyOn(notificationsService, 'notifyWarning');

  const { result, waitForValueToChange } = renderHook(
    () => useDocumentTerminal(doc),
    { wrapper }
  );

  await waitForValueToChange(() => useAsync.hasFinished(result.current));
  expect(result.current.statusText).toBeFalsy();
  expect(result.current.status).toBe('success');

  expect(notificationsService.notifyWarning).toHaveBeenCalledWith({
    title: expect.stringContaining('Could not source environment variables'),
    description: expect.stringContaining('shell startup'),
  });
  expect(notificationsService.notifyWarning).toHaveBeenCalledTimes(1);
});

describe('calling useDocumentTerminal with a doc with a loginHost', () => {
  const tests: Array<
    {
      name: string;
      prepareDoc?: (doc: DocumentTshNodeWithLoginHost) => void;
      prepareContext?: (ctx: IAppContext) => void;
      mockGetServerByHostname:
        | Awaited<ReturnType<ResourcesService['getServerByHostname']>>
        | AmbiguousHostnameError
        | Error;
      expectedDocumentUpdate: Partial<DocumentTshNode>;
      expectedArgsOfGetServerByHostname: Parameters<
        ResourcesService['getServerByHostname']
      >;
      expectedErrorNotification?: Parameters<
        NotificationsService['notifyError']
      >[0];
    } & (
      | { expectedPtyCommand: PtyCommand; expectedError?: never }
      | { expectedPtyCommand?: never; expectedError: string }
    )
  > = [
    {
      name: 'calls ResourcesService to resolve the hostname of a root cluster SSH server to a UUID',
      mockGetServerByHostname: server,
      expectedPtyCommand: {
        kind: 'pty.tsh-login',
        proxyHost: 'localhost:3080',
        clusterName: 'Test',
        login: 'user',
        serverId: serverUUID,
        rootClusterId: 'test',
        leafClusterId: undefined,
      },
      expectedDocumentUpdate: {
        serverId: serverUUID,
        serverUri: server.uri,
        login: 'user',
        loginHost: undefined,
        title: 'user@foo',
      },
      expectedArgsOfGetServerByHostname: [rootClusterUri, 'foo'],
    },
    {
      name: 'calls ResourcesService to resolve the hostname of a leaf cluster SSH server to a UUID',
      prepareDoc: doc => {
        doc.leafClusterId = 'leaf';
      },
      mockGetServerByHostname: leafServer,
      expectedPtyCommand: {
        kind: 'pty.tsh-login',
        proxyHost: 'localhost:3080',
        clusterName: 'leaf',
        login: 'user',
        serverId: serverUUID,
        rootClusterId: 'test',
        leafClusterId: 'leaf',
      },
      expectedDocumentUpdate: {
        serverId: serverUUID,
        serverUri: leafServer.uri,
        login: 'user',
        loginHost: undefined,
        title: 'user@foo',
      },
      expectedArgsOfGetServerByHostname: [leafClusterUri, 'foo'],
    },
    {
      name: 'starts the session even if the leaf cluster is not synced yet',
      prepareDoc: doc => {
        doc.leafClusterId = 'leaf';
      },
      prepareContext: ctx => {
        ctx.clustersService.setState(draft => {
          draft.clusters.delete(leafClusterUri);
        });
      },
      mockGetServerByHostname: leafServer,
      expectedPtyCommand: {
        kind: 'pty.tsh-login',
        proxyHost: 'localhost:3080',
        clusterName: 'leaf',
        login: 'user',
        serverId: serverUUID,
        rootClusterId: 'test',
        leafClusterId: 'leaf',
      },
      expectedDocumentUpdate: {
        serverId: serverUUID,
        serverUri: leafServer.uri,
        login: 'user',
        loginHost: undefined,
        title: 'user@foo',
      },
      expectedArgsOfGetServerByHostname: [leafClusterUri, 'foo'],
    },
    {
      name: 'maintains incorrect loginHost with too many parts',
      prepareDoc: doc => {
        doc.loginHost = 'user@foo@baz';
      },
      mockGetServerByHostname: undefined,
      expectedPtyCommand: {
        kind: 'pty.tsh-login',
        proxyHost: 'localhost:3080',
        clusterName: 'Test',
        login: 'user@foo',
        serverId: 'baz',
        rootClusterId: 'test',
        leafClusterId: undefined,
      },
      expectedDocumentUpdate: {
        serverId: 'baz',
        serverUri: `${rootClusterUri}/servers/baz`,
        login: 'user@foo',
        loginHost: undefined,
        title: 'user@foo@baz',
      },
      expectedArgsOfGetServerByHostname: [rootClusterUri, 'baz'],
    },
    {
      // This is in order to call `tsh ssh user@foo` anyway and make tsh show an appropriate error.
      name: 'uses hostname as serverId if no matching server was found',
      mockGetServerByHostname: undefined,
      expectedPtyCommand: {
        kind: 'pty.tsh-login',
        proxyHost: 'localhost:3080',
        clusterName: 'Test',
        login: 'user',
        serverId: 'foo',
        rootClusterId: 'test',
        leafClusterId: undefined,
      },
      expectedDocumentUpdate: {
        serverId: 'foo',
        serverUri: `${rootClusterUri}/servers/foo`,
        login: 'user',
        loginHost: undefined,
        title: 'user@foo',
      },
      expectedArgsOfGetServerByHostname: [rootClusterUri, 'foo'],
    },
    {
      // This is the case when the user tries to execute `tsh ssh host`. We want to call `tsh ssh
      // host` anyway and make tsh show an appropriate error. But…
      name: 'attempts to connect even if only the host was supplied and the server was not resolved',
      prepareDoc: doc => {
        doc.loginHost = 'host';
      },
      mockGetServerByHostname: undefined,
      expectedPtyCommand: {
        kind: 'pty.tsh-login',
        proxyHost: 'localhost:3080',
        clusterName: 'Test',
        login: undefined,
        serverId: 'host',
        rootClusterId: 'test',
        leafClusterId: undefined,
      },
      expectedDocumentUpdate: {
        serverId: 'host',
        serverUri: `${rootClusterUri}/servers/host`,
        login: undefined,
        loginHost: undefined,
        title: 'host',
      },
      expectedArgsOfGetServerByHostname: [rootClusterUri, 'host'],
    },
    {
      // …it might also be the case that the username of a Teleport user is equal to a user on the
      // host, in which case explicitly providing the username is not necessary.
      name: 'attempts to connect even if only the host was supplied and the server was resolved',
      prepareDoc: doc => {
        doc.loginHost = 'foo';
      },
      mockGetServerByHostname: server,
      expectedPtyCommand: {
        kind: 'pty.tsh-login',
        proxyHost: 'localhost:3080',
        clusterName: 'Test',
        login: undefined,
        serverId: serverUUID,
        rootClusterId: 'test',
        leafClusterId: undefined,
      },
      expectedDocumentUpdate: {
        serverId: serverUUID,
        serverUri: server.uri,
        login: undefined,
        loginHost: undefined,
        title: 'foo',
      },
      expectedArgsOfGetServerByHostname: [rootClusterUri, 'foo'],
    },
    {
      // As in other scenarios, we execute `tsh ssh user@ambiguous-host` anyway and let tsh show the
      // error message.
      name: 'silently ignores an ambiguous hostname error',
      prepareDoc: doc => {
        doc.loginHost = 'user@ambiguous-host';
      },
      mockGetServerByHostname: new AmbiguousHostnameError('ambiguous-host'),
      expectedPtyCommand: {
        kind: 'pty.tsh-login',
        proxyHost: 'localhost:3080',
        clusterName: 'Test',
        login: 'user',
        serverId: 'ambiguous-host',
        rootClusterId: 'test',
        leafClusterId: undefined,
      },
      expectedDocumentUpdate: {
        serverId: 'ambiguous-host',
        serverUri: `${rootClusterUri}/servers/ambiguous-host`,
        login: 'user',
        loginHost: undefined,
        title: 'user@ambiguous-host',
      },
      expectedArgsOfGetServerByHostname: [rootClusterUri, 'ambiguous-host'],
    },
    {
      name: 'shows an error notification and updates doc state if there was an error when resolving hostname',
      mockGetServerByHostname: new Error('oops'),
      expectedError: 'oops',
      expectedDocumentUpdate: {
        status: 'disconnected',
      },
      expectedArgsOfGetServerByHostname: [rootClusterUri, 'foo'],
      expectedErrorNotification: {
        title: expect.stringContaining('connection to user@foo'),
        description: 'oops',
      },
    },
  ];

  test.each(tests)(
    '$name',
    async ({
      prepareDoc,
      prepareContext,
      mockGetServerByHostname,
      expectedPtyCommand,
      expectedDocumentUpdate,
      expectedArgsOfGetServerByHostname,
      expectedError,
      expectedErrorNotification,
    }) => {
      const doc = getDocTshNodeWithLoginHost();
      prepareDoc?.(doc);
      const { wrapper, appContext, documentsService } = testSetup(doc);
      prepareContext?.(appContext);
      const { resourcesService, terminalsService, notificationsService } =
        appContext;

      jest.spyOn(documentsService, 'update');
      jest.spyOn(notificationsService, 'notifyError');

      if (mockGetServerByHostname instanceof Error) {
        jest
          .spyOn(resourcesService, 'getServerByHostname')
          .mockRejectedValueOnce(mockGetServerByHostname);
      } else {
        jest
          .spyOn(resourcesService, 'getServerByHostname')
          .mockResolvedValueOnce(mockGetServerByHostname);
      }

      const { result, waitForValueToChange } = renderHook(
        () => useDocumentTerminal(doc),
        { wrapper }
      );

      await waitForValueToChange(() => useAsync.hasFinished(result.current));

      /* eslint-disable jest/no-conditional-expect */
      if (expectedError) {
        expect(result.current.statusText).toEqual(expectedError);
        expect(result.current.status).toBe('error');
        expect(terminalsService.createPtyProcess).not.toHaveBeenCalled();
      } else {
        expect(result.current.statusText).toBeFalsy();
        expect(result.current.status).toBe('success');
        expect(terminalsService.createPtyProcess).toHaveBeenCalledWith(
          expectedPtyCommand
        );
      }
      /* eslint-enable jest/no-conditional-expect */

      expect(resourcesService.getServerByHostname).toHaveBeenCalledWith(
        ...expectedArgsOfGetServerByHostname
      );
      expect(documentsService.update).toHaveBeenCalledWith(
        doc.uri,
        expectedDocumentUpdate
      );

      if (expectedErrorNotification) {
        // eslint-disable-next-line jest/no-conditional-expect
        expect(notificationsService.notifyError).toHaveBeenCalledWith(
          expectedErrorNotification
        );
      }
    }
  );
});

// testSetup adds a cluster to ClustersService and WorkspacesService.
// It also makes TerminalsService.prototype.createPtyProcess a noop.
const testSetup = (
  doc: DocumentTerminal,
  localClusterUri: uri.ClusterUri = rootClusterUri
) => {
  const cluster: tsh.Cluster = {
    uri: rootClusterUri,
    name: 'Test',
    connected: true,
    leaf: false,
    proxyHost: 'localhost:3080',
    authClusterId: '73c4746b-d956-4f16-9848-4e3469f70762',
    loggedInUser: {
      activeRequestsList: [],
      assumedRequests: {},
      name: 'admin',
      acl: {},
      sshLoginsList: [],
      rolesList: [],
      requestableRolesList: [],
      suggestedReviewersList: [],
    },
  };
  const leafCluster: tsh.Cluster = {
    uri: leafClusterUri,
    name: 'leaf',
    connected: true,
    leaf: true,
    proxyHost: '',
    authClusterId: '5408fc2f-a452-4bde-bda2-b3b918c635ad',
    loggedInUser: {
      activeRequestsList: [],
      assumedRequests: {},
      name: 'admin',
      acl: {},
      sshLoginsList: [],
      rolesList: [],
      requestableRolesList: [],
      suggestedReviewersList: [],
    },
  };
  const appContext = new MockAppContext();
  appContext.clustersService.setState(draftState => {
    draftState.clusters.set(rootClusterUri, cluster);
    draftState.clusters.set(leafCluster.uri, leafCluster);
  });
  appContext.workspacesService.setActiveWorkspace(rootClusterUri);
  const documentsService =
    appContext.workspacesService.getWorkspaceDocumentService(rootClusterUri);
  documentsService.add(doc);
  jest
    .spyOn(appContext.terminalsService, 'createPtyProcess')
    .mockImplementationOnce(async () => {
      return {
        process: undefined,
        creationStatus: PtyProcessCreationStatus.Ok,
      };
    });

  const wrapper = ({ children }) => (
    <MockAppContextProvider appContext={appContext}>
      <WorkspaceContextProvider
        value={{
          rootClusterUri: rootClusterUri,
          localClusterUri,
          documentsService,
          accessRequestsService: undefined,
        }}
      >
        {children}
      </WorkspaceContextProvider>
    </MockAppContextProvider>
  );

  return { appContext, wrapper, documentsService };
};

// TODO(ravicious): Add tests for the following cases:
// * dispose on unmount when state is success
// * removing init command from doc
// * marking the doc as connected when data arrives
// * closing the doc with 0 exit code
// * not closing the doc with non-zero exit code
