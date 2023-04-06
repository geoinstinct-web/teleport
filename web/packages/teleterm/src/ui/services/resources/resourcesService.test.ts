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

import {
  makeDatabase,
  makeKube,
  makeServer,
} from 'teleterm/services/tshd/testHelpers';

import {
  AmbiguousHostnameError,
  ResourceSearchError,
  ResourcesService,
} from './resourcesService';

import type * as tsh from 'teleterm/services/tshd/types';

describe('getServerByHostname', () => {
  const server: tsh.Server = makeServer();
  const getServerByHostnameTests: Array<
    {
      name: string;
      getServersMockedValue: Awaited<ReturnType<tsh.TshClient['getServers']>>;
    } & (
      | { expectedServer: tsh.Server; expectedErr?: never }
      | { expectedErr: any; expectedServer?: never }
    )
  > = [
    {
      name: 'returns a server when the hostname matches a single server',
      getServersMockedValue: {
        agentsList: [server],
        totalCount: 1,
        startKey: 'foo',
      },
      expectedServer: server,
    },
    {
      name: 'throws an error when the hostname matches multiple servers',
      getServersMockedValue: {
        agentsList: [server, server],
        totalCount: 2,
        startKey: 'foo',
      },
      expectedErr: AmbiguousHostnameError,
    },
    {
      name: 'returns nothing if the hostname does not match any servers',
      getServersMockedValue: {
        agentsList: [],
        totalCount: 0,
        startKey: 'foo',
      },
      expectedServer: undefined,
    },
  ];
  test.each(getServerByHostnameTests)(
    '$name',
    async ({ getServersMockedValue, expectedServer, expectedErr }) => {
      const tshClient: Partial<tsh.TshClient> = {
        getServers: jest.fn().mockResolvedValueOnce(getServersMockedValue),
      };
      const service = new ResourcesService(tshClient as tsh.TshClient);

      const promise = service.getServerByHostname('/clusters/bar', 'foo');

      if (expectedErr) {
        // eslint-disable-next-line jest/no-conditional-expect
        await expect(promise).rejects.toThrow(expectedErr);
      } else {
        // eslint-disable-next-line jest/no-conditional-expect
        await expect(promise).resolves.toStrictEqual(expectedServer);
      }

      expect(tshClient.getServers).toHaveBeenCalledWith({
        clusterUri: '/clusters/bar',
        query: 'name == "foo"',
        limit: 2,
        sort: null,
      });
    }
  );
});

describe('searchResources', () => {
  it('returns settled promises for each resource type', async () => {
    const server = makeServer();
    const db = makeDatabase();
    const kube = makeKube();

    const tshClient: Partial<tsh.TshClient> = {
      getServers: jest.fn().mockResolvedValueOnce({
        agentsList: [server],
        totalCount: 1,
        startKey: '',
      }),
      getDatabases: jest.fn().mockResolvedValueOnce({
        agentsList: [db],
        totalCount: 1,
        startKey: '',
      }),
      getKubes: jest.fn().mockResolvedValueOnce({
        agentsList: [kube],
        totalCount: 1,
        startKey: '',
      }),
    };
    const service = new ResourcesService(tshClient as tsh.TshClient);

    const searchResults = await service.searchResources(
      '/clusters/foo',
      '',
      undefined
    );
    expect(searchResults).toHaveLength(3);

    const [actualServers, actualDatabases, actualKubes] = searchResults;
    expect(actualServers).toEqual({
      status: 'fulfilled',
      value: [{ kind: 'server', resource: server }],
    });
    expect(actualDatabases).toEqual({
      status: 'fulfilled',
      value: [{ kind: 'database', resource: db }],
    });
    expect(actualKubes).toEqual({
      status: 'fulfilled',
      value: [{ kind: 'kube', resource: kube }],
    });
  });

  it('returns a single item if a filter is supplied', async () => {
    const server = makeServer();
    const tshClient: Partial<tsh.TshClient> = {
      getServers: jest.fn().mockResolvedValueOnce({
        agentsList: [server],
        totalCount: 1,
        startKey: '',
      }),
    };
    const service = new ResourcesService(tshClient as tsh.TshClient);

    const searchResults = await service.searchResources('/clusters/foo', '', {
      filter: 'resource-type',
      resourceType: 'servers',
    });
    expect(searchResults).toHaveLength(1);

    const [actualServers] = searchResults;
    expect(actualServers).toEqual({
      status: 'fulfilled',
      value: [{ kind: 'server', resource: server }],
    });
  });

  it('returns a custom error pointing at resource kind and cluster when an underlying promise gets rejected', async () => {
    const expectedCause = new Error('oops');
    const tshClient: Partial<tsh.TshClient> = {
      getServers: jest.fn().mockRejectedValueOnce(expectedCause),
      getDatabases: jest.fn().mockRejectedValueOnce(expectedCause),
      getKubes: jest.fn().mockRejectedValueOnce(expectedCause),
    };
    const service = new ResourcesService(tshClient as tsh.TshClient);

    const searchResults = await service.searchResources(
      '/clusters/foo',
      '',
      undefined
    );
    expect(searchResults).toHaveLength(3);

    const [actualServers, actualDatabases, actualKubes] = searchResults;
    expect(actualServers).toEqual({
      status: 'rejected',
      reason: new ResourceSearchError('/clusters/foo', 'server', expectedCause),
    });
    expect(actualDatabases).toEqual({
      status: 'rejected',
      reason: new ResourceSearchError(
        '/clusters/foo',
        'database',
        expectedCause
      ),
    });
    expect(actualKubes).toEqual({
      status: 'rejected',
      reason: new ResourceSearchError('/clusters/foo', 'kube', expectedCause),
    });

    expect((actualServers as PromiseRejectedResult).reason.cause).toEqual(
      expectedCause
    );
  });
});
