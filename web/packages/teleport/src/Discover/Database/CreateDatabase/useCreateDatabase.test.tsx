/**
 * Copyright 2022 Gravitational, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import React from 'react';
import { MemoryRouter } from 'react-router';
import { renderHook, act } from '@testing-library/react-hooks';

import { createTeleportContext } from 'teleport/mocks/contexts';
import { ContextProvider } from 'teleport';
import { DiscoverProvider } from 'teleport/Discover/useDiscover';
import api from 'teleport/services/api';
import { FeaturesContextProvider } from 'teleport/FeaturesContext';
import { userEventService } from 'teleport/services/userEvent';
import cfg from 'teleport/config';

import {
  useCreateDatabase,
  findActiveDatabaseSvc,
  WAITING_TIMEOUT,
} from './useCreateDatabase';

import type { CreateDatabaseRequest } from 'teleport/services/databases';

const crypto = require('crypto');

// eslint-disable-next-line jest/require-hook
Object.defineProperty(globalThis, 'crypto', {
  value: {
    randomUUID: () => crypto.randomUUID(),
  },
});

const dbLabels = [
  { name: 'env', value: 'prod' },
  { name: 'os', value: 'mac' },
  { name: 'tag', value: 'v11.0.0' },
];

const emptyAwsIdentity = {
  accountId: '',
  arn: '',
  resourceType: '',
  resourceName: '',
};

const services = [
  {
    name: 'svc1',
    matcherLabels: { os: ['windows', 'mac'], env: ['staging'] },
    awsIdentity: emptyAwsIdentity,
  },
  {
    name: 'svc2', // match
    matcherLabels: {
      os: ['windows', 'mac', 'linux'],
      tag: ['v11.0.0'],
      env: ['staging', 'prod'],
    },
    awsIdentity: emptyAwsIdentity,
  },
  {
    name: 'svc3',
    matcherLabels: { env: ['prod'], fruit: ['orange'] },
    awsIdentity: emptyAwsIdentity,
  },
];

const testCases = [
  {
    name: 'match in multiple services',
    newLabels: dbLabels,
    services,
    expectedMatch: 'svc2',
  },
  {
    name: 'no match despite matching all labels when a svc has a non-matching label',
    newLabels: dbLabels,
    services: [
      {
        name: 'svc1',
        matcherLabels: { os: ['windows', 'mac'], env: ['staging'] },
        awsIdentity: emptyAwsIdentity,
      },
      {
        name: 'svc2',
        matcherLabels: {
          os: ['windows', 'mac', 'linux'],
          tag: ['v11.0.0'],
          env: ['staging', 'prod'],
          fruit: ['apple', '*'], // the non-matching label
        },
        awsIdentity: emptyAwsIdentity,
      },
      {
        name: 'svc3',
        matcherLabels: { env: ['prod'], fruit: ['orange'] },
        awsIdentity: emptyAwsIdentity,
      },
    ],
    expectedMatch: undefined,
  },
  {
    name: 'match by all asteriks',
    newLabels: [],
    services: [
      {
        name: 'svc1',
        matcherLabels: { '*': ['dev'], env: ['*'] },
        awsIdentity: emptyAwsIdentity,
      },
      {
        name: 'svc2',
        matcherLabels: { '*': ['*'] },
        awsIdentity: emptyAwsIdentity,
      },
    ],
    expectedMatch: 'svc2',
  },
  {
    name: 'match by asteriks, despite labels being defined',
    newLabels: dbLabels,
    services: [
      {
        name: 'svc1',
        matcherLabels: { id: ['env', 'dev'], a: [], '*': ['*'] },
        awsIdentity: emptyAwsIdentity,
      },
    ],
    expectedMatch: 'svc1',
  },
  {
    name: 'match by any key, matching its val',
    newLabels: dbLabels,
    services: [
      {
        name: 'svc1',
        matcherLabels: { env: ['*'], '*': ['dev'] },
        awsIdentity: emptyAwsIdentity,
      },
      {
        name: 'svc2',
        matcherLabels: {
          os: ['linux', 'mac'],
          '*': ['prod', 'apple', 'v11.0.0'],
        },
        awsIdentity: emptyAwsIdentity,
      },
    ],
    expectedMatch: 'svc2',
  },
  {
    name: 'no matching value for any key',
    newLabels: dbLabels,
    services: [
      {
        name: 'svc1',
        matcherLabels: { '*': ['windows', 'mac'] },
        awsIdentity: emptyAwsIdentity,
      },
    ],
    expectedMatch: undefined,
  },
  {
    name: 'match by any val, matching its key',
    newLabels: dbLabels,
    services: [
      {
        name: 'svc1',
        matcherLabels: {
          env: ['dev', '*'],
          os: ['windows', 'mac'],
          tag: ['*'],
        },
        awsIdentity: emptyAwsIdentity,
      },
    ],
    expectedMatch: 'svc1',
  },
  {
    name: 'no matching key for any value',
    newLabels: dbLabels,
    services: [
      {
        name: 'svc1',
        matcherLabels: {
          fruit: ['*'],
          os: ['mac'],
        },
        awsIdentity: emptyAwsIdentity,
      },
    ],
    expectedMatch: undefined,
  },
  {
    name: 'no match',
    newLabels: dbLabels,
    services: [
      {
        name: 'svc1',
        matcherLabels: {
          fruit: ['*'],
        },
        awsIdentity: emptyAwsIdentity,
      },
    ],
    expectedMatch: undefined,
  },
  {
    name: 'no match with empty service list',
    newLabels: dbLabels,
    services: [],
    expectedMatch: undefined,
  },
  {
    name: 'no match with empty label fields',
    newLabels: dbLabels,
    services: [{ name: '', matcherLabels: {}, awsIdentity: emptyAwsIdentity }],
    expectedMatch: undefined,
  },
];

test.each(testCases)('$name', ({ newLabels, services, expectedMatch }) => {
  const foundSvc = findActiveDatabaseSvc(newLabels, services);
  expect(foundSvc?.name).toEqual(expectedMatch);
});

const newDatabaseReq: CreateDatabaseRequest = {
  name: 'db-name',
  protocol: 'postgres',
  uri: 'https://localhost:5432',
  labels: dbLabels,
};

jest.useFakeTimers();

describe('registering new databases, mainly error checking', () => {
  const props = {
    agentMeta: {} as any,
    updateAgentMeta: jest.fn(x => x),
    nextStep: jest.fn(x => x),
    resourceSpec: { dbMeta: {} } as any,
  };
  const ctx = createTeleportContext();

  let wrapper;

  beforeEach(() => {
    jest.spyOn(api, 'get').mockResolvedValue([]); // required for fetchClusterAlerts

    jest
      .spyOn(userEventService, 'captureDiscoverEvent')
      .mockResolvedValue(null as never); // return value does not matter but required by ts
    jest
      .spyOn(ctx.databaseService, 'fetchDatabases')
      .mockResolvedValue({ agents: [{ name: 'new-db' } as any] });
    jest.spyOn(ctx.databaseService, 'createDatabase').mockResolvedValue(null); // ret val not used
    jest.spyOn(ctx.databaseService, 'updateDatabase').mockResolvedValue(null); // ret val not used
    jest
      .spyOn(ctx.databaseService, 'fetchDatabaseServices')
      .mockResolvedValue({ services });

    wrapper = ({ children }) => (
      <MemoryRouter
        initialEntries={[
          { pathname: cfg.routes.discover, state: { entity: 'database' } },
        ]}
      >
        <ContextProvider ctx={ctx}>
          <FeaturesContextProvider value={[]}>
            <DiscoverProvider>{children}</DiscoverProvider>
          </FeaturesContextProvider>
        </ContextProvider>
      </MemoryRouter>
    );
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  test('with matching service, activates polling', async () => {
    const { result } = renderHook(() => useCreateDatabase(props), {
      wrapper,
    });

    // Check polling hasn't started.
    expect(ctx.databaseService.fetchDatabases).not.toHaveBeenCalled();

    await act(async () => {
      result.current.registerDatabase(newDatabaseReq);
    });
    expect(ctx.databaseService.createDatabase).toHaveBeenCalledTimes(1);
    expect(ctx.databaseService.fetchDatabaseServices).toHaveBeenCalledTimes(1);

    await act(async () => jest.advanceTimersByTime(3000));
    expect(ctx.databaseService.fetchDatabases).toHaveBeenCalledTimes(1);
    expect(props.nextStep).toHaveBeenCalledWith(2);
    expect(props.updateAgentMeta).toHaveBeenCalledWith({
      resourceName: 'db-name',
      agentMatcherLabels: dbLabels,
      db: { name: 'new-db' },
    });
  });

  test('when there are no services, skips polling', async () => {
    jest
      .spyOn(ctx.databaseService, 'fetchDatabaseServices')
      .mockResolvedValue({ services: [] } as any);
    const { result, waitFor } = renderHook(() => useCreateDatabase(props), {
      wrapper,
    });

    act(() => {
      result.current.registerDatabase({ ...newDatabaseReq, labels: [] });
    });

    await waitFor(() => {
      expect(ctx.databaseService.createDatabase).toHaveBeenCalledTimes(1);
    });

    await waitFor(() => {
      expect(ctx.databaseService.fetchDatabaseServices).toHaveBeenCalledTimes(
        1
      );
    });

    expect(props.nextStep).toHaveBeenCalledWith();
    expect(props.updateAgentMeta).toHaveBeenCalledWith({
      resourceName: 'db-name',
      agentMatcherLabels: [],
    });
    expect(ctx.databaseService.fetchDatabases).not.toHaveBeenCalled();
  });

  test('when failed to create db, stops flow', async () => {
    jest.spyOn(ctx.databaseService, 'createDatabase').mockRejectedValue(null);
    const { result } = renderHook(() => useCreateDatabase(props), {
      wrapper,
    });

    await act(async () => {
      result.current.registerDatabase({ ...newDatabaseReq, labels: [] });
    });

    expect(ctx.databaseService.createDatabase).toHaveBeenCalledTimes(1);
    expect(ctx.databaseService.fetchDatabases).not.toHaveBeenCalled();
    expect(props.nextStep).not.toHaveBeenCalled();
    expect(result.current.attempt.status).toBe('failed');
  });

  test('when failed to fetch services, stops flow and retries properly', async () => {
    jest
      .spyOn(ctx.databaseService, 'fetchDatabaseServices')
      .mockRejectedValue(null);
    const { result } = renderHook(() => useCreateDatabase(props), {
      wrapper,
    });

    await act(async () => {
      result.current.registerDatabase({ ...newDatabaseReq, labels: [] });
    });

    expect(ctx.databaseService.createDatabase).toHaveBeenCalledTimes(1);
    expect(ctx.databaseService.fetchDatabaseServices).toHaveBeenCalledTimes(1);
    expect(ctx.databaseService.fetchDatabases).not.toHaveBeenCalled();
    expect(props.nextStep).not.toHaveBeenCalled();
    expect(result.current.attempt.status).toBe('failed');

    // Test retrying with same request, skips creating database since it's been already created.
    jest.clearAllMocks();
    await act(async () => {
      result.current.registerDatabase({ ...newDatabaseReq, labels: [] });
    });
    expect(ctx.databaseService.createDatabase).not.toHaveBeenCalled();
    expect(ctx.databaseService.fetchDatabaseServices).toHaveBeenCalledTimes(1);
    expect(result.current.attempt.status).toBe('failed');

    // Test retrying with updated field, triggers create database.
    jest.clearAllMocks();
    await act(async () => {
      result.current.registerDatabase({
        ...newDatabaseReq,
        labels: [],
        uri: 'diff-uri',
      });
    });
    expect(ctx.databaseService.createDatabase).not.toHaveBeenCalled();
    expect(ctx.databaseService.updateDatabase).toHaveBeenCalledTimes(1);
    expect(ctx.databaseService.fetchDatabaseServices).toHaveBeenCalledTimes(1);
    expect(result.current.attempt.status).toBe('failed');
  });

  test('when polling timeout, retries properly', async () => {
    jest
      .spyOn(ctx.databaseService, 'fetchDatabases')
      .mockResolvedValue({ agents: [] });
    const { result } = renderHook(() => useCreateDatabase(props), {
      wrapper,
    });

    await act(async () => {
      result.current.registerDatabase(newDatabaseReq);
    });

    act(() => jest.advanceTimersByTime(WAITING_TIMEOUT + 1));

    expect(ctx.databaseService.createDatabase).toHaveBeenCalledTimes(1);
    expect(ctx.databaseService.fetchDatabaseServices).toHaveBeenCalledTimes(1);
    expect(ctx.databaseService.fetchDatabases).toHaveBeenCalled();
    expect(props.nextStep).not.toHaveBeenCalled();
    expect(result.current.attempt.status).toBe('failed');
    expect(result.current.attempt.statusText).toContain('could not detect');

    // Test retrying with same request, skips creating database.
    jest.clearAllMocks();
    await act(async () => {
      result.current.registerDatabase(newDatabaseReq);
    });
    act(() => jest.advanceTimersByTime(WAITING_TIMEOUT + 1));

    expect(ctx.databaseService.createDatabase).not.toHaveBeenCalled();
    expect(ctx.databaseService.fetchDatabaseServices).toHaveBeenCalledTimes(1);
    expect(ctx.databaseService.fetchDatabases).toHaveBeenCalled();
    expect(result.current.attempt.status).toBe('failed');

    // Test retrying with request with updated fields, updates db and fetches new services.
    jest.clearAllMocks();
    await act(async () => {
      result.current.registerDatabase({
        ...newDatabaseReq,
        uri: 'diff-uri',
      });
    });
    act(() => jest.advanceTimersByTime(WAITING_TIMEOUT + 1));

    expect(ctx.databaseService.updateDatabase).toHaveBeenCalledTimes(1);
    expect(ctx.databaseService.createDatabase).not.toHaveBeenCalled();
    expect(ctx.databaseService.fetchDatabaseServices).toHaveBeenCalledTimes(1);
    expect(ctx.databaseService.fetchDatabases).toHaveBeenCalled();
    expect(result.current.attempt.status).toBe('failed');
  });
});
