/**
 * Copyright 2023 Gravitational, Inc.
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
import { render, screen, fireEvent, act } from 'design/utils/testing';

import { ContextProvider } from 'teleport';
import {
  AwsRdsDatabase,
  Integration,
  IntegrationKind,
  IntegrationStatusCode,
  Regions,
  integrationService,
} from 'teleport/services/integrations';
import { createTeleportContext } from 'teleport/mocks/contexts';
import cfg from 'teleport/config';
import TeleportContext from 'teleport/teleportContext';
import {
  DbMeta,
  DiscoverContextState,
  DiscoverProvider,
} from 'teleport/Discover/useDiscover';
import {
  DatabaseEngine,
  DatabaseLocation,
} from 'teleport/Discover/SelectResource';
import { FeaturesContextProvider } from 'teleport/FeaturesContext';
import { PingTeleportProvider } from 'teleport/Discover/Shared/PingTeleportContext';
import { ResourceKind } from 'teleport/Discover/Shared';
import { SHOW_HINT_TIMEOUT } from 'teleport/Discover/Shared/useShowHint';

import { AutoDeploy } from './AutoDeploy';

const mockDbLabels = [{ name: 'env', value: 'prod' }];

const integrationName = 'aws-oidc-integration';
const region: Regions = 'us-east-2';
const awsoidcRoleArn = 'role-arn';

const mockAwsRdsDb: AwsRdsDatabase = {
  engine: 'postgres',
  name: 'rds-1',
  uri: 'endpoint-1',
  status: 'available',
  labels: mockDbLabels,
  accountId: 'account-id-1',
  resourceId: 'resource-id-1',
  region: region,
  subnets: ['subnet1', 'subnet2'],
};

const mocKIntegration: Integration = {
  kind: IntegrationKind.AwsOidc,
  name: integrationName,
  resourceType: 'integration',
  spec: {
    roleArn: `doncare/${awsoidcRoleArn}`,
  },
  statusCode: IntegrationStatusCode.Running,
};

describe('test AutoDeploy.tsx', () => {
  jest.useFakeTimers();

  const teleCtx = createTeleportContext();
  const discoverCtx: DiscoverContextState = {
    agentMeta: {
      resourceName: 'db1',
      integration: mocKIntegration,
      selectedAwsRdsDb: mockAwsRdsDb,
      agentMatcherLabels: mockDbLabels,
    } as DbMeta,
    currentStep: 0,
    nextStep: jest.fn(x => x),
    prevStep: () => null,
    onSelectResource: () => null,
    resourceSpec: {
      dbMeta: {
        location: DatabaseLocation.Aws,
        engine: DatabaseEngine.AuroraMysql,
      },
    } as any,
    viewConfig: null,
    exitFlow: null,
    indexedViews: [],
    setResourceSpec: () => null,
    updateAgentMeta: jest.fn(x => x),
    emitErrorEvent: () => null,
    emitEvent: () => null,
    eventState: null,
  };

  beforeEach(() => {
    jest.spyOn(integrationService, 'deployAwsOidcService').mockResolvedValue({
      clusterArn: 'cluster-arn',
      serviceArn: 'service-arn',
      taskDefinitionArn: 'task-definition',
      serviceDashboardUrl: 'dashboard-url',
    });

    jest.spyOn(teleCtx.databaseService, 'fetchDatabases').mockResolvedValue({
      agents: [],
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  test('init: labels are rendered, command is not rendered yet', () => {
    renderAutoDeploy(teleCtx, discoverCtx);

    expect(screen.getByText(/env: prod/i)).toBeInTheDocument();
    expect(screen.queryByText(/copy\/paste/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/curl/i)).not.toBeInTheDocument();
  });

  test('clicking button renders command', () => {
    renderAutoDeploy(teleCtx, discoverCtx);

    fireEvent.click(screen.getByText(/generate command/i));

    expect(screen.getByText(/copy\/paste/i)).toBeInTheDocument();
    expect(
      screen.getByText(
        /integrationName=aws-oidc-integration&awsRegion=us-east-2&role=role-arn&taskRole=TeleportDatabaseAccess/i
      )
    ).toBeInTheDocument();
  });

  test('invalid role name', () => {
    renderAutoDeploy(teleCtx, discoverCtx);

    expect(
      screen.queryByText(/name can only contain/i)
    ).not.toBeInTheDocument();

    // add invalid characters in role name
    const inputEl = screen.getByPlaceholderText(/TeleportDatabaseAccess/i);
    fireEvent.change(inputEl, { target: { value: 'invalidname!@#!$!%' } });

    fireEvent.click(screen.getByText(/generate command/i));
    expect(screen.getByText(/name can only contain/i)).toBeInTheDocument();

    // change back to valid name
    fireEvent.change(inputEl, { target: { value: 'llama' } });
    expect(
      screen.queryByText(/name can only contain/i)
    ).not.toBeInTheDocument();
  });

  test('deploy hint states', async () => {
    renderAutoDeploy(teleCtx, discoverCtx);

    fireEvent.click(screen.getByText(/Deploy Teleport Service/i));

    await screen.findByText(
      /Teleport is currently deploying a Database Service/i
    );

    act(() => jest.advanceTimersByTime(SHOW_HINT_TIMEOUT + 1));

    expect(
      screen.getByText(
        /We're still in the process of creating your Database Service/i
      )
    ).toBeInTheDocument();
  });
});

const TEST_PING_INTERVAL = 1000 * 60 * 5; // 5 minutes

function renderAutoDeploy(
  ctx: TeleportContext,
  discoverCtx: DiscoverContextState
) {
  return render(
    <MemoryRouter
      initialEntries={[
        { pathname: cfg.routes.discover, state: { entity: 'database' } },
      ]}
    >
      <ContextProvider ctx={ctx}>
        <FeaturesContextProvider value={[]}>
          <DiscoverProvider mockCtx={discoverCtx}>
            <PingTeleportProvider
              interval={TEST_PING_INTERVAL}
              resourceKind={ResourceKind.Database}
            >
              <AutoDeploy />
            </PingTeleportProvider>
          </DiscoverProvider>
        </FeaturesContextProvider>
      </ContextProvider>
    </MemoryRouter>
  );
}
