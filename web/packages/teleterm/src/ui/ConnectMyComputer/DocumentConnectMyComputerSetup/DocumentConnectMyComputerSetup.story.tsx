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

import React, { useEffect, useRef, useLayoutEffect } from 'react';

import { MockAppContextProvider } from 'teleterm/ui/fixtures/MockAppContextProvider';
import { MockAppContext } from 'teleterm/ui/fixtures/mocks';
import { MockWorkspaceContextProvider } from 'teleterm/ui/fixtures/MockWorkspaceContextProvider';
import {
  makeRootCluster,
  makeServer,
} from 'teleterm/services/tshd/testHelpers';
import { IAppContext } from 'teleterm/ui/types';
import { Cluster } from 'teleterm/services/tshd/types';
import { ResourcesContextProvider } from 'teleterm/ui/DocumentCluster/resourcesContext';

import { ConnectMyComputerContextProvider } from '../connectMyComputerContext';

import { DocumentConnectMyComputerSetup } from './DocumentConnectMyComputerSetup';

export default {
  title: 'Teleterm/ConnectMyComputer/Setup',
};

export function Default() {
  const cluster = makeRootCluster();
  const appContext = new MockAppContext({ appVersion: cluster.proxyVersion });
  appContext.connectMyComputerService.waitForNodeToJoin = async () =>
    makeServer();
  return (
    <ShowState
      cluster={cluster}
      appContext={appContext}
      clickStartSetup={false}
    />
  );
}

export function Success() {
  const cluster = makeRootCluster();
  const appContext = new MockAppContext({ appVersion: cluster.proxyVersion });
  appContext.connectMyComputerService.waitForNodeToJoin = async () =>
    makeServer();
  // Report the agent as running so that the autostart behavior doesn't kick in and attempt to start
  // the agent over and over.
  appContext.mainProcessClient.subscribeToAgentUpdate = (
    rootClusterUri,
    callback
  ) => {
    callback({ status: 'running' });

    return { cleanup: () => {} };
  };
  return <ShowState cluster={cluster} appContext={appContext} />;
}

export function Errored() {
  const cluster = makeRootCluster();
  const appContext = new MockAppContext({ appVersion: cluster.proxyVersion });
  appContext.connectMyComputerService.createAgentConfigFile = () => {
    throw new Error('Failed to write file, no permissions.');
  };
  return <ShowState cluster={cluster} appContext={appContext} />;
}

export function InProgress() {
  const cluster = makeRootCluster();
  const appContext = new MockAppContext({ appVersion: cluster.proxyVersion });
  const ref = useRef(new AbortController());

  useEffect(() => {
    return () => ref.current.abort();
  }, []);

  appContext.connectMyComputerService.downloadAgent = () =>
    new Promise(resolve => {
      ref.current.signal.addEventListener('abort', () => resolve(undefined));
    });

  return <ShowState cluster={cluster} appContext={appContext} />;
}

export function AgentVersionTooNew() {
  const cluster = makeRootCluster({ proxyVersion: '16.3.0' });
  const appContext = new MockAppContext({ appVersion: '17.0.0' });

  return (
    <ShowState
      cluster={cluster}
      appContext={appContext}
      clickStartSetup={false}
    />
  );
}

export function AgentVersionTooOld() {
  const cluster = makeRootCluster({ proxyVersion: '16.3.0' });
  const appContext = new MockAppContext({ appVersion: '14.1.0' });
  return (
    <ShowState
      cluster={cluster}
      appContext={appContext}
      clickStartSetup={false}
    />
  );
}

function ShowState({
  cluster,
  appContext,
  clickStartSetup = true,
}: {
  cluster: Cluster;
  appContext: IAppContext;
  clickStartSetup?: boolean;
}) {
  if (!appContext.clustersService.state.clusters.get(cluster.uri)) {
    appContext.clustersService.state.clusters.set(cluster.uri, cluster);
    appContext.workspacesService.setState(draftState => {
      draftState.rootClusterUri = cluster.uri;
      draftState.workspaces[cluster.uri] = {
        localClusterUri: cluster.uri,
        documents: [],
        location: undefined,
        accessRequests: undefined,
      };
    });
  }

  useLayoutEffect(() => {
    if (clickStartSetup) {
      (
        document.querySelector('[data-testid=start-setup]') as HTMLButtonElement
      )?.click();
    }
  }, [clickStartSetup]);

  return (
    <MockAppContextProvider appContext={appContext}>
      <MockWorkspaceContextProvider rootClusterUri={cluster.uri}>
        <ResourcesContextProvider>
          <ConnectMyComputerContextProvider rootClusterUri={cluster.uri}>
            <DocumentConnectMyComputerSetup />
          </ConnectMyComputerContextProvider>
        </ResourcesContextProvider>
      </MockWorkspaceContextProvider>
    </MockAppContextProvider>
  );
}
