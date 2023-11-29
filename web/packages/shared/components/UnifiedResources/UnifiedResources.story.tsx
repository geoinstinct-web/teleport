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

import React, { useState } from 'react';

import { ButtonBorder } from 'design';

import { apps } from 'teleport/Apps/fixtures';
import { databases } from 'teleport/Databases/fixtures';
import { kubes } from 'teleport/Kubes/fixtures';
import { desktops } from 'teleport/Desktops/fixtures';
import { nodes } from 'teleport/Nodes/fixtures';

import { UrlResourcesParams } from 'teleport/config';
import { ResourcesResponse } from 'teleport/services/agents';

import {
  UnifiedResourcePreferences,
  DefaultTab,
  ViewMode,
} from 'shared/services/unifiedResourcePreferences';

import { UnifiedResources, useUnifiedResourcesFetch } from './UnifiedResources';
import {
  SharedUnifiedResource,
  UnifiedResourcesPinning,
  UnifiedResourcesQueryParams,
} from './types';

export default {
  title: 'Shared/UnifiedResources',
};

const aLotOfLabels = {
  ...databases[0],
  name: 'A DB with a lot of labels',
  labels: Array(300)
    .fill(0)
    .map((_, i) => ({ name: `label-${i}`, value: `value ${i}` })),
};

const allResources = [
  ...apps,
  aLotOfLabels,
  ...databases,
  ...kubes,
  ...desktops,
  ...nodes,
  ...apps,
  ...databases,
  ...kubes,
  ...desktops,
  ...nodes,
];

const story = ({
  fetchFunc,
  pinning = {
    kind: 'supported',
    getClusterPinnedResources: async () => [],
    updateClusterPinnedResources: async () => undefined,
  },
  params,
}: {
  fetchFunc: (
    params: UrlResourcesParams,
    signal: AbortSignal
  ) => Promise<ResourcesResponse<SharedUnifiedResource['resource']>>;
  pinning?: UnifiedResourcesPinning;
  params?: Partial<UnifiedResourcesQueryParams>;
}) => {
  const mergedParams: UnifiedResourcesQueryParams = {
    ...{
      sort: {
        dir: 'ASC',
        fieldName: 'name',
      },
    },
    ...params,
  };
  return () => {
    const [userPrefs, setUserPrefs] = useState<UnifiedResourcePreferences>({
      defaultTab: DefaultTab.DEFAULT_TAB_ALL,
      viewMode: ViewMode.VIEW_MODE_CARD,
    });
    const { fetch, attempt, resources } = useUnifiedResourcesFetch({
      fetchFunc,
    });
    return (
      <UnifiedResources
        availableKinds={[
          {
            kind: 'app',
            disabled: false,
          },
          {
            kind: 'db',
            disabled: false,
          },
          {
            kind: 'node',
            disabled: false,
          },
          {
            kind: 'kube_cluster',
            disabled: false,
          },
          {
            kind: 'windows_desktop',
            disabled: false,
          },
        ]}
        params={mergedParams}
        setParams={() => undefined}
        pinning={pinning}
        unifiedResourcePreferences={userPrefs}
        updateUnifiedResourcesPreferences={setUserPrefs}
        onLabelClick={() => undefined}
        NoResources={undefined}
        fetchResources={fetch}
        resourcesFetchAttempt={attempt}
        resources={resources.map(resource => ({
          resource,
          ui: {
            ActionButton: <ButtonBorder size="small">Connect</ButtonBorder>,
          },
        }))}
      />
    );
  };
};

export const Empty = story({
  fetchFunc: async () => ({ agents: [], startKey: '' }),
});

export const List = story({
  fetchFunc: async () => ({
    agents: allResources,
  }),
});

export const NoResults = story({
  fetchFunc: async () => ({
    agents: [],
  }),
  params: { search: 'my super long search query' },
});

export const Loading = story({
  fetchFunc: (_, signal) =>
    new Promise<never>((resolve, reject) => {
      signal.addEventListener('abort', reject);
    }),
});

export const LoadingAfterScrolling = story({
  fetchFunc: async params => {
    if (params.startKey === 'next-key') {
      return new Promise(() => {});
    }
    return {
      agents: allResources,
      startKey: 'next-key',
    };
  },
});

export const Errored = story({
  fetchFunc: async () => {
    throw new Error('Failed to fetch');
  },
});

export const ErroredAfterScrolling = story({
  fetchFunc: async params => {
    if (params.startKey === 'next-key') {
      throw new Error('Failed to fetch');
    }
    return { agents: allResources, startKey: 'next-key' };
  },
});

export const PinningNotSupported = story({
  fetchFunc: async () => {
    return { agents: allResources, startKey: 'next-key' };
  },
  pinning: { kind: 'not-supported' },
});

export const PinningHidden = story({
  fetchFunc: async () => {
    return { agents: allResources, startKey: 'next-key' };
  },
  pinning: { kind: 'hidden' },
});
