/*
Copyright 2019-2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import React, { useEffect, useRef } from 'react';
import { Box, Indicator, Flex } from 'design';

import styled from 'styled-components';

import {
  FeatureBox,
  FeatureHeader,
  FeatureHeaderTitle,
} from 'teleport/components/Layout';
import ErrorMessage from 'teleport/components/AgentErrorMessage';
import Empty, { EmptyStateInfo } from 'teleport/components/Empty';
import useTeleport from 'teleport/useTeleport';
import cfg from 'teleport/config';
import history from 'teleport/services/history/history';
import localStorage from 'teleport/services/localStorage';
import useStickyClusterId from 'teleport/useStickyClusterId';
import AgentButtonAdd from 'teleport/components/AgentButtonAdd';
import { useInfiniteScroll } from 'teleport/components/hooks/useInfiniteScroll';
import { SearchResource } from 'teleport/Discover/SelectResource';
import { useUrlFiltering } from 'teleport/components/hooks';

import { ResourceCard } from './ResourceCard';
import SearchPanel from './SearchPanel';
import { FilterPanel } from './FilterPanel';

export function Resources() {
  const { isLeafCluster } = useStickyClusterId();
  const enabled = localStorage.areUnifiedResourcesEnabled();
  const teleCtx = useTeleport();
  const canCreate = teleCtx.storeUser.getTokenAccess().create;
  const { clusterId } = useStickyClusterId();

  const filtering = useUrlFiltering({
    fieldName: 'name',
    dir: 'ASC',
  });
  const {
    params,
    search,
    setParams,
    replaceHistory,
    pathname,
    setSort,
    onLabelClick,
  } = filtering;

  const { fetchInitial, fetchedData, attempt, fetchMore } = useInfiniteScroll({
    fetchFunc: teleCtx.resourceService.fetchUnifiedResources,
    clusterId,
    params,
  });

  useEffect(() => {
    fetchInitial();
  }, [clusterId, search]);

  const infiniteScrollDetector = useRef(null);

  // Install the infinite scroll intersection observer.
  //
  // TODO(bl-nero): There's a known issue here. We need to have `fetchMore` in
  // the list of hook dependencies, because using a stale `fetchMore` closure
  // means we will fetch the same data over and over. However, as it's
  // implemented now, every time `fetchMore` changes, we reinstall the observer.
  // This is mitigated by `fetchMore` implementation, which doesn't spawn
  // another request before the first one finishes, but it's still a potential
  // for trouble in future. We need to decouple updating the `fetchMore` closure
  // and installing the observer.
  useEffect(() => {
    if (infiniteScrollDetector.current) {
      const observer = new IntersectionObserver(entries => {
        if (entries[0]?.isIntersecting) {
          fetchMore();
        }
      });
      observer.observe(infiniteScrollDetector.current);
      return () => observer.disconnect();
    }
  });

  if (!enabled) {
    history.replace(cfg.getNodesRoute(clusterId));
  }

  return (
    <FeatureBox>
      <FeatureHeader alignItems="center" justifyContent="space-between">
        <FeatureHeaderTitle>Resources</FeatureHeaderTitle>
        <Flex alignItems="center">
          <AgentButtonAdd
            agent={SearchResource.UNIFIED_RESOURCE}
            beginsWithVowel={false}
            isLeafCluster={isLeafCluster}
            canCreate={canCreate}
          />
        </Flex>
      </FeatureHeader>
      <SearchPanel
        params={params}
        setParams={setParams}
        pathname={pathname}
        replaceHistory={replaceHistory}
      />
      <FilterPanel
        params={params}
        setParams={setParams}
        setSort={setSort}
        pathname={pathname}
        replaceHistory={replaceHistory}
      />
      {attempt.status === 'failed' && (
        <ErrorMessage message={attempt.statusText} />
      )}
      <ResourcesContainer gap={2}>
        {fetchedData.agents.map((agent, i) => (
          <ResourceCard key={i} onLabelClick={onLabelClick} resource={agent} />
        ))}
      </ResourcesContainer>
      <div
        ref={infiniteScrollDetector}
        style={{
          visibility: attempt.status === 'processing' ? 'visible' : 'hidden',
        }}
      >
        {(attempt.status === 'processing' || fetchedData.startKey) && (
          <Box
            textAlign="center"
            style={{ visible: attempt.status === 'processing' }}
          >
            <Indicator />
          </Box>
        )}
      </div>
      {attempt.status === 'success' && fetchedData.agents.length === 0 && (
        <Empty
          clusterId={clusterId}
          canCreate={canCreate && !isLeafCluster}
          emptyStateInfo={emptyStateInfo}
        />
      )}
    </FeatureBox>
  );
}

const ResourcesContainer = styled(Flex)`
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
`;

const emptyStateInfo: EmptyStateInfo = {
  title: 'Add your first resource to Teleport',
  byline:
    'Connect SSH servers, Kubernetes clusters, Windows Desktops, Databases, Web apps and more from our integrations catalog.',
  readOnly: {
    title: 'No Resources Found',
    resource: 'resources',
  },
};
