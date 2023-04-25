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

import React, { ReactElement, useCallback } from 'react';
import styled from 'styled-components';
import {
  Box,
  ButtonBorder,
  ButtonPrimary,
  Flex,
  Label as DesignLabel,
  Text,
} from 'design';
import * as icons from 'design/Icon';
import { Highlight } from 'shared/components/Highlight';
import { hasFinished } from 'shared/hooks/useAsync';

import { useAppContext } from 'teleterm/ui/appContextProvider';
import {
  ResourceMatch,
  SearchResult,
  ResourceSearchResult,
  SearchResultDatabase,
  SearchResultKube,
  SearchResultServer,
  SearchResultCluster,
  SearchResultResourceType,
} from 'teleterm/ui/Search/searchResult';
import * as tsh from 'teleterm/services/tshd/types';
import * as uri from 'teleterm/ui/uri';
import { ResourceSearchError } from 'teleterm/ui/services/resources';

import { SearchAction } from '../actions';
import { useSearchContext } from '../SearchContext';

import { useActionAttempts } from './useActionAttempts';
import { getParameterPicker } from './pickers';
import { ResultList, NonInteractiveItem } from './ResultList';
import { PickerContainer } from './PickerContainer';

const MUTED_WHITE_COLOR = 'rgba(255, 255, 255, 0.72)';
// TODO(gzdunek): replace with theme color after theme update
const BRAND_PRIMARY_COLOR = '#9f85ff';

export function ActionPicker(props: { input: ReactElement }) {
  const ctx = useAppContext();
  const { clustersService, modalsService } = ctx;
  ctx.clustersService.useState();

  const {
    changeActivePicker,
    lockOpen,
    close,
    inputValue,
    resetInput,
    closeAndResetInput,
    filters,
    removeFilter,
  } = useSearchContext();
  const {
    filterActionsAttempt,
    resourceActionsAttempt,
    resourceSearchAttempt,
  } = useActionAttempts();
  const totalCountOfClusters = clustersService.getClusters().length;

  const getClusterName = useCallback(
    (resourceUri: uri.ClusterOrResourceUri) => {
      const clusterUri = uri.routing.ensureClusterUri(resourceUri);
      const cluster = clustersService.findCluster(clusterUri);

      return cluster ? cluster.name : uri.routing.parseClusterName(resourceUri);
    },
    [clustersService]
  );

  const getOptionalClusterName = useCallback(
    (resourceUri: uri.ClusterOrResourceUri) =>
      totalCountOfClusters === 1 ? undefined : getClusterName(resourceUri),
    [getClusterName, totalCountOfClusters]
  );

  const onPick = useCallback(
    (action: SearchAction) => {
      if (action.type === 'simple-action') {
        action.perform();
        // TODO: This logic probably should be encapsulated inside SearchContext, so that ActionPicker
        // and ParameterPicker can reuse it.
        //
        // Overall, the context should probably encapsulate more logic so that the components don't
        // have to worry about low-level stuff such as input state. Input state already lives in the
        // search context so it should be managed from there, if possible.
        if (action.preventAutoClose === true) {
          resetInput();
        } else {
          closeAndResetInput();
        }
      }
      if (action.type === 'parametrized-action') {
        changeActivePicker(getParameterPicker(action));
      }
    },
    [changeActivePicker, closeAndResetInput, resetInput]
  );

  const filterButtons = filters.map(s => {
    if (s.filter === 'resource-type') {
      return (
        <FilterButton
          key="resource-type"
          text={s.resourceType}
          onClick={() => removeFilter(s)}
        />
      );
    }
    if (s.filter === 'cluster') {
      const clusterName = getClusterName(s.clusterUri);
      return (
        <FilterButton
          key="cluster"
          text={clusterName}
          onClick={() => removeFilter(s)}
        />
      );
    }
  });

  function handleKeyDown(e: React.KeyboardEvent) {
    const { length } = filters;
    if (e.key === 'Backspace' && inputValue === '' && length) {
      removeFilter(filters[length - 1]);
    }
  }

  let ExtraTopComponent = null;
  // The order of attempts is important. Filter actions should be displayed before resource actions.
  const actionAttempts = [filterActionsAttempt, resourceActionsAttempt];
  const attemptsHaveFinishedWithoutActions = actionAttempts.every(
    a => hasFinished(a) && a.data.length === 0
  );
  const noRemainingFilters =
    filterActionsAttempt.status === 'success' &&
    filterActionsAttempt.data.length === 0;

  if (inputValue && attemptsHaveFinishedWithoutActions) {
    ExtraTopComponent = (
      <NoResultsItem clusters={clustersService.getRootClusters()} />
    );
  }

  if (!inputValue && noRemainingFilters) {
    ExtraTopComponent = <TypeToSearchItem />;
  }

  if (
    resourceSearchAttempt.status === 'success' &&
    resourceSearchAttempt.data.errors.length > 0
  ) {
    const showErrorsInModal = () => {
      lockOpen(
        new Promise(resolve => {
          modalsService.openRegularDialog({
            kind: 'resource-search-errors',
            errors: resourceSearchAttempt.data.errors,
            getClusterName,
            onCancel: () => resolve(undefined),
          });
        })
      );
    };

    ExtraTopComponent = (
      <>
        <ResourceSearchErrorsItem
          errors={resourceSearchAttempt.data.errors}
          getClusterName={getClusterName}
          onShowDetails={showErrorsInModal}
        />
        {ExtraTopComponent}
      </>
    );
  }

  return (
    <PickerContainer>
      <InputWrapper onKeyDown={handleKeyDown}>
        {filterButtons}
        {props.input}
      </InputWrapper>
      <ResultList<SearchAction>
        attempts={actionAttempts}
        onPick={onPick}
        onBack={close}
        render={item => {
          const Component = ComponentMap[item.searchResult.kind];
          return {
            key:
              item.searchResult.kind !== 'resource-type-filter'
                ? item.searchResult.resource.uri
                : item.searchResult.resource,
            Component: (
              <Component
                searchResult={item.searchResult}
                getOptionalClusterName={getOptionalClusterName}
              />
            ),
          };
        }}
        ExtraTopComponent={ExtraTopComponent}
      />
    </PickerContainer>
  );
}

export const InputWrapper = styled(Flex).attrs({ px: 2 })`
  row-gap: ${props => props.theme.space[2]}px;
  column-gap: ${props => props.theme.space[2]}px;
  align-items: center;
  flex-wrap: wrap;
  // account for border
  padding-block: calc(${props => props.theme.space[2]}px - 1px);
  // input height without border
  min-height: 38px;

  & > input {
    height: unset;
    padding-inline: 0;
    flex: 1;
  }
`;

export const ComponentMap: Record<
  SearchResult['kind'],
  React.FC<SearchResultItem<SearchResult>>
> = {
  server: ServerItem,
  kube: KubeItem,
  database: DatabaseItem,
  'cluster-filter': ClusterFilterItem,
  'resource-type-filter': ResourceTypeFilterItem,
};

type SearchResultItem<T> = {
  searchResult: T;
  getOptionalClusterName: (uri: uri.ResourceUri) => string;
};

function Item(
  props: React.PropsWithChildren<{
    Icon: React.ComponentType<{
      color: string;
      fontSize: string;
      lineHeight: string;
    }>;
    iconColor: string;
  }>
) {
  return (
    <Flex alignItems="flex-start" gap={2}>
      {/* lineHeight of the icon needs to match the line height of the first row of props.children */}
      <props.Icon color={props.iconColor} fontSize="20px" lineHeight="24px" />
      <Flex flexDirection="column" gap={1} minWidth={0} flex="1">
        {props.children}
      </Flex>
    </Flex>
  );
}

function ClusterFilterItem(props: SearchResultItem<SearchResultCluster>) {
  return (
    <Item Icon={icons.Lan} iconColor={MUTED_WHITE_COLOR}>
      <Text typography="body1">
        Search only in{' '}
        <strong>
          <Highlight
            text={props.searchResult.resource.name}
            keywords={[props.searchResult.nameMatch]}
          />
        </strong>
      </Text>
    </Item>
  );
}

const resourceIcons: Record<
  SearchResultResourceType['resource'],
  React.ComponentType<{
    color: string;
    fontSize: string;
    lineHeight: string;
  }>
> = {
  kubes: icons.Kubernetes,
  servers: icons.Server,
  databases: icons.Database,
};

function ResourceTypeFilterItem(
  props: SearchResultItem<SearchResultResourceType>
) {
  return (
    <Item
      Icon={resourceIcons[props.searchResult.resource]}
      iconColor={MUTED_WHITE_COLOR}
    >
      <Text typography="body1">
        Search only for{' '}
        <strong>
          <Highlight
            text={props.searchResult.resource}
            keywords={[props.searchResult.nameMatch]}
          />
        </strong>
      </Text>
    </Item>
  );
}

export function ServerItem(props: SearchResultItem<SearchResultServer>) {
  const { searchResult } = props;
  const server = searchResult.resource;
  const hasUuidMatches = searchResult.resourceMatches.some(
    match => match.field === 'name'
  );

  return (
    <Item Icon={icons.Server} iconColor={BRAND_PRIMARY_COLOR}>
      <Flex
        justifyContent="space-between"
        alignItems="center"
        flexWrap="wrap"
        gap={1}
      >
        <Text typography="body1">
          Connect over SSH to{' '}
          <strong>
            <HighlightField field="hostname" searchResult={searchResult} />
          </strong>
        </Text>
        <Box ml="auto">
          <Text typography="body2" fontSize={0}>
            {props.getOptionalClusterName(server.uri)}
          </Text>
        </Box>
      </Flex>

      <Labels searchResult={searchResult}>
        <ResourceFields>
          {server.tunnel ? (
            <span title="This node is connected to the cluster through a reverse tunnel">
              ↵ tunnel
            </span>
          ) : (
            <span>
              <HighlightField field="addr" searchResult={searchResult} />
            </span>
          )}

          {hasUuidMatches && (
            <span>
              UUID:{' '}
              <HighlightField field={'name'} searchResult={searchResult} />
            </span>
          )}
        </ResourceFields>
      </Labels>
    </Item>
  );
}

export function DatabaseItem(props: SearchResultItem<SearchResultDatabase>) {
  const { searchResult } = props;
  const db = searchResult.resource;

  const $resourceFields = (
    <ResourceFields>
      <span
        css={`
          flex-shrink: 0;
        `}
      >
        <HighlightField field="type" searchResult={searchResult} />
        /
        <HighlightField field="protocol" searchResult={searchResult} />
      </span>
      {db.desc && (
        <span
          css={`
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
          `}
        >
          <HighlightField field="desc" searchResult={searchResult} />
        </span>
      )}
    </ResourceFields>
  );

  return (
    <Item Icon={icons.Database} iconColor={BRAND_PRIMARY_COLOR}>
      <Flex
        justifyContent="space-between"
        alignItems="center"
        flexWrap="wrap"
        gap={1}
      >
        <Text typography="body1">
          Set up a db connection for{' '}
          <strong>
            <HighlightField field="name" searchResult={searchResult} />
          </strong>
        </Text>
        <Box ml="auto">
          <Text typography="body2" fontSize={0}>
            {props.getOptionalClusterName(db.uri)}
          </Text>
        </Box>
      </Flex>

      {/* If the description is long, put the resource fields on a separate line.
          Otherwise show the resource fields and the labels together in a single line.
       */}
      {db.desc.length >= 30 ? (
        <>
          {$resourceFields}
          <Labels searchResult={searchResult} />
        </>
      ) : (
        <Labels searchResult={searchResult}>{$resourceFields}</Labels>
      )}
    </Item>
  );
}

export function KubeItem(props: SearchResultItem<SearchResultKube>) {
  const { searchResult } = props;

  return (
    <Item Icon={icons.Kubernetes} iconColor={BRAND_PRIMARY_COLOR}>
      <Flex
        justifyContent="space-between"
        alignItems="center"
        flexWrap="wrap"
        gap={1}
      >
        <Text typography="body1">
          Log in to Kubernetes cluster{' '}
          <strong>
            <HighlightField field="name" searchResult={searchResult} />
          </strong>
        </Text>
        <Box ml="auto">
          <Text typography="body2" fontSize={0}>
            {props.getOptionalClusterName(searchResult.resource.uri)}
          </Text>
        </Box>
      </Flex>

      <Labels searchResult={searchResult} />
    </Item>
  );
}

export function NoResultsItem(props: { clusters: tsh.Cluster[] }) {
  const excludedClustersCopy = getExcludedClustersCopy(props.clusters);
  return (
    <NonInteractiveItem>
      <Item Icon={icons.Info} iconColor={MUTED_WHITE_COLOR}>
        <Text typography="body1">No matching results found.</Text>
        {excludedClustersCopy && (
          <Text typography="body2">{excludedClustersCopy}</Text>
        )}
      </Item>
    </NonInteractiveItem>
  );
}

export function TypeToSearchItem() {
  return (
    <NonInteractiveItem>
      <Text typography="body1" color="text.primary">
        Type something to search.
      </Text>
    </NonInteractiveItem>
  );
}

export function ResourceSearchErrorsItem(props: {
  errors: ResourceSearchError[];
  getClusterName: (resourceUri: uri.ClusterOrResourceUri) => string;
  onShowDetails: () => void;
}) {
  const { errors, getClusterName } = props;

  let shortDescription: string;

  if (errors.length === 1) {
    const firstErrorMessage = errors[0].messageWithClusterName(getClusterName);
    shortDescription = `${firstErrorMessage}.`;
  } else {
    const allErrorMessages = errors
      .map(err =>
        err.messageWithClusterName(getClusterName, { capitalize: false })
      )
      .join(', ');
    shortDescription = `Ran into ${errors.length} errors: ${allErrorMessages}.`;
  }

  return (
    <NonInteractiveItem>
      <Item Icon={icons.Warning} iconColor="#f3af3d">
        <Text typography="body1">
          Some of the search results are incomplete.
        </Text>

        <Flex gap={2} justifyContent="space-between" alignItems="baseline">
          <span
            css={`
              text-overflow: ellipsis;
              white-space: nowrap;
              overflow: hidden;
            `}
          >
            <Text typography="body2">{shortDescription}</Text>
          </span>

          <ButtonBorder
            type="button"
            size="small"
            css={`
              flex-shrink: 0;
            `}
            onClick={props.onShowDetails}
          >
            Show details
          </ButtonBorder>
        </Flex>
      </Item>
    </NonInteractiveItem>
  );
}

function getExcludedClustersCopy(allClusters: tsh.Cluster[]): string {
  // TODO(ravicious): Include leaf clusters.
  const excludedClusters = allClusters.filter(c => !c.connected);
  const excludedClustersString = excludedClusters.map(c => c.name).join(', ');
  if (excludedClusters.length === 0) {
    return '';
  }
  if (excludedClusters.length === 1) {
    return `The cluster ${excludedClustersString} was excluded from the search because you are not logged in to it.`;
  }
  return `Clusters ${excludedClustersString} were excluded from the search because you are not logged in to them.`;
}

function Labels(
  props: React.PropsWithChildren<{
    searchResult: ResourceSearchResult;
  }>
) {
  const { searchResult } = props;

  // Label name to score.
  const scoreMap: Map<string, number> = new Map();
  searchResult.labelMatches.forEach(match => {
    const currentScore = scoreMap.get(match.labelName) || 0;
    scoreMap.set(match.labelName, currentScore + match.score);
  });

  const sortedLabelsList = [...searchResult.resource.labelsList];
  sortedLabelsList.sort(
    (a, b) =>
      // Highest score first.
      (scoreMap.get(b.name) || 0) - (scoreMap.get(a.name) || 0)
  );

  return (
    <LabelsFlex>
      {props.children}
      {sortedLabelsList.map(label => (
        <Label
          key={label.name + label.value}
          searchResult={searchResult}
          label={label}
        />
      ))}
    </LabelsFlex>
  );
}

const LabelsFlex = styled(Flex).attrs({ gap: 1 })`
  overflow-x: hidden;
  flex-wrap: nowrap;
  align-items: baseline;

  // Make the children not shrink, otherwise they would shrink in attempt to render all labels in
  // the same row.
  & > * {
    flex-shrink: 0;
  }
`;

const ResourceFields = styled(Flex).attrs({ gap: 1 })`
  color: ${props => props.theme.colors.text.primary};
  font-size: ${props => props.theme.fontSizes[0]}px;
`;

function Label(props: {
  searchResult: ResourceSearchResult;
  label: tsh.Label;
}) {
  const { searchResult: item, label } = props;
  const labelMatches = item.labelMatches.filter(
    match => match.labelName == label.name
  );
  const nameMatches = labelMatches
    .filter(match => match.kind === 'label-name')
    .map(match => match.searchTerm);
  const valueMatches = labelMatches
    .filter(match => match.kind === 'label-value')
    .map(match => match.searchTerm);

  return (
    <DesignLabel
      key={label.name}
      kind="secondary"
      title={`${label.name}: ${label.value}`}
    >
      <Highlight text={label.name} keywords={nameMatches} />:{' '}
      <Highlight text={label.value} keywords={valueMatches} />
    </DesignLabel>
  );
}

function HighlightField(props: {
  searchResult: ResourceSearchResult;
  field: ResourceMatch<ResourceSearchResult['kind']>['field'];
}) {
  // `as` used as a workaround for a TypeScript issue.
  // https://github.com/microsoft/TypeScript/issues/33591
  const keywords = (
    props.searchResult.resourceMatches as ResourceMatch<
      ResourceSearchResult['kind']
    >[]
  )
    .filter(match => match.field === props.field)
    .map(match => match.searchTerm);

  return (
    <Highlight
      text={props.searchResult.resource[props.field]}
      keywords={keywords}
    />
  );
}

function FilterButton(props: { text: string; onClick(): void }) {
  return (
    <ButtonPrimary
      px={2}
      size="small"
      title={props.text}
      onClick={props.onClick}
    >
      <span
        css={`
          max-width: calc(${props => props.theme.space[9]}px * 2);
          text-overflow: ellipsis;
          white-space: nowrap;
          overflow: hidden;
        `}
      >
        {props.text}
      </span>
    </ButtonPrimary>
  );
}
