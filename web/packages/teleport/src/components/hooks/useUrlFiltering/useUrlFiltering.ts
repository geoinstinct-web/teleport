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

import { useState } from 'react';
import { useLocation } from 'react-router';
import { SortType } from 'design/DataTable/types';

import history from 'teleport/services/history';
import { ResourceFilter, ResourceLabel } from 'teleport/services/agents';

import { encodeUrlQueryParams } from './encodeUrlQueryParams';

export interface UrlFilteringState {
  isSearchEmpty: boolean;
  params: ResourceFilter;
  setParams: (params: ResourceFilter) => void;
  pathname: string;
  setSort: (sort: SortType) => void;
  onLabelClick: (label: ResourceLabel) => void;
  replaceHistory: (path: string) => void;
  search: string;
}

export function useUrlFiltering(
  initialParams: Partial<ResourceFilter>
): UrlFilteringState {
  const { search, pathname } = useLocation();
  const [params, setParams] = useState<ResourceFilter>({
    ...initialParams,
    ...getResourceUrlQueryParams(search),
  });

  function replaceHistory(path: string) {
    history.replace(path);
  }

  function setSort(sort: SortType) {
    setParams({ ...params, sort });
  }

  const onLabelClick = (label: ResourceLabel) => {
    const queryAfterLabelClick = labelClickQuery(label, params);

    setParams({ ...params, search: '', query: queryAfterLabelClick });
    replaceHistory(
      encodeUrlQueryParams(
        pathname,
        queryAfterLabelClick,
        params.sort,
        params.kinds,
        true /*isAdvancedSearch*/,
        params.pinnedOnly
      )
    );
  };

  const isSearchEmpty = !params?.query && !params?.search;

  return {
    isSearchEmpty,
    params,
    setParams,
    pathname,
    setSort,
    onLabelClick,
    replaceHistory,
    search,
  };
}

export default function getResourceUrlQueryParams(
  searchPath: string
): ResourceFilter {
  const searchParams = new URLSearchParams(searchPath);
  const query = searchParams.get('query');
  const search = searchParams.get('search');
  const pinnedOnly = searchParams.get('pinnedOnly');
  const sort = searchParams.get('sort');
  const kinds = searchParams.has('kinds') ? searchParams.getAll('kinds') : null;

  const sortParam = sort ? sort.split(':') : null;

  // Converts the "fieldname:dir" format into {fieldName: "", dir: ""}
  const processedSortParam = sortParam
    ? ({
        fieldName: sortParam[0],
        dir: sortParam[1]?.toUpperCase() || 'ASC',
      } as SortType)
    : null;

  return {
    query,
    search,
    kinds,
    // Conditionally adds the sort field based on whether it exists or not
    ...(!!processedSortParam && { sort: processedSortParam }),
    // Conditionally adds the pinnedResources field based on whether its true or not
    ...(pinnedOnly === 'true' && { pinnedOnly: true }),
  };
}

function labelClickQuery(label: ResourceLabel, params: ResourceFilter) {
  const queryParts: string[] = [];

  // Add existing query
  if (params.query) {
    queryParts.push(params.query);
  }

  // If there is an existing simple search, convert it to predicate language and add it
  if (params.search) {
    queryParts.push(`search("${params.search}")`);
  }

  const labelQuery = `labels["${label.name}"] == "${label.value}"`;
  queryParts.push(labelQuery);

  const finalQuery = queryParts.join(' && ');

  return finalQuery;
}
