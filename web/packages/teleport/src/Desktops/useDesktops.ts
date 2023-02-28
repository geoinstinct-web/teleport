/*
Copyright 2021-2022 Gravitational, Inc.

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

import { useState, useEffect } from 'react';
import { useLocation } from 'react-router';
import { FetchStatus, SortType } from 'design/DataTable/types';
import useAttempt from 'shared/hooks/useAttemptNext';

import { LoginItem } from 'shared/components/MenuLogin';

import Ctx from 'teleport/teleportContext';
import cfg from 'teleport/config';
import useStickyClusterId from 'teleport/useStickyClusterId';
import history from 'teleport/services/history';
import { Desktop, DesktopsResponse } from 'teleport/services/desktops';
import getResourceUrlQueryParams, {
  ResourceUrlQueryParams,
} from 'teleport/getUrlQueryParams';
import { openNewTab } from 'teleport/lib/util';
import labelClick from 'teleport/labelClick';
import { AgentLabel } from 'teleport/services/agents';

export default function useDesktops(ctx: Ctx) {
  const { attempt, setAttempt } = useAttempt('processing');
  const { search, pathname } = useLocation();
  const [startKeys, setStartKeys] = useState<string[]>([]);
  const { clusterId, isLeafCluster } = useStickyClusterId();
  const canCreate = ctx.storeUser.getTokenAccess().create;
  const username = ctx.storeUser.state.username;
  const [fetchStatus, setFetchStatus] = useState<FetchStatus>('');
  const [params, setParams] = useState<ResourceUrlQueryParams>({
    sort: { fieldName: 'name', dir: 'ASC' },
    ...getResourceUrlQueryParams(search),
  });

  const isSearchEmpty = !params?.query && !params?.search;

  const [results, setResults] = useState<DesktopsResponse>({
    desktops: [],
    startKey: '',
    totalCount: 0,
  });

  const pageSize = 15;

  const from =
    results.totalCount > 0 ? (startKeys.length - 2) * pageSize + 1 : 0;
  const to = results.totalCount > 0 ? from + results.desktops.length - 1 : 0;

  const getWindowsLoginOptions = ({ name, logins }: Desktop) =>
    makeOptions(clusterId, name, logins);

  useEffect(() => {
    fetchDesktops();
  }, [clusterId, search]);

  const openRemoteDesktopTab = (username: string, desktopName: string) => {
    const url = cfg.getDesktopRoute({
      clusterId,
      desktopName,
      username,
    });

    openNewTab(url);
  };

  function replaceHistory(path: string) {
    history.replace(path);
  }

  function setSort(sort: SortType) {
    setParams({ ...params, sort });
  }

  function fetchDesktops() {
    setAttempt({ status: 'processing' });
    ctx.desktopService
      .fetchDesktops(clusterId, { ...params, limit: pageSize })
      .then(res => {
        setResults({
          desktops: res.agents,
          startKey: res.startKey,
          totalCount: res.totalCount,
        });
        setFetchStatus(res.startKey ? '' : 'disabled');
        setStartKeys(['', res.startKey]);
        setAttempt({ status: 'success' });
      })
      .catch((err: Error) => {
        setAttempt({ status: 'failed', statusText: err.message });
        setResults({ ...results, desktops: [], totalCount: 0 });
        setStartKeys(['']);
      });
  }

  const fetchNext = () => {
    setFetchStatus('loading');
    ctx.desktopService
      .fetchDesktops(clusterId, {
        ...params,
        limit: pageSize,
        startKey: results.startKey,
      })
      .then(res => {
        setResults({
          ...results,
          desktops: res.agents,
          startKey: res.startKey,
        });
        setFetchStatus(res.startKey ? '' : 'disabled');
        setStartKeys([...startKeys, res.startKey]);
      })
      .catch((err: Error) => {
        setAttempt({ status: 'failed', statusText: err.message });
      });
  };

  const fetchPrev = () => {
    setFetchStatus('loading');
    ctx.desktopService
      .fetchDesktops(clusterId, {
        ...params,
        limit: pageSize,
        startKey: startKeys[startKeys.length - 3],
      })
      .then(res => {
        const tempStartKeys = startKeys;
        tempStartKeys.pop();
        setStartKeys(tempStartKeys);
        setResults({
          ...results,
          desktops: res.agents,
          startKey: res.startKey,
        });
        setFetchStatus('');
      })
      .catch((err: Error) => {
        setAttempt({ status: 'failed', statusText: err.message });
      });
  };

  const onLabelClick = (label: AgentLabel) =>
    labelClick(label, params, setParams, pathname, replaceHistory);

  return {
    attempt,
    username,
    clusterId,
    canCreate,
    isLeafCluster,
    getWindowsLoginOptions,
    openRemoteDesktopTab,
    results,
    fetchNext,
    fetchPrev,
    pageSize,
    from,
    to,
    params,
    setParams,
    startKeys,
    setSort,
    pathname,
    replaceHistory,
    fetchStatus,
    isSearchEmpty,
    onLabelClick,
  };
}

function makeOptions(
  clusterId: string,
  desktopName = '',
  logins = [] as string[]
): LoginItem[] {
  return logins.map(username => {
    const url = cfg.getDesktopRoute({
      clusterId,
      desktopName,
      username,
    });

    return {
      login: username,
      url,
    };
  });
}

export type State = ReturnType<typeof useDesktops>;
