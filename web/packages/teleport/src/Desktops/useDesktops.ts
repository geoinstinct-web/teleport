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
import { FetchStatus } from 'design/DataTable/types';
import useAttempt from 'shared/hooks/useAttemptNext';

import Ctx from 'teleport/teleportContext';
import cfg from 'teleport/config';
import useStickyClusterId from 'teleport/useStickyClusterId';
import {
  useUrlFiltering,
  useServerSidePagination,
} from 'teleport/components/hooks';
import { openNewTab } from 'teleport/lib/util';
import { AgentResponse } from 'teleport/services/agents';

import type { Desktop } from 'teleport/services/desktops';

export default function useDesktops(ctx: Ctx) {
  const { attempt, setAttempt } = useAttempt('processing');
  const { clusterId, isLeafCluster } = useStickyClusterId();
  const canCreate = ctx.storeUser.getTokenAccess().create;
  const username = ctx.storeUser.state.username;
  const windowsLogins = ctx.storeUser.getWindowsLogins();
  const [fetchStatus, setFetchStatus] = useState<FetchStatus>('');
  const [results, setResults] = useState<AgentResponse<Desktop>>({
    agents: [],
    startKey: '',
    totalCount: 0,
  });

  const { params, search, ...filteringProps } = useUrlFiltering({
    fieldName: 'name',
    dir: 'ASC',
  });

  const { setStartKeys, pageSize, ...paginationProps } =
    useServerSidePagination({
      fetchFunc: ctx.desktopService.fetchDesktops,
      clusterId,
      params,
      results,
      setResults,
      setFetchStatus,
      setAttempt,
    });

  const getWindowsLoginOptions = (desktopName: string) =>
    makeOptions(clusterId, desktopName, windowsLogins);

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

  function fetchDesktops() {
    setAttempt({ status: 'processing' });
    ctx.desktopService
      .fetchDesktops(clusterId, { ...params, limit: pageSize })
      .then(res => {
        setResults(res);
        setFetchStatus(res.startKey ? '' : 'disabled');
        setStartKeys(['', res.startKey]);
        setAttempt({ status: 'success' });
      })
      .catch((err: Error) => {
        setAttempt({ status: 'failed', statusText: err.message });
        setResults({ ...results, agents: [], totalCount: 0 });
        setStartKeys(['']);
      });
  }

  return {
    attempt,
    username,
    clusterId,
    canCreate,
    isLeafCluster,
    getWindowsLoginOptions,
    openRemoteDesktopTab,
    results,
    fetchStatus,
    params,
    pageSize,
    ...filteringProps,
    ...paginationProps,
  };
}

function makeOptions(
  clusterId: string,
  desktopName = '',
  logins = [] as string[]
) {
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
