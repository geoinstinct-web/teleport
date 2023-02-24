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

import React from 'react';
import Table, {
  Cell,
  ClickableLabelCell,
  UnclickableLabelCell,
} from 'design/DataTable';
import { SortType } from 'design/DataTable/types';

import { LoginItem, MenuLogin } from 'shared/components/MenuLogin';

import { Desktop } from 'teleport/services/desktops';
import { AgentLabel } from 'teleport/services/agents';
import ServersideSearchPanel from 'teleport/components/ServersideSearchPanel';
import { ResourceUrlQueryParams } from 'teleport/getUrlQueryParams';

function DesktopList(props: Props) {
  const {
    desktops = [],
    pageSize,
    onLoginMenuOpen,
    onLoginSelect,
    totalCount,
    fetchNext,
    fetchPrev,
    fetchStatus,
    from,
    to,
    params,
    setParams,
    startKeys,
    setSort,
    pathname,
    replaceHistory,
    onLabelClick,
    paginationUnsupported,
  } = props;

  function onDesktopSelect(
    e: React.MouseEvent,
    username: string,
    desktopName: string
  ) {
    e.preventDefault();
    onLoginSelect(username, desktopName);
  }

  if (paginationUnsupported) {
    // Return a client paging/searching table.
    return (
      <Table
        data={desktops}
        emptyText="No Desktops Found"
        isSearchable
        pagination={{ pageSize }}
        columns={[
          {
            key: 'addr',
            headerText: 'Address',
          },
          {
            key: 'name',
            headerText: 'Name',
            isSortable: true,
          },
          {
            key: 'labels',
            headerText: 'Labels',
            render: ({ labels }) => <UnclickableLabelCell labels={labels} />,
          },
          {
            altKey: 'login-cell',
            render: desktop =>
              renderLoginCell(desktop, onLoginMenuOpen, onDesktopSelect),
          },
        ]}
      />
    );
  }

  return (
    <Table
      data={desktops}
      columns={[
        {
          key: 'addr',
          headerText: 'Address',
        },
        {
          key: 'name',
          headerText: 'Name',
          isSortable: true,
        },
        {
          key: 'labels',
          headerText: 'Labels',
          render: ({ labels }) => (
            <ClickableLabelCell labels={labels} onClick={onLabelClick} />
          ),
        },
        {
          altKey: 'login-cell',
          render: desktop =>
            renderLoginCell(desktop, onLoginMenuOpen, onDesktopSelect),
        },
      ]}
      pagination={{
        pageSize,
      }}
      fetching={{
        onFetchNext: fetchNext,
        onFetchPrev: fetchPrev,
        fetchStatus,
      }}
      serversideProps={{
        sort: params.sort,
        setSort,
        startKeys,
        serversideSearchPanel: (
          <ServersideSearchPanel
            from={from}
            to={to}
            count={totalCount}
            params={params}
            setParams={setParams}
            pathname={pathname}
            replaceHistory={replaceHistory}
          />
        ),
      }}
      isSearchable
      emptyText="No Desktops Found"
    />
  );
}

function renderLoginCell(
  desktop: Desktop,
  onOpen: (desktop: Desktop) => LoginItem[],
  onSelect: (
    e: React.SyntheticEvent,
    username: string,
    desktopName: string
  ) => void
) {
  function handleOnOpen() {
    return onOpen(desktop);
  }

  function handleOnSelect(e: React.SyntheticEvent, login: string) {
    if (!onSelect) {
      return [];
    }

    return onSelect(e, login, desktop.name);
  }

  return (
    <Cell align="right">
      <MenuLogin
        getLoginItems={handleOnOpen}
        onSelect={handleOnSelect}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
        anchorOrigin={{
          vertical: 'center',
          horizontal: 'right',
        }}
      />
    </Cell>
  );
}

type Props = {
  desktops: Desktop[];
  pageSize: number;
  username: string;
  clusterId: string;
  onLoginMenuOpen(desktop: Desktop): LoginItem[];
  onLoginSelect(username: string, desktopName: string): void;
  fetchNext: () => void;
  fetchPrev: () => void;
  fetchStatus: any;
  from: number;
  to: number;
  totalCount: number;
  params: ResourceUrlQueryParams;
  setParams: (params: ResourceUrlQueryParams) => void;
  startKeys: string[];
  setSort: (sort: SortType) => void;
  pathname: string;
  replaceHistory: (path: string) => void;
  onLabelClick: (label: AgentLabel) => void;
  paginationUnsupported: boolean;
};

export default DesktopList;
