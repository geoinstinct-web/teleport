/**
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import React from 'react';
import styled from 'styled-components';
import { Flex, Box } from 'design';
import Table from 'design/DataTable';
import { FetchStatus } from 'design/DataTable/types';

import {
  DisableableCell as Cell,
  RadioCell,
  Labels,
  labelMatcher,
} from 'teleport/Discover/Shared';

import { CheckedEksCluster } from './EnrollEksCluster';

type Props = {
  items: CheckedEksCluster[];
  fetchStatus: FetchStatus;
  fetchNextPage(): void;

  onSelectCluster(item: CheckedEksCluster): void;
  selectedCluster?: CheckedEksCluster;
};

const disabledText = `This EKS cluster is already enrolled`;

export const ClustersList = ({
  items = [],
  fetchStatus = '',
  fetchNextPage,
  onSelectCluster,
  selectedCluster,
}: Props) => {
  return (
    <Table
      data={items}
      columns={[
        {
          altKey: 'radio-select',
          headerText: 'Select',
          render: item => {
            const isChecked = item.name === selectedCluster?.name;
            return (
              <RadioCell<CheckedEksCluster>
                disabledText={disabledText}
                item={item}
                key={`${item.name}${item.region}`}
                isChecked={isChecked}
                onChange={onSelectCluster}
                disabled={item.kubeServerExists}
                value={item.name}
              />
            );
          },
        },
        {
          key: 'name',
          headerText: 'Name',
          render: ({ name, kubeServerExists }) => (
            <Cell disabledText={disabledText} disabled={kubeServerExists}>
              {name}
            </Cell>
          ),
        },
        {
          key: 'labels',
          headerText: 'Labels',
          render: ({ labels, kubeServerExists }) => (
            <Cell disabledText={disabledText} disabled={kubeServerExists}>
              <Labels labels={labels} />
            </Cell>
          ),
        },
        {
          key: 'status',
          headerText: 'Status',
          render: item => <StatusCell item={item} />,
        },
      ]}
      emptyText="No Results"
      customSearchMatchers={[labelMatcher]}
      pagination={{ pageSize: 10 }}
      fetching={{ onFetchMore: fetchNextPage, fetchStatus }}
      isSearchable
    />
  );
};

const StatusCell = ({ item }: { item: CheckedEksCluster }) => {
  const status = getStatus(item);

  return (
    <Cell disabledText={disabledText} disabled={item.kubeServerExists}>
      <Flex alignItems="center">
        <StatusLight status={status} />
        {item.status}
      </Flex>
    </Cell>
  );
};

enum Status {
  Success,
  Warning,
  Error,
}

function getStatus(item: CheckedEksCluster) {
  switch (item.status.toLowerCase()) {
    case 'active':
      return Status.Success;

    case 'failed':
    case 'deleting':
      return Status.Error;
  }
}

// TODO(lisa): copy from IntegrationList.tsx
// move to common file for both files.
const StatusLight = styled(Box)`
  border-radius: 50%;
  margin-right: 6px;
  width: 8px;
  height: 8px;
  background-color: ${({ status, theme }) => {
    if (status === Status.Success) {
      return theme.colors.success;
    }
    if (status === Status.Error) {
      return theme.colors.error.main;
    }
    if (status === Status.Warning) {
      return theme.colors.warning;
    }
    return theme.colors.grey[300]; // Unknown
  }};
`;
