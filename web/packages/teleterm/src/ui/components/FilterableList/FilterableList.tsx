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

import React, { Fragment, ReactNode, useMemo, useState } from 'react';
import { Input } from 'design';
import styled from 'styled-components';

interface FilterableListProps<T> {
  items: T[];
  filterBy: keyof T;
  placeholder?: string;

  Node(props: { item: T; index: number }): ReactNode;

  onFilterChange?(filter: string): void;
}

export function FilterableList<T>(
  props: React.PropsWithChildren<FilterableListProps<T>>
) {
  const { items } = props;
  const [searchValue, setSearchValue] = useState<string>();

  const filteredItems = useMemo(
    () => filterItems(searchValue, items, props.filterBy),
    [items, searchValue]
  );

  return (
    <>
      <StyledInput
        role="searchbox"
        onChange={e => {
          const { value } = e.target;
          props.onFilterChange?.(value);
          setSearchValue(value);
        }}
        placeholder={props.placeholder}
        autoFocus={true}
      />
      <UnorderedList>
        {filteredItems.map((item, index) => (
          <Fragment key={index}>{props.Node({ item, index })}</Fragment>
        ))}
      </UnorderedList>
    </>
  );
}

function filterItems<T>(
  searchValue: string,
  items: T[],
  filterBy: keyof T
): T[] {
  const trimmed = searchValue?.trim();
  if (!trimmed) {
    return items;
  }
  return items.filter(item => item[filterBy].toString().includes(trimmed));
}

const UnorderedList = styled.ul`
  padding: 0;
  margin: 0;
`;

const StyledInput = styled(Input)`
  background-color: inherit;
  border-radius: 51px;
  margin-bottom: 8px;
  font-size: 14px;
  height: 34px;
`;
