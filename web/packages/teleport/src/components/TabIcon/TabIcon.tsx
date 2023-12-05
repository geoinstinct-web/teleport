/**
 * Copyright 2020 Gravitational, Inc.
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

import React from 'react';
import styled from 'styled-components';
import { Text } from 'design';

export default function TabIcon({ Icon, ...props }: Props) {
  return (
    <StyledTab
      ml="4"
      typography="h5"
      key={props.title}
      active={props.active}
      onClick={props.onClick}
    >
      <Icon size="medium" />
      {props.title}
    </StyledTab>
  );
}

type Props = {
  active: boolean;
  onClick(): void;
  title: string;
  Icon: (any) => JSX.Element;
};

const StyledTab = styled(Text)<{ active: boolean }>`
  align-items: center;
  display: flex;
  padding: 4px 8px;
  cursor: pointer;
  border-bottom: 4px solid transparent;

  svg {
    margin-right: 8px;
  }

  ${({ active, theme }) =>
    active &&
    `
    font-weight: 500;
    border-bottom: 4px solid ${theme.colors.brand};
  `}
`;
