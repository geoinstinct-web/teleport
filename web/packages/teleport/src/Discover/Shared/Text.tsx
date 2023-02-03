/**
 * Copyright 2022 Gravitational, Inc.
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

import { Box, Text } from 'design';

import styled from 'styled-components';

export const TextIcon = styled(Text)`
  display: flex;
  align-items: center;

  .icon {
    margin-right: 8px;
  }
`;

export const TextBox = styled(Box)`
  width: 100%;
  margin-top: 32px;
  border-radius: 8px;
  background-color: ${p => p.theme.colors.primary.light};
  padding: 24px;
`;
