/**
 * Copyright 2023 Gravitational, Inc.
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

import { markdownCSS } from 'teleport/Assist/markdown';
import { MonospacedOutput } from 'teleport/Assist/shared/MonospacedOutput';
import { Markdown } from 'teleport/Assist/Conversation/Markdown';

interface CommandResultSummaryEntryProps {
  command: string;
  summary: string;
}

const Container = styled.div`
  border-radius: 10px;
  position: relative;
`;

const Title = styled.div`
  font-size: 15px;
  font-weight: 600;
  padding: 10px 15px;
`;

const Summary = styled.div`
  padding: 10px 15px 0 17px;

  ${markdownCSS}
`;

const Header = styled.div`
  display: flex;
  justify-content: space-between;
  padding-right: 20px;
`;

export function CommandResultSummaryEntry(
  props: CommandResultSummaryEntryProps
) {
  return (
    <Container>
      <Header>
        <Title>Summary of command execution</Title>
      </Header>

      <MonospacedOutput>{props.command}</MonospacedOutput>

      <Summary>
        <Markdown content={props.summary} />
      </Summary>
    </Container>
  );
}
