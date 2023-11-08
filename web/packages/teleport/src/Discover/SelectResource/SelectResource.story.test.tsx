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
import { render } from 'design/utils/testing';
import { UserAgent } from 'design/platform';

import { mockUserContextProviderWith } from 'teleport/User/testHelpers/mockUserContextWith';
import { makeTestUserContext } from 'teleport/User/testHelpers/makeTestUserContext';

import {
  AllAccess,
  NoAccess,
  PartialAccess,
  InitRouteEntryServer,
} from './SelectResource.story';

beforeEach(() => {
  jest.restoreAllMocks();
  jest
    .spyOn(window.navigator, 'userAgent', 'get')
    .mockReturnValue(UserAgent.macOS);
});

test('render with all access', async () => {
  mockUserContextProviderWith(makeTestUserContext());
  const { container } = render(<AllAccess />);
  expect(container.firstChild).toMatchSnapshot();
});

test('render with no access', async () => {
  mockUserContextProviderWith(makeTestUserContext());
  const { container } = render(<NoAccess />);
  expect(container.firstChild).toMatchSnapshot();
});

test('render with partial access', async () => {
  mockUserContextProviderWith(makeTestUserContext());
  const { container } = render(<PartialAccess />);
  expect(container.firstChild).toMatchSnapshot();
});

test('render with URL loc state set to "server"', async () => {
  mockUserContextProviderWith(makeTestUserContext());
  const { container } = render(<InitRouteEntryServer />);
  expect(container.firstChild).toMatchSnapshot();
});
