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

import React from 'react';
import { render, screen, waitFor } from 'design/utils/testing';
import { makeSuccessAttempt } from 'shared/hooks/useAsync';

import { MockAppContext } from 'teleterm/ui/fixtures/mocks';
import { MockAppContextProvider } from 'teleterm/ui/fixtures/MockAppContextProvider';
import { ResourceSearchError } from 'teleterm/ui/services/resources';
import ModalsHost from 'teleterm/ui/ModalsHost';

import * as pickers from './pickers/pickers';
import * as useActionAttempts from './pickers/useActionAttempts';
import * as SearchContext from './SearchContext';

import { SearchBarConnected } from './SearchBar';

beforeEach(() => {
  jest.restoreAllMocks();
});

it('does not display empty results copy after selecting two filters', () => {
  const appContext = new MockAppContext();
  appContext.workspacesService.setState(draft => {
    draft.rootClusterUri = '/clusters/foo';
  });

  const mockActionAttempts = {
    filterActionsAttempt: makeSuccessAttempt([]),
    resourceActionsAttempt: makeSuccessAttempt([]),
    resourceSearchAttempt: makeSuccessAttempt({
      results: [],
      errors: [],
      search: '',
    }),
  };
  jest
    .spyOn(useActionAttempts, 'useActionAttempts')
    .mockImplementation(() => mockActionAttempts);
  jest.spyOn(SearchContext, 'useSearchContext').mockImplementation(() => ({
    ...getMockedSearchContext(),
    filters: [
      { filter: 'cluster', clusterUri: '/clusters/foo' },
      { filter: 'resource-type', resourceType: 'servers' },
    ],
    inputValue: '',
  }));

  render(
    <MockAppContextProvider appContext={appContext}>
      <SearchBarConnected />
    </MockAppContextProvider>
  );

  const results = screen.getByRole('menu');
  expect(results).not.toHaveTextContent('No matching results found');
});

it('does display empty results copy after providing search query for which there is no results', () => {
  const appContext = new MockAppContext();
  appContext.workspacesService.setState(draft => {
    draft.rootClusterUri = '/clusters/foo';
  });

  const mockActionAttempts = {
    filterActionsAttempt: makeSuccessAttempt([]),
    resourceActionsAttempt: makeSuccessAttempt([]),
    resourceSearchAttempt: makeSuccessAttempt({
      results: [],
      errors: [],
      search: '',
    }),
  };
  jest
    .spyOn(useActionAttempts, 'useActionAttempts')
    .mockImplementation(() => mockActionAttempts);
  jest
    .spyOn(SearchContext, 'useSearchContext')
    .mockImplementation(getMockedSearchContext);

  render(
    <MockAppContextProvider appContext={appContext}>
      <SearchBarConnected />
    </MockAppContextProvider>
  );

  const results = screen.getByRole('menu');
  expect(results).toHaveTextContent('No matching results found.');
});

it('does display empty results copy and excluded clusters after providing search query for which there is no results', () => {
  const appContext = new MockAppContext();
  jest
    .spyOn(appContext.clustersService, 'getRootClusters')
    .mockImplementation(() => [
      {
        uri: '/clusters/teleport-12-ent.asteroid.earth',
        name: 'teleport-12-ent.asteroid.earth',
        connected: false,
        leaf: false,
        proxyHost: 'test:3030',
        authClusterId: '73c4746b-d956-4f16-9848-4e3469f70762',
      },
    ]);
  appContext.workspacesService.setState(draft => {
    draft.rootClusterUri = '/clusters/foo';
  });

  const mockActionAttempts = {
    filterActionsAttempt: makeSuccessAttempt([]),
    resourceActionsAttempt: makeSuccessAttempt([]),
    resourceSearchAttempt: makeSuccessAttempt({
      results: [],
      errors: [],
      search: '',
    }),
  };
  jest
    .spyOn(useActionAttempts, 'useActionAttempts')
    .mockImplementation(() => mockActionAttempts);
  jest
    .spyOn(SearchContext, 'useSearchContext')
    .mockImplementation(getMockedSearchContext);

  render(
    <MockAppContextProvider appContext={appContext}>
      <SearchBarConnected />
    </MockAppContextProvider>
  );

  const results = screen.getByRole('menu');
  expect(results).toHaveTextContent('No matching results found.');
  expect(results).toHaveTextContent(
    'The cluster teleport-12-ent.asteroid.earth was excluded from the search because you are not logged in to it.'
  );
});

it('notifies about resource search errors and allows to display details', () => {
  const appContext = new MockAppContext();
  appContext.workspacesService.setState(draft => {
    draft.rootClusterUri = '/clusters/foo';
  });

  const resourceSearchError = new ResourceSearchError(
    '/clusters/foo',
    'server',
    new Error('whoops')
  );

  const mockActionAttempts = {
    filterActionsAttempt: makeSuccessAttempt([]),
    resourceActionsAttempt: makeSuccessAttempt([]),
    resourceSearchAttempt: makeSuccessAttempt({
      results: [],
      errors: [resourceSearchError],
      search: '',
    }),
  };
  jest
    .spyOn(useActionAttempts, 'useActionAttempts')
    .mockImplementation(() => mockActionAttempts);
  const mockedSearchContext = {
    ...getMockedSearchContext(),
    inputValue: 'foo',
  };
  jest
    .spyOn(SearchContext, 'useSearchContext')
    .mockImplementation(() => mockedSearchContext);
  jest.spyOn(appContext.modalsService, 'openRegularDialog');
  jest.spyOn(mockedSearchContext, 'lockOpen');

  render(
    <MockAppContextProvider appContext={appContext}>
      <SearchBarConnected />
    </MockAppContextProvider>
  );

  const results = screen.getByRole('menu');
  expect(results).toHaveTextContent(
    'Some of the search results are incomplete.'
  );
  expect(results).toHaveTextContent('Could not fetch servers from foo');
  expect(results).not.toHaveTextContent(resourceSearchError.cause['message']);

  screen.getByText('Show details').click();

  expect(appContext.modalsService.openRegularDialog).toHaveBeenCalledWith(
    expect.objectContaining({
      kind: 'resource-search-errors',
      errors: [resourceSearchError],
    })
  );
  expect(mockedSearchContext.lockOpen).toHaveBeenCalled();
});

it('maintains focus on the search input after closing a resource search error modal', async () => {
  const appContext = new MockAppContext();
  appContext.workspacesService.setState(draft => {
    draft.rootClusterUri = '/clusters/foo';
  });

  const resourceSearchError = new ResourceSearchError(
    '/clusters/foo',
    'server',
    new Error('whoops')
  );

  const mockActionAttempts = {
    filterActionsAttempt: makeSuccessAttempt([]),
    resourceActionsAttempt: makeSuccessAttempt([]),
    resourceSearchAttempt: makeSuccessAttempt({
      results: [],
      errors: [resourceSearchError],
      search: '',
    }),
  };
  jest
    .spyOn(useActionAttempts, 'useActionAttempts')
    .mockImplementation(() => mockActionAttempts);

  render(
    <MockAppContextProvider appContext={appContext}>
      <SearchBarConnected />
      <ModalsHost />
    </MockAppContextProvider>
  );

  screen.getByRole('searchbox').focus();
  expect(screen.getByRole('menu')).toHaveTextContent(
    'Some of the search results are incomplete.'
  );
  screen.getByText('Show details').click();

  const modal = screen.getByTestId('Modal');
  expect(modal).toHaveTextContent('Resource search errors');
  expect(modal).toHaveTextContent('whoops');

  // Lose focus on the search input.
  screen.getByText('Close').focus();
  screen.getByText('Close').click();

  // Need to await this since some state updates in SearchContext are done after the modal closes.
  // Otherwise we'd get a warning about missing `act`.
  await waitFor(() => {
    expect(modal).not.toBeInTheDocument();
  });

  expect(screen.getByRole('searchbox')).toHaveFocus();
  // Verify that the search bar wasn't closed.
  expect(screen.getByRole('menu')).toBeInTheDocument();
});

const getMockedSearchContext = () => ({
  inputValue: 'foo',
  filters: [],
  setFilter: () => {},
  removeFilter: () => {},
  isOpen: true,
  open: () => {},
  lockOpen: async () => {},
  close: () => {},
  closeAndResetInput: () => {},
  resetInput: () => {},
  changeActivePicker: () => {},
  onInputValueChange: () => {},
  activePicker: pickers.actionPicker,
  inputRef: undefined,
});
