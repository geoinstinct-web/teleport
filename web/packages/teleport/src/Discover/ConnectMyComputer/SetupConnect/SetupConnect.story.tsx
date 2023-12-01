/**
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
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
import { MemoryRouter } from 'react-router';
import { initialize, mswLoader } from 'msw-storybook-addon';
import { rest } from 'msw';

import {
  OverrideUserAgent,
  UserAgent,
} from 'shared/components/OverrideUserAgent';

import { ContextProvider } from 'teleport';
import cfg from 'teleport/config';
import { UserContext } from 'teleport/User/UserContext';
import { createTeleportContext } from 'teleport/mocks/contexts';
import { makeDefaultUserPreferences } from 'teleport/services/userPreferences/userPreferences';

import { SetupConnect } from './SetupConnect';

const oneDay = 1000 * 60 * 60 * 24;

const setupConnectProps = {
  prevStep: () => {},
  nextStep: () => {},
  updateAgentMeta: () => {},
  // Set high default intervals and timeouts so that stories don't poll for no reason.
  pingInterval: oneDay,
  showHintTimeout: oneDay,
};

initialize();

export default {
  title: 'Teleport/Discover/ConnectMyComputer/SetupConnect',
  loaders: [mswLoader],
};

const noNodesHandler = rest.get(cfg.api.nodesPath, (req, res, ctx) =>
  res(ctx.json({ items: [] }))
);

export const macOS = () => (
  <OverrideUserAgent userAgent={UserAgent.macOS}>
    <Provider>
      <SetupConnect {...setupConnectProps} />
    </Provider>
  </OverrideUserAgent>
);

macOS.parameters = {
  msw: {
    handlers: [noNodesHandler],
  },
};

export const Linux = () => (
  <OverrideUserAgent userAgent={UserAgent.Linux}>
    <Provider>
      <SetupConnect {...setupConnectProps} />
    </Provider>
  </OverrideUserAgent>
);

Linux.parameters = {
  msw: {
    handlers: [noNodesHandler],
  },
};

export const Polling = () => (
  <Provider>
    <SetupConnect {...setupConnectProps} />
  </Provider>
);

Polling.parameters = {
  msw: {
    handlers: [noNodesHandler],
  },
};

export const PollingSuccess = () => (
  <Provider>
    <SetupConnect {...setupConnectProps} pingInterval={5} />
  </Provider>
);

PollingSuccess.parameters = {
  msw: {
    handlers: [
      rest.get(cfg.api.nodesPath, (req, res, ctx) => {
        return res.once(ctx.json({ items: [] }));
      }),
      rest.get(cfg.api.nodesPath, (req, res, ctx) => {
        return res(ctx.json({ items: [{ id: '1234', hostname: 'foo' }] }));
      }),
    ],
  },
};

export const HintTimeout = () => (
  <Provider>
    <SetupConnect {...setupConnectProps} showHintTimeout={1} />
  </Provider>
);

HintTimeout.parameters = {
  msw: {
    handlers: [
      noNodesHandler,
      rest.post(cfg.api.webRenewTokenPath, (req, res, ctx) =>
        res(ctx.json({}))
      ),
    ],
  },
};

const Provider = ({ children }) => {
  const ctx = createTeleportContext();
  // The proxy version is set mostly so that the download links point to actual artifacts.
  ctx.storeUser.state.cluster.proxyVersion = '14.1.0';

  const preferences = makeDefaultUserPreferences();
  const updatePreferences = () => Promise.resolve();
  const getClusterPinnedResources = () => Promise.resolve([]);
  const updateClusterPinnedResources = () => Promise.resolve();

  return (
    <MemoryRouter>
      <UserContext.Provider
        value={{
          preferences,
          updatePreferences,
          getClusterPinnedResources,
          updateClusterPinnedResources,
        }}
      >
        <ContextProvider ctx={ctx}>{children}</ContextProvider>
      </UserContext.Provider>
    </MemoryRouter>
  );
};
