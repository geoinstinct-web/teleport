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
import { setupServer } from 'msw/node';
import { rest } from 'msw';
import { render, fireEvent, screen } from 'design/utils/testing';

import { ContextProvider } from 'teleport';
import { createTeleportContext } from 'teleport/mocks/contexts';
import cfg from 'teleport/config';

import { Locks } from './Locks';

test('lock search', async () => {
  const server = setupServer(
    rest.get(cfg.getLocksUrl(), (req, res, ctx) => {
      return res(
        ctx.json([
          {
            name: 'lock-name-1',
            targets: {
              user: 'lock-user',
            },
          },
          {
            name: 'lock-name-2',
            targets: {
              role: 'lock-role-1',
            },
          },
          {
            name: 'lock-name-3',
            targets: {
              role: 'lock-role-2',
            },
          },
        ])
      );
    })
  );

  server.listen();

  const ctx = createTeleportContext();

  render(
    <MemoryRouter>
      <ContextProvider ctx={ctx}>
        <Locks />
      </ContextProvider>
    </MemoryRouter>
  );

  const rows = await screen.findAllByText(/lock-/i);
  expect(rows).toHaveLength(3);

  // Test searching.
  fireEvent.change(screen.getByPlaceholderText(/search/i), {
    target: { value: 'lock-role' },
  });

  expect(screen.queryAllByText(/lock-role/i)).toHaveLength(2);
  expect(screen.queryByText(/lock-user/i)).not.toBeInTheDocument();

  server.close();
});
