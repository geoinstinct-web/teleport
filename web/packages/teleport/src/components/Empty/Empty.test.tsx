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
import { render } from 'design/utils/testing';
import { MemoryRouter } from 'react-router';

import Empty, { Props } from './Empty';

test('empty state for enterprise or oss, with create perms', async () => {
  const { findByText } = render(
    <MemoryRouter>
      <Empty {...props} />
    </MemoryRouter>
  );

  await expect(
    findByText(/Add your first Linux server to Teleport/i)
  ).resolves.toBeVisible();
});

test('empty state for cant create or leaf cluster', async () => {
  const { findByText } = render(
    <MemoryRouter>
      <Empty {...props} canCreate={false} />
    </MemoryRouter>
  );

  await expect(
    findByText(/Either there are no servers in the/i)
  ).resolves.toBeVisible();
});

const props: Props = {
  clusterId: 'im-a-cluster',
  canCreate: true,
  emptyStateInfo: {
    title: 'Add your first Linux server to Teleport',
    byline:
      'Teleport Server Access consolidates SSH access across all environments.',
    docsURL: 'https://goteleport.com/docs/server-access/getting-started/',
    resourceType: 'server',
    readOnly: {
      title: 'No Servers Found',
      resource: 'servers',
    },
  },
};
