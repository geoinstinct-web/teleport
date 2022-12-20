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

import React from 'react';
import { MemoryRouter } from 'react-router';

import { DatabaseEngine } from '../resources';

import { CreateDatabaseView } from './CreateDatabase';

import type { State } from './useCreateDatabase';

export default {
  title: 'Teleport/Discover/Database/CreateDatabase',
};

export const Init = () => (
  <MemoryRouter>
    <CreateDatabaseView {...props} />
  </MemoryRouter>
);

export const NoPerm = () => (
  <MemoryRouter>
    <CreateDatabaseView {...props} canCreateDatabase={false} />
  </MemoryRouter>
);

export const Processing = () => (
  <MemoryRouter>
    <CreateDatabaseView {...props} attempt={{ status: 'processing' }} />
  </MemoryRouter>
);

export const Failed = () => (
  <MemoryRouter>
    <CreateDatabaseView
      {...props}
      attempt={{ status: 'failed', statusText: 'some error message' }}
    />
  </MemoryRouter>
);

const props: State = {
  attempt: { status: '' },
  createDbAndQueryDb: () => null,
  canCreateDatabase: true,
  engine: DatabaseEngine.PostgreSQL,
};
