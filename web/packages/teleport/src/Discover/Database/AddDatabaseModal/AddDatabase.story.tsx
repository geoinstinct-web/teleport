/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import React from 'react';

import {
  DatabaseEngine,
  DatabaseLocation,
} from 'teleport/Discover/Database/resources';
import { AuthType } from 'teleport/services/user';

import { AddDatabase } from './AddDatabase';

export default {
  title: 'Teleport/Databases/Add',
};

export const WithToken = () => <AddDatabase {...props} />;
export const Processing = () => (
  <AddDatabase {...props} attempt={{ status: 'processing' }} />
);
export const WithoutTokenLocal = () => (
  <AddDatabase {...props} attempt={{ status: 'failed' }} />
);
export const WithoutTokenSSO = () => (
  <AddDatabase {...props} attempt={{ status: 'failed' }} authType="sso" />
);

const props = {
  isEnterprise: false,
  username: 'yassine',
  version: '6.1.3',
  onClose: () => null,
  authType: 'local' as AuthType,
  attempt: {
    status: 'success',
    statusText: '',
  } as any,
  token: { id: 'some-join-token-hash', expiry: null, expiryText: '4 hours' },
  createJoinToken() {
    return Promise.resolve(null);
  },
  selectedDb: {
    engine: DatabaseEngine.PostgreSQL,
    location: DatabaseLocation.AWS,
    name: 'Postgres',
  },
};
