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

import api from 'teleport/services/api';

import ping from './ping';

test('undefined automatic upgrade resolves to false', async () => {
  const mockContext = {};

  jest.spyOn(api, 'get').mockResolvedValue(mockContext);

  const response = await ping.fetchPing();
  expect(response).toEqual({
    automaticUpgrades: false,
  });
});

test('null automatic upgrade resolves to false', async () => {
  const mockContext = {
    automatic_upgrades: null,
  };

  jest.spyOn(api, 'get').mockResolvedValue(mockContext);

  const response = await ping.fetchPing();
  expect(response).toEqual({
    automaticUpgrades: false,
  });
});

test('automatic upgrade set to true, resolves to true', async () => {
  const mockContext = {
    automatic_upgrades: true,
  };

  jest.spyOn(api, 'get').mockResolvedValue(mockContext);

  const response = await ping.fetchPing();
  expect(response).toEqual({
    automaticUpgrades: true,
  });
});
