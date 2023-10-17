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

import { makeEmptyAttempt } from 'shared/hooks/useAsync';

import { UserContextValue } from 'teleport/User/UserContext';

export const makeTestUserContext = (
  overrides?: Partial<UserContextValue>
): UserContextValue => {
  return Object.assign(
    {
      preferences: {
        theme: 1,
        assist: {
          preferredLogins: [],
          viewMode: 1,
        },
        onboard: {
          preferredResources: [],
        },
      },
      clusterPreferences: {
        pinnedResources: [],
      },
      updateClusterPreferencesAttempt: makeEmptyAttempt(),
      updatePreferences: () => Promise.resolve(),
      updateClusterPinnedResources: () => Promise.resolve(),
      getClusterPinnedResources: () => Promise.resolve(),
    },
    overrides
  );
};
