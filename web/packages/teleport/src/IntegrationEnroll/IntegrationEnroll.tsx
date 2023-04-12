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
import { Box } from 'design';

import {
  FeatureBox,
  FeatureHeader,
  FeatureHeaderTitle,
} from 'teleport/components/Layout';

import { IntegrationTiles } from './IntegrationTiles';
import { NoCodeIntegrationDescription } from './common';

export function IntegrationEnroll() {
  return (
    <FeatureBox>
      <FeatureHeader>
        <FeatureHeaderTitle>Select Integration Type</FeatureHeaderTitle>
      </FeatureHeader>
      <Box>
        <NoCodeIntegrationDescription />
        <IntegrationTiles />
      </Box>
    </FeatureBox>
  );
}
