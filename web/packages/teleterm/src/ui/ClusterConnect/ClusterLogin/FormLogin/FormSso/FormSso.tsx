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
import { Box } from 'design';

import SSOButtonList from './SsoButtons';

import type { Props } from '../FormLogin';

export const FormSso = ({
  loginAttempt,
  authProvidersList,
  onLoginWithSso,
  autoFocus = false,
}: Props) => {
  return (
    <Box textAlign="center">
      <SSOButtonList
        prefixText="Login with"
        isDisabled={loginAttempt.status === 'processing'}
        providers={authProvidersList}
        onClick={onLoginWithSso}
        autoFocus={autoFocus}
      />
    </Box>
  );
};
