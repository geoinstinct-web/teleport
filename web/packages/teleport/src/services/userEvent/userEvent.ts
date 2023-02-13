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

import api from 'teleport/services/api';
import cfg from 'teleport/config';

import { CaptureEvent } from './types';

export type UserEvent = {
  event: CaptureEvent;
  alert?: string;
};

export type PreUserEvent = UserEvent & {
  username: string;
  mfaType?: string;
  loginFlow?: string;
};

export const userEventService = {
  captureUserEvent(userEvent: UserEvent) {
    // using api.fetch instead of api.fetchJSON
    // because we are not expecting a JSON response
    void api.fetch(cfg.api.captureUserEventPath, {
      method: 'POST',
      body: JSON.stringify(userEvent),
    });
  },

  capturePreUserEvent(preUserEvent: PreUserEvent) {
    // using api.fetch instead of api.fetchJSON
    // because we are not expecting a JSON response
    void api.fetch(cfg.api.capturePreUserEventPath, {
      method: 'POST',
      body: JSON.stringify({ ...preUserEvent }),
    });
  },
};
