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

import {
  askAboutUserJobRoleIfNeeded,
  setUpUsageReporting,
} from 'teleterm/ui/services/usage';
import { IAppContext } from 'teleterm/ui/types';
import { ConfigService } from 'teleterm/services/config';
import { NotificationsService } from 'teleterm/ui/services/notifications';

/**
 * Runs after the UI becomes visible.
 * If possible, put the initialization code here, instead of `appContext.init()`,
 * where it blocks the rendering of the app.
 */
export async function initUi(ctx: IAppContext): Promise<void> {
  const { configService } = ctx.mainProcessClient;

  await askAboutUserJobRoleIfNeeded(
    ctx.statePersistenceService,
    configService,
    ctx.modalsService,
    ctx.usageService
  );
  // Setting up usage reporting after asking for a job role prevents a situation
  // where these dialogs are shown one after another.
  // Instead, on the first launch only "usage reporting" dialog shows up.
  // "User job role" dialog is shown on the second launch (only if user agreed to reporting earlier).
  await setUpUsageReporting(configService, ctx.modalsService);
  ctx.workspacesService.restorePersistedState();
  notifyAboutStoredConfigErrors(configService, ctx.notificationsService);
}

function notifyAboutStoredConfigErrors(
  configService: ConfigService,
  notificationsService: NotificationsService
): void {
  const errors = configService.getStoredConfigErrors();
  if (errors) {
    notificationsService.notifyError({
      title: 'Encountered errors in config file',
      description: errors
        .map(error => `${error.path[0]}: ${error.message}`)
        .join('\n'),
    });
  }
}
