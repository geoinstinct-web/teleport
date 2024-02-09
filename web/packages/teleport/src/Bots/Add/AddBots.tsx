/**
 * Teleport
 * Copyright (C) 2024 Gravitational, Inc.
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

import { Switch, Route } from 'teleport/components/Router';
import cfg from 'teleport/config';

import { FeatureBox } from 'teleport/components/Layout';

import { BotType } from '../types';

import GitHubActionsFlow from './GitHubActions';
import { AddBotsPicker } from './AddBotsPicker';

export function AddBots() {
  return (
    <FeatureBox>
      <Switch>
        <Route
          path={cfg.getBotsNewRoute(BotType.GitHubActions)}
          component={GitHubActionsFlow}
        />
        <Route path={cfg.getBotsNewRoute()} component={AddBotsPicker} />
      </Switch>
    </FeatureBox>
  );
}
