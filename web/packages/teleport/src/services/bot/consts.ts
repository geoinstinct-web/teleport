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

import {
  ApiBot,
  FlatBot,
  GitHubRepoRule,
  ProvisionTokenSpecV2GitHub,
} from 'teleport/services/bot/types';

/**
 *
 * @param spec a ProvisionTokenSpecV2GitHub
 * @returns the server's teleport/api/types.ProvisionTokenSpecV2GitHub,
 * which has similar properties but different casing
 */
export function toApiGitHubTokenSpec(spec: ProvisionTokenSpecV2GitHub | null) {
  if (!spec) {
    return null;
  }
  return {
    allow: spec.allow.map(toApiGitHubRule),
    enterprise_server_host: spec.enterpriseServerHost,
  };
}

/**
 *
 * @param {GitHubRepoRule} rule a GitHubRepoRule
 * @returns the server's teleport/api/types.ProvisionTokenSpecV2GitHub_Rule,
 * which has similar properties, but different casing
 */
export function toApiGitHubRule({
  sub,
  repository,
  repositoryOwner,
  workflow,
  environment,
  actor,
  ref,
  refType,
}: GitHubRepoRule) {
  return {
    sub,
    repository,
    repository_owner: repositoryOwner,
    workflow,
    environment,
    actor,
    ref,
    ref_type: refType,
  };
}

export function makeBot(bot: ApiBot): FlatBot {
  if (!bot?.metadata?.name) {
    return;
  }

  return {
    kind: bot?.kind || '',
    status: bot?.status || '',
    subKind: bot?.subKind || '',
    version: bot?.version || '',

    name: bot?.metadata?.name || '',
    namespace: bot?.metadata?.namespace || '',
    description: bot?.metadata?.description || '',
    labels: bot?.metadata?.labels || new Map<string, string>(),
    revision: bot?.metadata?.revision || '',

    roles: bot?.spec?.roles || [],
    traits: bot?.spec?.traits || [],
  };
}
