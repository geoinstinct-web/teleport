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

import { Platform } from 'design/theme/utils';

import { ResourceKind } from '../Shared/ResourceKind';

import type { DiscoverEventResource } from 'teleport/services/userEvent';

import type { ResourceIconName } from 'design/ResourceIcon';

export enum DatabaseLocation {
  Aws,
  SelfHosted,
  Gcp,
  Azure,
  Microsoft,

  TODO,
}

// DatabaseEngine represents the db "protocol".
export enum DatabaseEngine {
  Postgres,
  AuroraPostgres,
  MySql,
  AuroraMysql,
  MongoDb,
  Redis,
  CoackroachDb,
  SqlServer,
  Snowflake,
  Cassandra,
  ElasticSearch,
  DynamoDb,
  Redshift,

  Doc,
}

export interface ResourceSpec {
  dbMeta?: { location: DatabaseLocation; engine: DatabaseEngine };
  name: string;
  popular?: boolean;
  kind: ResourceKind;
  icon: ResourceIconName;
  // keywords are filter words that user may use to search for
  // this resource.
  keywords: string;
  // hasAccess is a flag to mean that user has
  // the preliminary permissions to add this resource.
  hasAccess?: boolean;
  // unguidedLink is the link out to this resources documentation.
  // It is used as a flag, that when defined, means that
  // this resource is not "guided" (has no UI interactive flow).
  unguidedLink?: string;
  // isDialog indicates whether the flow for this resource is a popover dialog as opposed to a Discover flow.
  // This is the case for the 'Application' resource.
  isDialog?: boolean;
  // event is the expected backend enum event name that describes
  // the type of this resource (e.g. server v. kubernetes),
  // used for usage reporting.
  event: DiscoverEventResource;
  // platform indicates a particular platform the resource is associated with.
  // Set this value if the resource should be prioritized based on the platform.
  platform?: Platform;
}

export enum SearchResource {
  UNSPECIFIED = '',
  APPLICATION = 'application',
  DATABASE = 'database',
  DESKTOP = 'desktop',
  KUBERNETES = 'kubernetes',
  SERVER = 'server',
  UNIFIED_RESOURCE = 'unified_resource',
}
