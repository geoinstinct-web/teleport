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

import { App } from 'teleport/services/apps';
import { Database } from 'teleport/services/databases';
import { Node } from 'teleport/services/nodes';
import { Kube } from 'teleport/services/kube';
import { Desktop } from 'teleport/services/desktops';

import { UserGroup } from '../userGroups';

import type { MfaAuthnResponse } from '../mfa';
import type { Platform } from 'design/platform';

export type UnifiedResource =
  | App
  | Database
  | Node
  | Kube
  | Desktop
  | UserGroup;

export type UnifiedResourceKind = UnifiedResource['kind'];

export type ResourcesResponse<T> = {
  //TODO(gzdunek): Rename to items.
  agents: T[];
  startKey?: string;
  totalCount?: number;
};

export type ResourceLabel = {
  name: string;
  value: string;
};

export type ResourceFilter = {
  /** query is query expression using the predicate language. */
  query?: string;
  /** search contains search words/phrases separated by space. */
  search?: string;
  sort?: SortType;
  limit?: number;
  startKey?: string;
  pinnedOnly?: boolean;
  searchAsRoles?: '' | 'yes';
  // TODO(bl-nero): Remove this once filters are expressed as advanced search.
  kinds?: string[];
};

export type SortType = {
  fieldName: string;
  dir: SortDir;
};

export type SortDir = 'ASC' | 'DESC';

/**
 * ResourceIdKind are the same id constants used to mark the type of
 * resource in the backend.
 *
 * These consts are expected for various resource requests:
 *   - search based access requests
 *   - diagnose connection requests
 */
export type ResourceIdKind =
  | 'node'
  | 'app'
  | 'db'
  | 'kube_cluster'
  | 'user_group'
  | 'windows_desktop';

export type ConnectionDiagnostic = {
  /** id is the identifier of the connection diagnostic. */
  id: string;
  /** success is whether the connection was successful */
  success: boolean;
  /** message is the diagnostic summary */
  message: string;
  /** traces contains multiple checkpoints results */
  traces: ConnectionDiagnosticTrace[];
};

/** ConnectionDiagnosticTrace describes a trace of a connection diagnostic */
export type ConnectionDiagnosticTrace = {
  traceType: string;
  status: 'success' | 'failed';
  details: string;
  error?: string;
};

/**
 * ConnectionDiagnosticRequest contains
 * - the identification of the resource kind and resource name to test
 * - additional paramenters which depend on the actual kind of resource to test
 * As an example, for SSH Node it also includes the User/Principal that will be used to login
 */
export type ConnectionDiagnosticRequest = {
  resourceKind: ResourceIdKind; //`json:"resource_kind"`
  resourceName: string; //`json:"resource_name"`
  sshPrincipal?: string; //`json:"ssh_principal"`
  /**
   * An optional field which describes whether the SSH principal was chosen manually by the user or
   * automatically. Used in Connect My Computer which automatically picks the principal if there's
   * only a single login available in the Connect My Computer role.
   */
  sshPrincipalSelectionMode?: 'manual' | 'auto'; //`json:"ssh_principal_selection_mode"`
  /**
   * An optional field which describes the platform the SSH agent runs on.
   */
  sshNodeOS?: Platform; // `json:"ssh_node_os"`
  /**
   * An optional field which which describes how an SSH agent was installed.
   * The value must match one of the consts defined in lib/client/conntest/connection_tester.go.
   */
  sshNodeSetupMethod?: 'script' | 'connect_my_computer'; // `json:"ssh_node_setup_method"`
  kubeImpersonation?: KubeImpersonation; // `json:"kubernetes_impersonation"`
  dbTester?: DatabaseTester;
  mfaAuthnResponse?: MfaAuthnResponse;
};

export type KubeImpersonation = {
  namespace: string; // `json:"kubernetes_namespace"`
  /**
   * The Kubernetes user to impersonate for this request.
   * Optional - If multiple values are configured the user must select one
   * otherwise the request will return an error.
   */
  user?: string; // `json:"kubernetes_impersonation.kubernetes_user"`
  /**
   * The Kubernetes groups to impersonate for this request.
   * Optional - If not specified it use all configured groups.
   * When KubernetesGroups is specified, KubernetesUser must be provided
   * as well.
   */
  groups?: string[]; // `json:"kubernetes_impersonation.kubernetes_groups"
};

export type DatabaseTester = {
  user?: string; // `json:"database_user"`
  name?: string; // `json:"database_name"`
};
