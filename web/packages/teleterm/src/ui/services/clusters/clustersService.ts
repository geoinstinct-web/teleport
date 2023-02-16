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

import { useStore } from 'shared/libs/stores';
import {
  DbProtocol,
  DbType,
  formatDatabaseInfo,
} from 'shared/services/databases';
import { pipe } from 'shared/utils/pipe';

import * as uri from 'teleterm/ui/uri';
import { NotificationsService } from 'teleterm/ui/services/notifications';
import {
  Cluster,
  CreateAccessRequestParams,
  GetRequestableRolesParams,
  ReviewAccessRequestParams,
  ServerSideParams,
} from 'teleterm/services/tshd/types';
import { MainProcessClient } from 'teleterm/mainProcess/types';
import { UsageService } from 'teleterm/ui/services/usage';

import { ImmutableStore } from '../immutableStore';

import type * as types from './types';
import type * as tsh from 'teleterm/services/tshd/types';

const { routing } = uri;

export function createClusterServiceState(): types.ClustersServiceState {
  return {
    clusters: new Map(),
    gateways: new Map(),
  };
}

export class ClustersService extends ImmutableStore<types.ClustersServiceState> {
  state: types.ClustersServiceState = createClusterServiceState();

  constructor(
    public client: tsh.TshClient,
    private mainProcessClient: MainProcessClient,
    private notificationsService: NotificationsService,
    private usageService: UsageService
  ) {
    super();
  }

  async addRootCluster(addr: string) {
    const cluster = await this.client.addRootCluster(addr);
    this.setState(draft => {
      draft.clusters.set(
        cluster.uri,
        this.removeInternalLoginsFromCluster(cluster)
      );
    });

    return cluster;
  }

  async logout(clusterUri: uri.RootClusterUri) {
    // TODO(gzdunek): logout and removeCluster should be combined into a single acton in tshd
    await this.client.logout(clusterUri);
    await this.removeCluster(clusterUri);
    await this.removeClusterKubeConfigs(clusterUri);
  }

  async loginLocal(
    params: types.LoginLocalParams,
    abortSignal: tsh.TshAbortSignal
  ) {
    await this.client.loginLocal(params, abortSignal);
    await this.syncRootClusterAndCatchErrors(params.clusterUri);
    this.usageService.captureUserLogin(params.clusterUri, 'local');
  }

  async loginSso(
    params: types.LoginSsoParams,
    abortSignal: tsh.TshAbortSignal
  ) {
    await this.client.loginSso(params, abortSignal);
    await this.syncRootClusterAndCatchErrors(params.clusterUri);
    this.usageService.captureUserLogin(params.clusterUri, params.providerType);
  }

  async loginPasswordless(
    params: types.LoginPasswordlessParams,
    abortSignal: tsh.TshAbortSignal
  ) {
    await this.client.loginPasswordless(params, abortSignal);
    await this.syncRootClusterAndCatchErrors(params.clusterUri);
    this.usageService.captureUserLogin(params.clusterUri, 'passwordless');
  }

  async syncRootClusterAndCatchErrors(clusterUri: uri.RootClusterUri) {
    try {
      await this.syncRootCluster(clusterUri);
    } catch (e) {
      const cluster = this.findCluster(clusterUri);
      const clusterName =
        cluster?.name ||
        routing.parseClusterUri(clusterUri).params.rootClusterId;
      this.notificationsService.notifyError({
        title: `Could not synchronize cluster ${clusterName}`,
        description: e.message,
      });
    }
  }

  async syncRootCluster(clusterUri: uri.RootClusterUri) {
    try {
      await Promise.all([
        // syncClusterInfo never fails with a retryable error, only syncLeafClusters does.
        this.syncClusterInfo(clusterUri),
        this.syncLeafClusters(clusterUri),
      ]);
    } finally {
      // Functions below handle their own errors, so we don't need to await them.
      //
      // Also, we wait for syncClusterInfo to finish first. When the response from it comes back and
      // it turns out that the cluster is not connected, these functions will immediately exit with
      // an error.
      //
      // Arguably, it is a bit of a race condition, as we assume that syncClusterInfo will return
      // before syncLeafClusters, but for now this is a condition we can live with.
      // TODO: What to do with this?
      this.syncGateways();
    }
  }

  async syncLeafCluster(clusterUri: uri.LeafClusterUri) {
    try {
      // Sync leaf clusters list, so that in case of an error that can be resolved with login we can
      // propagate that error up.
      const rootClusterUri = routing.ensureRootClusterUri(clusterUri);
      await this.syncLeafClustersList(rootClusterUri);
    } finally {
      // TODO: Is syncGateways needed here?
      // this.syncLeafClusterResourcesAndCatchErrors(clusterUri);
      this.syncGateways();
    }
  }

  async syncRootClusters() {
    try {
      const clusters = await this.client.listRootClusters();
      this.setState(draft => {
        draft.clusters = new Map(clusters.map(c => [c.uri, c]));
      });
      clusters
        .filter(c => c.connected)
        .forEach(c => this.syncRootClusterAndCatchErrors(c.uri));
    } catch (error) {
      this.notificationsService.notifyError({
        title: 'Could not fetch root clusters',
        description: error.message,
      });
    }
  }

  async syncCluster(clusterUri: uri.ClusterUri) {
    const cluster = this.findCluster(clusterUri);
    if (!cluster) {
      throw Error(`missing cluster: ${clusterUri}`);
    }

    if (cluster.leaf) {
      return await this.syncLeafCluster(clusterUri as uri.LeafClusterUri);
    } else {
      return await this.syncRootCluster(clusterUri);
    }
  }

  async syncGateways() {
    try {
      const gws = await this.client.listGateways();
      this.setState(draft => {
        draft.gateways = new Map(gws.map(g => [g.uri, g]));
      });
    } catch (error) {
      this.notificationsService.notifyError({
        title: 'Could not synchronize database connections',
        description: error.message,
      });
    }
  }

  async syncLeafClusters(clusterUri: uri.RootClusterUri) {
    await this.syncLeafClustersList(clusterUri);

    // TODO: Is syncGateways necessary here?
    this.syncGateways();
  }

  private async syncLeafClustersList(clusterUri: uri.RootClusterUri) {
    const leaves = await this.client.listLeafClusters(clusterUri);

    this.setState(draft => {
      for (const leaf of leaves) {
        draft.clusters.set(
          leaf.uri,
          this.removeInternalLoginsFromCluster(leaf)
        );
      }
    });

    return leaves;
  }

  async getRequestableRoles(params: GetRequestableRolesParams) {
    const cluster = this.state.clusters.get(params.rootClusterUri);
    if (!cluster.connected) {
      return;
    }

    return this.client.getRequestableRoles(params);
  }

  getAssumedRequests(rootClusterUri: uri.RootClusterUri) {
    const cluster = this.state.clusters.get(rootClusterUri);
    if (!cluster?.connected) {
      return {};
    }

    return cluster.loggedInUser?.assumedRequests || {};
  }

  getAssumedRequest(rootClusterUri: uri.RootClusterUri, requestId: string) {
    return this.getAssumedRequests(rootClusterUri)[requestId];
  }

  async getAccessRequests(rootClusterUri: uri.RootClusterUri) {
    const cluster = this.state.clusters.get(rootClusterUri);
    if (!cluster.connected) {
      return;
    }

    return this.client.getAccessRequests(rootClusterUri);
  }

  async deleteAccessRequest(
    rootClusterUri: uri.RootClusterUri,
    requestId: string
  ) {
    const cluster = this.state.clusters.get(rootClusterUri);
    if (!cluster.connected) {
      return;
    }
    return this.client.deleteAccessRequest(rootClusterUri, requestId);
  }

  async assumeRole(
    rootClusterUri: uri.RootClusterUri,
    requestIds: string[],
    dropIds: string[]
  ) {
    const cluster = this.state.clusters.get(rootClusterUri);
    if (!cluster.connected) {
      return;
    }
    await this.client.assumeRole(rootClusterUri, requestIds, dropIds);
    this.usageService.captureAccessRequestAssumeRole(rootClusterUri);
    return this.syncCluster(rootClusterUri);
  }

  async getAccessRequest(
    rootClusterUri: uri.RootClusterUri,
    requestId: string
  ) {
    const cluster = this.state.clusters.get(rootClusterUri);
    if (!cluster.connected) {
      return;
    }

    return this.client.getAccessRequest(rootClusterUri, requestId);
  }

  async reviewAccessRequest(
    rootClusterUri: uri.RootClusterUri,
    params: ReviewAccessRequestParams
  ) {
    const cluster = this.state.clusters.get(rootClusterUri);
    if (!cluster.connected) {
      return;
    }

    const response = await this.client.reviewAccessRequest(
      rootClusterUri,
      params
    );
    this.usageService.captureAccessRequestReview(rootClusterUri);
    return response;
  }

  async createAccessRequest(params: CreateAccessRequestParams) {
    const cluster = this.state.clusters.get(params.rootClusterUri);
    if (!cluster.connected) {
      return;
    }

    const response = await this.client.createAccessRequest(params);
    this.usageService.captureAccessRequestCreate(
      params.rootClusterUri,
      params.roles.length ? 'role' : 'resource'
    );
    return response;
  }

  /**
   * Removes cluster and its leaf clusters (if any)
   */
  async removeCluster(clusterUri: uri.RootClusterUri) {
    await this.client.removeCluster(clusterUri);
    const leafClustersUris = this.getClusters()
      .filter(
        item =>
          item.leaf && routing.ensureRootClusterUri(item.uri) === clusterUri
      )
      .map(cluster => cluster.uri);
    this.setState(draft => {
      draft.clusters.delete(clusterUri);
      leafClustersUris.forEach(leafClusterUri => {
        draft.clusters.delete(leafClusterUri);
      });
    });
  }

  async getAuthSettings(clusterUri: uri.RootClusterUri) {
    return (await this.client.getAuthSettings(
      clusterUri
    )) as types.AuthSettings;
  }

  async createGateway(params: tsh.CreateGatewayParams) {
    const gateway = await this.client.createGateway(params);
    this.usageService.captureProtocolUse(params.targetUri, 'db');
    this.setState(draft => {
      draft.gateways.set(gateway.uri, gateway);
    });
    return gateway;
  }

  async removeGateway(gatewayUri: uri.GatewayUri) {
    try {
      await this.client.removeGateway(gatewayUri);
      this.setState(draft => {
        draft.gateways.delete(gatewayUri);
      });
    } catch (error) {
      const gateway = this.findGateway(gatewayUri);
      const gatewayDescription = gateway
        ? `for ${gateway.targetUser}@${gateway.targetName}`
        : gatewayUri;
      const title = `Could not close the database connection ${gatewayDescription}`;

      this.notificationsService.notifyError({
        title,
        description: error.message,
      });
      throw error;
    }
  }

  async setGatewayTargetSubresourceName(
    gatewayUri: uri.GatewayUri,
    targetSubresourceName: string
  ) {
    if (!this.findGateway(gatewayUri)) {
      throw new Error(`Could not find gateway ${gatewayUri}`);
    }

    const gateway = await this.client.setGatewayTargetSubresourceName(
      gatewayUri,
      targetSubresourceName
    );

    this.setState(draft => {
      draft.gateways.set(gatewayUri, gateway);
    });

    return gateway;
  }

  async setGatewayLocalPort(gatewayUri: uri.GatewayUri, localPort: string) {
    if (!this.findGateway(gatewayUri)) {
      throw new Error(`Could not find gateway ${gatewayUri}`);
    }

    const gateway = await this.client.setGatewayLocalPort(
      gatewayUri,
      localPort
    );

    this.setState(draft => {
      draft.gateways.set(gatewayUri, gateway);
    });

    return gateway;
  }

  findCluster(clusterUri: uri.ClusterUri) {
    return this.state.clusters.get(clusterUri);
  }

  findGateway(gatewayUri: uri.GatewayUri) {
    return this.state.gateways.get(gatewayUri);
  }

  findClusterByResource(uri: string) {
    const parsed = routing.parseClusterUri(uri);
    if (!parsed) {
      return null;
    }

    const clusterUri = routing.getClusterUri(parsed.params);
    return this.findCluster(clusterUri);
  }

  findRootClusterByResource(uri: string) {
    const parsed = routing.parseClusterUri(uri);
    if (!parsed) {
      return null;
    }

    const rootClusterUri = routing.getClusterUri({
      rootClusterId: parsed.params.rootClusterId,
    });
    return this.findCluster(rootClusterUri);
  }

  getGateways() {
    return [...this.state.gateways.values()];
  }

  getClusters() {
    return [...this.state.clusters.values()];
  }

  getRootClusters() {
    return this.getClusters().filter(c => !c.leaf);
  }

  async fetchKubes(params: ServerSideParams) {
    return await this.client.getKubes(params);
  }

  async getDbUsers(dbUri: uri.DatabaseUri): Promise<string[]> {
    return await this.client.listDatabaseUsers(dbUri);
  }

  async removeClusterKubeConfigs(clusterUri: string): Promise<void> {
    const {
      params: { rootClusterId },
    } = routing.parseClusterUri(clusterUri);
    return this.mainProcessClient.removeKubeConfig({
      relativePath: rootClusterId,
      isDirectory: true,
    });
  }

  async removeKubeConfig(kubeConfigRelativePath: string): Promise<void> {
    return this.mainProcessClient.removeKubeConfig({
      relativePath: kubeConfigRelativePath,
    });
  }

  useState() {
    return useStore(this).state;
  }

  private async syncClusterInfo(clusterUri: uri.RootClusterUri) {
    const cluster = await this.client.getCluster(clusterUri);
    // TODO: this information should eventually be gathered by getCluster
    const assumedRequests = cluster.loggedInUser
      ? await this.fetchClusterAssumedRequests(
          cluster.loggedInUser.activeRequestsList,
          clusterUri
        )
      : undefined;
    const mergeAssumedRequests = (cluster: Cluster) => ({
      ...cluster,
      loggedInUser: cluster.loggedInUser && {
        ...cluster.loggedInUser,
        assumedRequests,
      },
    });
    const processCluster = pipe(
      this.removeInternalLoginsFromCluster,
      mergeAssumedRequests
    );

    this.setState(draft => {
      draft.clusters.set(clusterUri, processCluster(cluster));
    });
  }

  private async fetchClusterAssumedRequests(
    activeRequestsList: string[],
    clusterUri: uri.RootClusterUri
  ) {
    return (
      await Promise.all(
        activeRequestsList.map(requestId =>
          this.getAccessRequest(clusterUri, requestId)
        )
      )
    ).reduce((requestsMap, request) => {
      requestsMap[request.id] = {
        id: request.id,
        expires: new Date(request.expires.seconds * 1000),
        roles: request.rolesList,
      };
      return requestsMap;
    }, {});
  }

  // temporary fix for https://github.com/gravitational/webapps.e/issues/294
  // remove when it will get fixed in `tsh`
  // alternatively, show only valid logins basing on RBAC check
  private removeInternalLoginsFromCluster(cluster: Cluster): Cluster {
    return {
      ...cluster,
      loggedInUser: cluster.loggedInUser && {
        ...cluster.loggedInUser,
        sshLoginsList: cluster.loggedInUser.sshLoginsList.filter(
          login => !login.startsWith('-')
        ),
      },
    };
  }
}

export function makeServer(source: tsh.Server) {
  return {
    uri: source.uri,
    id: source.name,
    clusterId: source.name,
    hostname: source.hostname,
    labels: source.labelsList,
    addr: source.addr,
    tunnel: source.tunnel,
    sshLogins: [],
  };
}

export function makeDatabase(source: tsh.Database) {
  return {
    uri: source.uri,
    name: source.name,
    description: source.desc,
    type: formatDatabaseInfo(
      source.type as DbType,
      source.protocol as DbProtocol
    ).title,
    protocol: source.protocol,
    labels: source.labelsList,
  };
}

export function makeKube(source: tsh.Kube) {
  return {
    uri: source.uri,
    name: source.name,
    labels: source.labelsList,
  };
}
