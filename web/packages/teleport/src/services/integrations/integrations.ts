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

import api from 'teleport/services/api';
import cfg from 'teleport/config';

import makeNode from '../nodes/makeNode';

import {
  Integration,
  IntegrationCreateRequest,
  IntegrationUpdateRequest,
  IntegrationStatusCode,
  IntegrationListResponse,
  AwsOidcListDatabasesRequest,
  AwsRdsDatabase,
  ListAwsRdsDatabaseResponse,
  RdsEngineIdentifier,
  AwsOidcDeployServiceRequest,
  ListEc2InstancesRequest,
  ListEc2InstancesResponse,
  Ec2InstanceConnectEndpoint,
  ListEc2InstanceConnectEndpointsRequest,
  ListEc2InstanceConnectEndpointsResponse,
  ListAwsSecurityGroupsRequest,
  ListAwsSecurityGroupsResponse,
  DeployEc2InstanceConnectEndpointRequest,
  DeployEc2InstanceConnectEndpointResponse,
  SecurityGroup,
  AwsOidcDeployDatabaseServicesRequest,
} from './types';

export const integrationService = {
  fetchIntegration(name: string): Promise<Integration> {
    return api.get(cfg.getIntegrationsUrl(name)).then(makeIntegration);
  },

  fetchIntegrations(): Promise<IntegrationListResponse> {
    return api.get(cfg.getIntegrationsUrl()).then(resp => {
      const integrations = resp?.items ?? [];
      return {
        items: integrations.map(makeIntegration),
        nextKey: resp?.nextKey,
      };
    });
  },

  createIntegration(req: IntegrationCreateRequest): Promise<Integration> {
    return api.post(cfg.getIntegrationsUrl(), req).then(makeIntegration);
  },

  updateIntegration(
    name: string,
    req: IntegrationUpdateRequest
  ): Promise<Integration> {
    return api.put(cfg.getIntegrationsUrl(name), req).then(makeIntegration);
  },

  deleteIntegration(name: string): Promise<void> {
    return api.delete(cfg.getIntegrationsUrl(name));
  },

  fetchThumbprint(): Promise<string> {
    return api.get(cfg.api.thumbprintPath);
  },

  fetchAwsRdsRequiredVpcs(
    integrationName: string,
    body: { region: string; accountId: string }
  ): Promise<Record<string, string[]>> {
    return api
      .post(cfg.getAwsRdsDbRequiredVpcsUrl(integrationName), body)
      .then(resp => resp.vpcMapOfSubnets);
  },

  fetchAwsRdsDatabases(
    integrationName: string,
    rdsEngineIdentifier: RdsEngineIdentifier,
    req: {
      region: AwsOidcListDatabasesRequest['region'];
      nextToken?: AwsOidcListDatabasesRequest['nextToken'];
    }
  ): Promise<ListAwsRdsDatabaseResponse> {
    let body: AwsOidcListDatabasesRequest;
    switch (rdsEngineIdentifier) {
      case 'mysql':
        body = {
          ...req,
          rdsType: 'instance',
          engines: ['mysql', 'mariadb'],
        };
        break;
      case 'postgres':
        body = {
          ...req,
          rdsType: 'instance',
          engines: ['postgres'],
        };
        break;
      case 'aurora-mysql':
        body = {
          ...req,
          rdsType: 'cluster',
          engines: ['aurora-mysql'],
        };
        break;
      case 'aurora-postgres':
        body = {
          ...req,
          rdsType: 'cluster',
          engines: ['aurora-postgresql'],
        };
        break;
    }

    return api
      .post(cfg.getAwsRdsDbListUrl(integrationName), body)
      .then(json => {
        const dbs = json?.databases ?? [];
        return {
          databases: dbs.map(makeAwsDatabase),
          nextToken: json?.nextToken,
        };
      });
  },

  deployAwsOidcService(
    integrationName,
    req: AwsOidcDeployServiceRequest
  ): Promise<string> {
    return api
      .post(cfg.getAwsDeployTeleportServiceUrl(integrationName), req)
      .then(resp => resp.serviceDashboardUrl);
  },

  deployDatabaseServices(
    integrationName,
    req: AwsOidcDeployDatabaseServicesRequest
  ): Promise<string> {
    return api
      .post(cfg.getAwsRdsDbsDeployServicesUrl(integrationName), req)
      .then(resp => resp.clusterDashboardUrl);
  },

  // Returns a list of EC2 Instances using the ListEC2ICE action of the AWS OIDC Integration.
  fetchAwsEc2Instances(
    integrationName,
    req: ListEc2InstancesRequest
  ): Promise<ListEc2InstancesResponse> {
    return api
      .post(cfg.getListEc2InstancesUrl(integrationName), req)
      .then(json => {
        const instances = json?.servers ?? [];
        return {
          instances: instances.map(makeNode),
          nextToken: json?.nextToken,
        };
      });
  },

  // Returns a list of EC2 Instance Connect Endpoints using the ListEC2ICE action of the AWS OIDC Integration.
  fetchAwsEc2InstanceConnectEndpoints(
    integrationName,
    req: ListEc2InstanceConnectEndpointsRequest
  ): Promise<ListEc2InstanceConnectEndpointsResponse> {
    return api
      .post(cfg.getListEc2InstanceConnectEndpointsUrl(integrationName), req)
      .then(json => {
        const endpoints = json?.ec2Ices ?? [];

        return {
          endpoints: endpoints.map(makeEc2InstanceConnectEndpoint),
          nextToken: json?.nextToken,
        };
      });
  },

  // Deploys an EC2 Instance Connect Endpoint.
  deployAwsEc2InstanceConnectEndpoint(
    integrationName,
    req: DeployEc2InstanceConnectEndpointRequest
  ): Promise<DeployEc2InstanceConnectEndpointResponse> {
    return api
      .post(cfg.getDeployEc2InstanceConnectEndpointUrl(integrationName), req)
      .then(json => ({ name: json?.name }));
  },

  // Returns a list of VPC Security Groups using the ListSecurityGroups action of the AWS OIDC Integration.
  fetchSecurityGroups(
    integrationName,
    req: ListAwsSecurityGroupsRequest
  ): Promise<ListAwsSecurityGroupsResponse> {
    return api
      .post(cfg.getListSecurityGroupsUrl(integrationName), req)
      .then(json => {
        const securityGroups = json?.securityGroups ?? [];

        return {
          securityGroups: securityGroups.map(makeSecurityGroup),
          nextToken: json?.nextToken,
        };
      });
  },
};

export function makeIntegrations(json: any): Integration[] {
  json = json || [];
  return json.map(user => makeIntegration(user));
}

function makeIntegration(json: any): Integration {
  json = json || {};
  const { name, subKind, awsoidc } = json;
  return {
    resourceType: 'integration',
    name,
    kind: subKind,
    spec: {
      roleArn: awsoidc?.roleArn,
      issuerS3Bucket: awsoidc?.issuerS3Bucket,
      issuerS3Prefix: awsoidc?.issuerS3Prefix,
    },
    // The integration resource does not have a "status" field, but is
    // a required field for the table that lists both plugin and
    // integration resources together. As discussed, the only
    // supported status for integration is `Running` for now:
    // https://github.com/gravitational/teleport/pull/22556#discussion_r1158674300
    statusCode: IntegrationStatusCode.Running,
  };
}

export function makeAwsDatabase(json: any): AwsRdsDatabase {
  json = json ?? {};
  const { aws, name, uri, labels, protocol } = json;

  return {
    engine: protocol,
    name,
    uri,
    status: aws?.status,
    labels: labels ?? [],
    subnets: aws?.rds?.subnets,
    resourceId: aws?.rds?.resource_id,
    vpcId: aws?.rds?.vpc_id,
    accountId: aws?.account_id,
    region: aws?.region,
  };
}

function makeEc2InstanceConnectEndpoint(json: any): Ec2InstanceConnectEndpoint {
  json = json ?? {};
  const { name, state, stateMessage, dashboardLink, subnetId } = json;

  return {
    name,
    state,
    stateMessage,
    dashboardLink,
    subnetId,
  };
}

function makeSecurityGroup(json: any): SecurityGroup {
  json = json ?? {};

  const { name, id, description = '', inboundRules, outboundRules } = json;

  return {
    name,
    id,
    description,
    inboundRules: inboundRules ?? [],
    outboundRules: outboundRules ?? [],
  };
}
