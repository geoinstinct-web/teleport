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

import { App, Cluster } from 'teleterm/services/tshd/types';

/** Returns a URL that can be used to open the web app in the browser. */
export function getWebAppLaunchUrl({
  app,
  cluster,
  rootCluster,
}: {
  app: App;
  rootCluster: Cluster;
  cluster: Cluster;
}): string {
  if (!isWebApp(app)) {
    return '';
  }

  const { fqdn, publicAddr } = app;
  return `https://${rootCluster.proxyHost}/web/launch/${fqdn}/${cluster.name}/${publicAddr}`;
}

/** Returns a URL that can be used to open the AWS app in the browser. */
export function getAwsAppLaunchUrl({
  app,
  cluster,
  rootCluster,
  arn,
}: {
  app: App;
  rootCluster: Cluster;
  cluster: Cluster;
  arn: string;
}): string {
  if (!app.awsConsole) {
    return '';
  }

  const { fqdn, publicAddr } = app;
  return `https://${rootCluster.proxyHost}/web/launch/${fqdn}/${
    cluster.name
  }/${publicAddr}/${encodeURIComponent(arn)}`;
}

export function isWebApp(app: App): boolean {
  if (app.samlApp || app.awsConsole) {
    return false;
  }
  return (
    app.endpointUri.startsWith('http://') ||
    app.endpointUri.startsWith('https://')
  );
}
