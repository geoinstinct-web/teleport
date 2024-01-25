/**
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
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

import React, { useCallback, useEffect } from 'react';

import { useLocation, useParams } from 'react-router';

import { Flex, Indicator } from 'design';

import { AccessDenied } from 'design/CardError';

import useAttempt from 'shared/hooks/useAttemptNext';

import { UrlLauncherParams } from 'teleport/config';
import service from 'teleport/services/apps';

export function AppLauncher() {
  const { attempt, setAttempt } = useAttempt('processing');

  const pathParams = useParams<UrlLauncherParams>();
  const { search } = useLocation();
  const queryParams = new URLSearchParams(search);

  const createAppSession = useCallback(async (params: UrlLauncherParams) => {
    let fqdn = params.fqdn;
    const port = location.port ? `:${location.port}` : '';

    try {
      let path = '';
      if (queryParams.has('path')) {
        path = queryParams.get('path');

        if (path && !path.startsWith('/')) {
          path = `/${path}`;
        }

        if (queryParams.has('query')) {
          path += '?' + queryParams.get('query');
        }
      }

      // Let the target app know of a new auth exchange.
      const stateToken = queryParams.get('state');
      if (!stateToken) {
        initiateNewAuthExchange({ fqdn, port, path, params });
        return;
      }

      // Continue the auth exchange.

      if (params.arn) {
        params.arn = decodeURIComponent(params.arn);
      }
      const session = await service.createAppSession(params);

      // Set all the fields expected by server to validate request.
      const url = getXTeleportAuthUrl({ fqdn, port });
      url.searchParams.set('state', stateToken);
      url.searchParams.set('subject', session.subjectCookieValue);
      url.hash = `#value=${session.cookieValue}`;

      if (path) {
        url.searchParams.set('path', path);
      }

      // This will load an empty HTML with the inline JS containing
      // logic to finish the auth exchange.
      window.location.replace(url.toString());
    } catch (err) {
      let statusText = 'Something went wrong';

      if (err instanceof TypeError) {
        // `fetch` returns `TypeError` when there is a network error.
        statusText = `Unable to access "${fqdn}". This may happen if your Teleport Proxy is using untrusted or self-signed certificate. Please ensure Teleport Proxy service uses valid certificate or access the application domain directly (https://${fqdn}${port}) and accept the certificate exception from your browser.`;
      } else if (err instanceof Error) {
        statusText = err.message;
      }

      setAttempt({
        status: 'failed',
        statusText,
      });
    }
  }, []);

  useEffect(() => {
    createAppSession(pathParams);
  }, [pathParams]);

  if (attempt.status === 'failed') {
    return <AppLauncherAccessDenied statusText={attempt.statusText} />;
  }

  return <AppLauncherProcessing />;
}

export function AppLauncherProcessing() {
  return (
    <Flex height="180px" justifyContent="center" alignItems="center" flex="1">
      <Indicator />
    </Flex>
  );
}

interface AppLauncherAccessDeniedProps {
  statusText: string;
}

export function AppLauncherAccessDenied(props: AppLauncherAccessDeniedProps) {
  return <AccessDenied message={props.statusText} />;
}

function getXTeleportAuthUrl({ fqdn, port }: { fqdn: string; port: string }) {
  return new URL(`https://${fqdn}${port}/x-teleport-auth`);
}

// initiateNewAuthExchange is the first step to gaining access to an
// application.
//
// It can be initiated in two ways:
//   1) user clicked our "launch" app button from the resource list
//      screen which will route the user in-app to this launcher.
//   2) user hits the app endpoint directly (eg: cliking on a
//      bookmarked URL), in which the server will redirect the user
//      to this launcher.
function initiateNewAuthExchange({
  fqdn,
  port,
  params,
  path,
}: {
  fqdn: string;
  port: string;
  // params will only be defined if the user clicked our "launch"
  // app button from the web UI.
  // The route is formatted as (cfg.routes.appLauncher):
  // "/web/launch/:fqdn/:clusterId?/:publicAddr?/:arn?"
  params: UrlLauncherParams;
  // path will only be defined, if a user hit the app endpoint
  // directly. This path is created in the server.
  // The path preserves both the path and query params of
  // the original request.
  path: string;
}) {
  const url = getXTeleportAuthUrl({ fqdn, port });

  if (path) {
    url.searchParams.set('path', path);
  }

  // Preserve "params" so that the initial auth exchange can
  // reconstruct and redirect back to the original web
  // launcher URL.
  //
  // These params are important when we create an app session
  // later in the flow, where it enables the server to lookup
  // the app directly.
  if (params.clusterId) {
    url.searchParams.set('cluster', params.clusterId);
  }
  if (params.publicAddr) {
    url.searchParams.set('addr', params.publicAddr);
  }
  if (params.arn) {
    url.searchParams.set('arn', params.arn);
  }

  window.location.replace(url.toString());
}
