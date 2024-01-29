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

import React, { useState, useRef } from 'react';
import { MenuLogin, MenuLoginProps } from 'shared/components/MenuLogin';
import { AwsLaunchButton } from 'shared/components/AwsLaunchButton';
import { ButtonBorder, MenuItem, Flex } from 'design';
import * as icons from 'design/Icon';
import Menu from 'design/Menu';

import {
  connectToServer,
  connectToDatabase,
  connectToKube,
  connectToApp,
  captureAppLaunchInBrowser,
} from 'teleterm/ui/services/workspacesService';
import { useAppContext } from 'teleterm/ui/appContextProvider';
import {
  Server,
  Kube,
  GatewayProtocol,
  Database,
  App,
  Cluster,
} from 'teleterm/services/tshd/types';

import { DatabaseUri, routing } from 'teleterm/ui/uri';
import { IAppContext } from 'teleterm/ui/types';
import { retryWithRelogin } from 'teleterm/ui/utils';
import {
  getWebAppLaunchUrl,
  isWebApp,
  getAwsAppLaunchUrl,
} from 'teleterm/services/tshd/app';

export function ConnectServerActionButton(props: {
  server: Server;
}): React.JSX.Element {
  const ctx = useAppContext();

  function getSshLogins(): string[] {
    const cluster = ctx.clustersService.findClusterByResource(props.server.uri);
    return cluster?.loggedInUser?.sshLogins || [];
  }

  function connect(login: string): void {
    const { uri, hostname } = props.server;
    connectToServer(
      ctx,
      { uri, hostname, login },
      {
        origin: 'resource_table',
      }
    );
  }

  return (
    <MenuLogin
      textTransform="none"
      getLoginItems={() => getSshLogins().map(login => ({ login, url: '' }))}
      onSelect={(e, login) => connect(login)}
      transformOrigin={{
        vertical: 'top',
        horizontal: 'right',
      }}
      anchorOrigin={{
        vertical: 'center',
        horizontal: 'right',
      }}
    />
  );
}

export function ConnectKubeActionButton(props: {
  kube: Kube;
}): React.JSX.Element {
  const appContext = useAppContext();

  function connect(): void {
    connectToKube(
      appContext,
      { uri: props.kube.uri },
      { origin: 'resource_table' }
    );
  }

  return (
    <ButtonBorder textTransform="none" size="small" onClick={connect}>
      Connect
    </ButtonBorder>
  );
}

export function ConnectAppActionButton(props: { app: App }): React.JSX.Element {
  const appContext = useAppContext();

  function connect(): void {
    connectToApp(appContext, props.app, { origin: 'resource_table' });
  }

  const rootCluster = appContext.clustersService.findCluster(
    routing.ensureRootClusterUri(props.app.uri)
  );
  const cluster = appContext.clustersService.findClusterByResource(
    props.app.uri
  );

  return (
    <AppButton
      connect={connect}
      app={props.app}
      cluster={cluster}
      rootCluster={rootCluster}
      onLaunchUrl={() => {
        captureAppLaunchInBrowser(appContext, props.app, {
          origin: 'resource_table',
        });
      }}
    />
  );
}

export function ConnectDatabaseActionButton(props: {
  database: Database;
}): React.JSX.Element {
  const appContext = useAppContext();

  function connect(dbUser: string): void {
    const { uri, name, protocol } = props.database;
    connectToDatabase(
      appContext,
      { uri, name, protocol, dbUser },
      { origin: 'resource_table' }
    );
  }

  return (
    <MenuLogin
      {...getDatabaseMenuLoginOptions(
        props.database.protocol as GatewayProtocol
      )}
      textTransform="none"
      width="195px"
      getLoginItems={() => getDatabaseUsers(appContext, props.database.uri)}
      onSelect={(_, user) => {
        connect(user);
      }}
      transformOrigin={{
        vertical: 'top',
        horizontal: 'right',
      }}
      anchorOrigin={{
        vertical: 'center',
        horizontal: 'right',
      }}
    />
  );
}

function getDatabaseMenuLoginOptions(
  protocol: GatewayProtocol
): Pick<MenuLoginProps, 'placeholder' | 'required'> {
  if (protocol === 'redis') {
    return {
      placeholder: 'Enter username (optional)',
      required: false,
    };
  }

  return {
    placeholder: 'Enter username',
    required: true,
  };
}

async function getDatabaseUsers(appContext: IAppContext, dbUri: DatabaseUri) {
  try {
    const dbUsers = await retryWithRelogin(appContext, dbUri, () =>
      appContext.resourcesService.getDbUsers(dbUri)
    );
    return dbUsers.map(user => ({ login: user, url: '' }));
  } catch (e) {
    // Emitting a warning instead of an error here because fetching those username suggestions is
    // not the most important part of the app.
    appContext.notificationsService.notifyWarning({
      title: 'Could not fetch database usernames',
      description: e.message,
    });

    throw e;
  }
}

function AppButton(props: {
  app: App;
  cluster: Cluster;
  rootCluster: Cluster;
  connect(): void;
  onLaunchUrl(): void;
}) {
  const ref = useRef<HTMLButtonElement>();
  const [isOpen, setIsOpen] = useState(false);

  if (props.app.awsConsole) {
    return (
      <AwsLaunchButton
        awsRoles={props.app.awsRoles}
        getLaunchUrl={arn =>
          getAwsAppLaunchUrl({
            app: props.app,
            rootCluster: props.rootCluster,
            cluster: props.cluster,
            arn,
          })
        }
      />
    );
  }

  if (isWebApp(props.app)) {
    return (
      <Flex>
        <ButtonBorder
          textTransform="none"
          size="small"
          forwardedAs="a"
          href={getWebAppLaunchUrl({
            app: props.app,
            rootCluster: props.rootCluster,
            cluster: props.cluster,
          })}
          onClick={props.onLaunchUrl}
          target="_blank"
          title="Launch app in the browser"
          css={`
            border-top-right-radius: 0;
            border-bottom-right-radius: 0;
          `}
        >
          Launch
        </ButtonBorder>
        <ButtonBorder
          css={`
            border-left: none;
            border-top-left-radius: 0;
            border-bottom-left-radius: 0;
          `}
          setRef={ref}
          px={1}
          size="small"
          onClick={() => setIsOpen(true)}
        >
          {/*
            Using MoreVert instead of ChevronDown to make this button visually distinct from the
            button that launches an AWS app.
          */}
          <icons.MoreVert size="small" color="text.slightlyMuted" />
        </ButtonBorder>
        <Menu
          anchorEl={ref.current}
          open={isOpen}
          onClose={() => setIsOpen(false)}
          // hack to properly position the menu
          getContentAnchorEl={null}
          anchorOrigin={{
            vertical: 'bottom',
            horizontal: 'right',
          }}
          transformOrigin={{
            vertical: 'top',
            horizontal: 'right',
          }}
        >
          <MenuItem
            onClick={() => {
              setIsOpen(false);
              props.connect();
            }}
          >
            Set up connection
          </MenuItem>
        </Menu>
      </Flex>
    );
  }

  return (
    <ButtonBorder size="small" onClick={props.connect} textTransform="none">
      Connect
    </ButtonBorder>
  );
}
