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

import React, { ComponentProps } from 'react';

import { useTheme } from 'styled-components';

import { Image } from 'design';

import appleDark from './assets/apple-dark.svg';
import appleLight from './assets/apple-light.svg';
import application from './assets/application.svg';
import awsDark from './assets/aws-dark.svg';
import awsLight from './assets/aws-light.svg';
import azure from './assets/azure.svg';
import cockroachDark from './assets/cockroach-dark.svg';
import cockroachLight from './assets/cockroach-light.svg';
import database from './assets/database.svg';
import dynamo from './assets/dynamo.svg';
import ec2 from './assets/ec2.svg';
import eks from './assets/eks.svg';
import gcp from './assets/gcp.svg';
import grafana from './assets/grafana.svg';
import jenkins from './assets/jenkins.svg';
import kube from './assets/kube.svg';
import linuxDark from './assets/linux-dark.svg';
import linuxLight from './assets/linux-light.svg';
import mongoDark from './assets/mongo-dark.svg';
import mongoLight from './assets/mongo-light.svg';
import mysqlLargeDark from './assets/mysql-large-dark.svg';
import mysqlLargeLight from './assets/mysql-large-light.svg';
import mysqlSmallDark from './assets/mysql-small-dark.svg';
import mysqlSmallLight from './assets/mysql-small-light.svg';
import postgres from './assets/postgres.svg';
import redshift from './assets/redshift.svg';
import server from './assets/server.svg';
import slack from './assets/slack.svg';
import snowflake from './assets/snowflake.svg';
import windowsDark from './assets/windows-dark.svg';
import windowsLight from './assets/windows-light.svg';

interface ResourceIconProps extends ComponentProps<typeof Image> {
  /**
   * Determines which icon will be displayed. See `iconSpecs` for the list of
   * available names.
   */
  name: ResourceIconName;
}

/**
 * Displays a resource icon of a given name for current theme. The icon
 * component exposes props of the underlying `Image`.
 */
export const ResourceIcon = ({ name, ...props }: ResourceIconProps) => {
  const theme = useTheme();
  const icon = iconSpecs[name]?.[theme.name];
  if (!icon) {
    return null;
  }
  return <Image src={icon} {...props} />;
};

/** Uses given icon for all themes. */
const forAllThemes = icon => ({ dark: icon, light: icon });

/** A name->theme->spec mapping of resource icons. */
const iconSpecs = {
  Apple: { dark: appleDark, light: appleLight },
  Application: forAllThemes(application),
  Aws: { dark: awsDark, light: awsLight },
  Azure: forAllThemes(azure),
  Cockroach: { dark: cockroachDark, light: cockroachLight },
  Database: forAllThemes(database),
  Dynamo: forAllThemes(dynamo),
  Ec2: forAllThemes(ec2),
  Eks: forAllThemes(eks),
  Gcp: forAllThemes(gcp),
  Grafana: forAllThemes(grafana),
  Jenkins: forAllThemes(jenkins),
  Kube: forAllThemes(kube),
  Linux: { dark: linuxDark, light: linuxLight },
  Mongo: { dark: mongoDark, light: mongoLight },
  MysqlLarge: { dark: mysqlLargeDark, light: mysqlLargeLight },
  MysqlSmall: { dark: mysqlSmallDark, light: mysqlSmallLight },
  Postgres: forAllThemes(postgres),
  Redshift: forAllThemes(redshift),
  SelfHosted: forAllThemes(database),
  Server: forAllThemes(server),
  Slack: forAllThemes(slack),
  Snowflake: forAllThemes(snowflake),
  Windows: { dark: windowsDark, light: windowsLight },
};

export type ResourceIconName = keyof typeof iconSpecs;

/** All icon names, exported for testing purposes. */
export const iconNames = Object.keys(iconSpecs) as ResourceIconName[];
