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

import React from 'react';
import { Link } from 'react-router-dom';
import { Text, Image } from 'design';
import awsIcon from 'design/assets/images/icons/aws.svg';

import cfg from 'teleport/config';
import { ToolTipNoPermBadge } from 'teleport/components/ToolTipNoPermBadge';

import { IntegrationTile } from './common';

// IntegrationTiles is plural but at the moment we only
// support aws-oidc. Expecting this to grow.
export function IntegrationTiles({
  hasAccess = true,
}: {
  hasAccess?: boolean;
}) {
  return (
    <IntegrationTile
      disabled={!hasAccess}
      as={hasAccess ? Link : null}
      to={hasAccess ? cfg.getIntegrationEnrollRoute('aws-oidc') : null}
    >
      <Image mt={3} mb={2} src={awsIcon} width="80px" height="80px" />
      <Text>
        Amazon Web Services
        <br />
        OIDC
      </Text>
      {!hasAccess && (
        <ToolTipNoPermBadge
          children={`You do not have access to create integrations`}
        />
      )}
    </IntegrationTile>
  );
}
