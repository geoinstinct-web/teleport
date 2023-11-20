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
import { useTheme } from 'styled-components';
import { Link } from 'react-router-dom';
import { Text, Box } from 'design';
import { AWSIcon } from 'design/SVGIcon';

import cfg from 'teleport/config';
import {
  BadgeTitle,
  ToolTipNoPermBadge,
} from 'teleport/components/ToolTipNoPermBadge';
import { IntegrationKind } from 'teleport/services/integrations';

import { ToolTipBadge } from 'teleport/components/ToolTipBadge';

import { IntegrationTile } from './common';

export function IntegrationTiles({
  hasIntegrationAccess = true,
  hasExternalCloudAuditAccess = true,
}: {
  hasIntegrationAccess?: boolean;
  hasExternalCloudAuditAccess?: boolean;
}) {
  // TODO(mcbattirola): isUsageBasedBilling is used here and in other
  // parts of the app as synonym with Team product, but this
  // will change in the future.
  const isEnterprise = cfg.isEnterprise && !cfg.isUsageBasedBilling;

  return (
    <>
      <IntegrationTile
        disabled={!hasIntegrationAccess}
        as={hasIntegrationAccess ? Link : null}
        to={
          hasIntegrationAccess
            ? cfg.getIntegrationEnrollRoute(IntegrationKind.AwsOidc)
            : null
        }
        data-testid="tile-aws-oidc"
      >
        <Box mt={3} mb={2}>
          <AWSIcon size={80} />
        </Box>
        <Text>
          Amazon Web Services
          <br />
          OIDC
        </Text>
        {!hasIntegrationAccess && (
          <ToolTipNoPermBadge
            children={
              <div>
                You don’t have sufficient permissions to create an integration.
                Reach out to your Teleport administrator to request additional
                permissions.
              </div>
            }
          />
        )}
      </IntegrationTile>
      <IntegrationTile
        disabled={!hasExternalCloudAuditAccess || !isEnterprise}
        as={hasExternalCloudAuditAccess ? Link : null}
        to={
          hasExternalCloudAuditAccess
            ? cfg.getIntegrationEnrollRoute(IntegrationKind.Byob)
            : null
        }
        data-testid="tile-byob"
      >
        <Box mt={3} mb={2}>
          <AWSIcon size={80} />
        </Box>
        <Text>AWS External Audit Storage</Text>
        {renderExternalCloudAuditBadge(
          hasExternalCloudAuditAccess,
          isEnterprise
        )}
      </IntegrationTile>
    </>
  );
}

function renderExternalCloudAuditBadge(
  hasExternalCloudAuditAccess: boolean,
  isEnterprise: boolean
) {
  const theme = useTheme();

  if (!isEnterprise)
    return (
      <ToolTipNoPermBadge
        badgeTitle={BadgeTitle.LackingEnterpriseLicense}
        children={
          <div>Unlock External Cloud Audit with Teleport Enterprise</div>
        }
      />
    );
  if (!hasExternalCloudAuditAccess) {
    return (
      <ToolTipNoPermBadge
        children={
          <div>
            You don’t have sufficient permissions to create an External Cloud
            Audit. Reach out to your Teleport administrator to request
            additional permissions.
          </div>
        }
      />
    );
  }

  return (
    <ToolTipBadge
      badgeTitle="New"
      children={
        <div>
          Connect your own AWS account to store Audit logs and Session recordings using Athena and S3.
        </div>
      }
      color={theme.colors.success}
    />
  );
}
