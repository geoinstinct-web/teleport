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

import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Box,
  ButtonLink,
  Text,
  ButtonPrimary,
  Indicator,
  Alert,
  Flex,
} from 'design';
import FieldSelect from 'shared/components/FieldSelect';
import useAttempt from 'shared/hooks/useAttemptNext';
import { Option } from 'shared/components/Select';
import Validation, { Validator } from 'shared/components/Validation';
import { requiredField } from 'shared/components/Validation/rules';
import TextEditor from 'shared/components/TextEditor';

import cfg from 'teleport/config';
import {
  IntegrationKind,
  integrationService,
} from 'teleport/services/integrations';
import { integrationRWE } from 'teleport/Discover/yamlTemplates';
import useTeleport from 'teleport/useTeleport';

import { ActionButtons, HeaderSubtitle, HeaderWithBackBtn } from '../../Shared';

import { DbMeta, useDiscover } from '../../useDiscover';

export function ConnectAwsAccount() {
  const { storeUser } = useTeleport();
  const { prevStep, nextStep, agentMeta, updateAgentMeta, eventState } =
    useDiscover();

  // TODO(lisa): also need to check for verb `use` which is pending
  // work.
  const access = storeUser.getIntegrationsAccess();
  const hasAccess = access.create && access.list;
  const { attempt, run } = useAttempt(hasAccess ? 'processing' : '');

  const [awsIntegrations, setAwsIntegrations] = useState<Option[]>([]);
  const [selectedAwsIntegration, setSelectedAwsIntegration] =
    useState<Option>();

  useEffect(() => {
    if (hasAccess) {
      fetchAwsIntegrations();
    }
  }, []);

  function fetchAwsIntegrations() {
    run(() =>
      integrationService.fetchIntegrations().then(res => {
        const options = res.items.map(i => {
          if (i.kind === 'aws-oidc') {
            return {
              value: i.name,
              label: i.name,
            };
          }
        });
        setAwsIntegrations(options);
      })
    );
  }

  if (!hasAccess) {
    return (
      <Box maxWidth="700px">
        <Header prevStep={prevStep} />
        <Box maxWidth="700px">
          <Text mt={4} width="100px">
            You don’t have the required permissions for integrating.
            <br />
            Ask your Teleport administrator to update your role with the
            following:
          </Text>
          <Flex minHeight="215px" mt={3}>
            <TextEditor
              readOnly={true}
              data={[{ content: integrationRWE, type: 'yaml' }]}
            />
          </Flex>
        </Box>
      </Box>
    );
  }

  if (attempt.status === 'processing') {
    return (
      <Box maxWidth="700px">
        <Header prevStep={prevStep} />
        <Box textAlign="center" m={10}>
          <Indicator />
        </Box>
      </Box>
    );
  }

  if (attempt.status === 'failed') {
    return (
      <Box maxWidth="700px">
        <Header prevStep={prevStep} />
        <Alert kind="danger" children={attempt.statusText} />
        <ButtonPrimary mt={2} onClick={fetchAwsIntegrations}>
          Retry
        </ButtonPrimary>
      </Box>
    );
  }

  function proceedWithExistingIntegration(validator: Validator) {
    if (!validator.validate()) {
      return;
    }

    updateAgentMeta({
      ...(agentMeta as DbMeta),
      awsIntegrationName: selectedAwsIntegration.value,
    });

    // TODO(lisa): Need to add a new event to emit for this screen.
    nextStep();
  }

  const hasAwsIntegrations = awsIntegrations.length > 0;
  const locationState = {
    pathname: cfg.getIntegrationEnrollRoute(IntegrationKind.AwsOidc),
    state: { discoverEventId: eventState?.id },
  };
  return (
    <Box maxWidth="700px">
      <Header prevStep={prevStep} />
      <Box mb={3}>
        <Validation>
          {({ validator }) => (
            <>
              {hasAwsIntegrations ? (
                <>
                  <Text mb={2}>
                    Select the name of the AWS integration to use:
                  </Text>
                  <Box width="300px" mb={6}>
                    <FieldSelect
                      disabled
                      label="AWS Integrations"
                      rule={requiredField('Region is required')}
                      placeholder="Select the AWS Integration to Use"
                      isSearchable
                      isSimpleValue
                      value={selectedAwsIntegration}
                      onChange={i => setSelectedAwsIntegration(i as Option)}
                      options={awsIntegrations}
                    />
                  </Box>
                  <ButtonLink as={Link} to={locationState} pl={0}>
                    Or click here to set up a different AWS account
                  </ButtonLink>
                </>
              ) : (
                <ButtonPrimary
                  mt={2}
                  mb={2}
                  size="large"
                  as={Link}
                  to={locationState}
                >
                  Set up AWS Account
                </ButtonPrimary>
              )}

              <ActionButtons
                onProceed={() => proceedWithExistingIntegration(validator)}
                disableProceed={!hasAwsIntegrations || !selectedAwsIntegration}
              />
            </>
          )}
        </Validation>
      </Box>
    </Box>
  );
}

const Header = ({ prevStep }: { prevStep(): void }) => (
  <>
    <HeaderWithBackBtn onPrev={prevStep}>
      Connect to your AWS Account
    </HeaderWithBackBtn>
    <HeaderSubtitle>
      Instead of storing long-lived static credentials, Teleport will request
      short-lived credentials from AWS to perform operations automatically.
    </HeaderSubtitle>
  </>
);
