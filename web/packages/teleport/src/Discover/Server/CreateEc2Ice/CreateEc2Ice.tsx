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

import React, { useState, useEffect } from 'react';

import { Box, Indicator, Text, Flex } from 'design';
import { Danger } from 'design/Alert';
import { FetchStatus } from 'design/DataTable/types';

import useAttempt from 'shared/hooks/useAttemptNext';
import { getErrMessage } from 'shared/utils/errorType';

import {
  SecurityGroup,
  integrationService,
} from 'teleport/services/integrations';
import { NodeMeta, useDiscover } from 'teleport/Discover/useDiscover';
import {
  ActionButtons,
  Header,
  SecurityGroupPicker,
} from 'teleport/Discover/Shared';

import { CreateEc2IceDialog } from './CreateEc2IceDialog';

type TableData = {
  items: SecurityGroup[];
  nextToken?: string;
  fetchStatus: FetchStatus;
};

export function CreateEc2Ice() {
  const [showCreatingDialog, setShowCreatingDialog] = useState(false);
  const [selectedSecurityGroups, setSelectedSecurityGroups] = useState<
    string[]
  >([]);
  const [tableData, setTableData] = useState<TableData>({
    items: [],
    nextToken: '',
    fetchStatus: 'disabled',
  });

  function onSelectSecurityGroup(
    sg: SecurityGroup,
    e: React.ChangeEvent<HTMLInputElement>
  ) {
    if (e.target.checked) {
      return setSelectedSecurityGroups([...selectedSecurityGroups, sg.id]);
    } else {
      setSelectedSecurityGroups(
        selectedSecurityGroups.filter(id => id !== sg.id)
      );
    }
  }

  useEffect(() => {
    fetchSecurityGroups();
  }, []);

  const {
    attempt: fetchSecurityGroupsAttempt,
    setAttempt: setFetchSecurityGroupsAttempt,
  } = useAttempt('');

  const { attempt: deployEc2IceAttempt, setAttempt: setDeployEc2IceAttempt } =
    useAttempt('');

  const { emitErrorEvent, agentMeta, prevStep, nextStep } = useDiscover();

  async function fetchSecurityGroups() {
    const integration = (agentMeta as NodeMeta).integration;

    setFetchSecurityGroupsAttempt({ status: 'processing' });
    try {
      const { securityGroups, nextToken } =
        await integrationService.fetchSecurityGroups(integration.name, {
          vpcId: (agentMeta as NodeMeta).node.awsMetadata.vpcId,
          region: (agentMeta as NodeMeta).node.awsMetadata.region,
          nextToken: tableData.nextToken,
        });

      setFetchSecurityGroupsAttempt({ status: 'success' });
      setTableData({
        nextToken: nextToken,
        fetchStatus: nextToken ? '' : 'disabled',
        items: [...tableData.items, ...securityGroups],
      });
    } catch (err) {
      const errMsg = getErrMessage(err);
      setFetchSecurityGroupsAttempt({ status: 'failed', statusText: errMsg });
      emitErrorEvent(`fetch security groups error: ${errMsg}`);
    }
  }

  async function deployEc2InstanceConnectEndpoint() {
    const integration = (agentMeta as NodeMeta).integration;

    setDeployEc2IceAttempt({ status: 'processing' });
    setShowCreatingDialog(true);
    try {
      await integrationService.deployAwsEc2InstanceConnectEndpoint(
        integration.name,
        {
          region: (agentMeta as NodeMeta).node.awsMetadata.region,
          subnetId: (agentMeta as NodeMeta).node.awsMetadata.subnetId,
          ...(selectedSecurityGroups.length && {
            securityGroupIds: selectedSecurityGroups,
          }),
        }
      );
      // Capture event for deploying EICE.
      // emitEvent(null); TODO rudream (ADD EVENTS FOR EICE FLOW)
    } catch (err) {
      const errMsg = getErrMessage(err);
      setShowCreatingDialog(false);
      setDeployEc2IceAttempt({ status: 'failed', statusText: errMsg });
      emitErrorEvent(
        `ec2 instance connect endpoint deploying failed: ${errMsg}`
      );
    }
  }

  function handleOnProceed() {
    deployEc2InstanceConnectEndpoint();
  }

  return (
    <>
      <Box maxWidth="800px">
        <Header>Create an EC2 Instance Connect Endpoint</Header>
        <Box width="800px">
          {deployEc2IceAttempt.status === 'failed' && (
            <Danger>{deployEc2IceAttempt.statusText}</Danger>
          )}
          <Text mb={1} typography="h4">
            Select AWS Security Groups to assign to the new EC2 Instance Connect
            Endpoint:
          </Text>
          <Text mb={2}>
            The security groups you pick should allow outbound connectivity for
            the agent to be able to dial Teleport clusters. If you don't select
            any security groups, the default one for the VPC will be used.
          </Text>
          {fetchSecurityGroupsAttempt.status === 'failed' && (
            <Danger>{fetchSecurityGroupsAttempt.statusText}</Danger>
          )}
          {fetchSecurityGroupsAttempt.status === 'processing' && (
            <Flex width="352px" justifyContent="center" mt={3}>
              <Indicator />
            </Flex>
          )}
          {fetchSecurityGroupsAttempt.status === 'success' && (
            <Box width="1000px">
              <SecurityGroupPicker
                items={tableData.items}
                attempt={fetchSecurityGroupsAttempt}
                fetchNextPage={() => fetchSecurityGroups()}
                fetchStatus={tableData.fetchStatus}
                onSelectSecurityGroup={onSelectSecurityGroup}
                selectedSecurityGroups={selectedSecurityGroups}
              />
            </Box>
          )}
        </Box>
        <ActionButtons
          onPrev={prevStep}
          onProceed={() => handleOnProceed()}
          disableProceed={deployEc2IceAttempt.status === 'processing'}
        />
      </Box>
      {showCreatingDialog && (
        <CreateEc2IceDialog
          nextStep={nextStep}
          retry={() => deployEc2InstanceConnectEndpoint()}
        />
      )}
    </>
  );
}
