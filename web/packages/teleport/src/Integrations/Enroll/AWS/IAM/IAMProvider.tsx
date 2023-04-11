import React from 'react';
import styled from 'styled-components';

import Flex from 'design/Flex';
import Box from 'design/Box';

import { Stage } from '../stages';

import { AWSWrapper, BreadcrumbArrow } from './SharedComponents';

import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbItemActive,
  Content,
  Page,
  RoleButton,
  Title,
} from './common';

import { AssignRoleModal } from './AssignRoleModal';

import type { CommonIAMProps } from './common';

const AWSHeader = styled.div`
  font-weight: bold;
  font-size: 18px;
  margin-bottom: 10px;
  display: flex;
`;

const AWSHeaderCount = styled.div`
  font-weight: 400;
  opacity: 0.5;
  margin-left: 10px;
`;

const SummaryContent = styled.div`
  display: flex;
  border-top: 1px solid #cccccc;
  padding-top: 10px;
  margin-bottom: 40px;
`;

const SummaryItem = styled.div`
  display: flex;
  flex-direction: column;
  min-width: 200px;
  border-right: 1px solid #ccc;
  padding-left: 10px;

  &:first-of-type {
    padding: 0;
  }

  &:last-of-type {
    border-right: none;
  }
`;

export function IAMProvider(props: CommonIAMProps) {
  const showAssignRoleModal = props.stage >= Stage.ShowAssignRoleModal;

  return (
    <AWSWrapper>
      <Page>
        {showAssignRoleModal && <AssignRoleModal />}

        <Content>
          <Breadcrumb>
            <BreadcrumbItem>IAM</BreadcrumbItem>
            <BreadcrumbArrow />
            <BreadcrumbItem>Identity providers</BreadcrumbItem>
            <BreadcrumbArrow />
            <BreadcrumbItemActive>teleport.lol</BreadcrumbItemActive>
          </Breadcrumb>

          <Flex
            mt={5}
            alignItems="center"
            justifyContent="space-between"
            mb={5}
          >
            <Title style={{ marginBottom: 0 }}>teleport.lol</Title>

            <RoleButton>Assign role</RoleButton>
          </Flex>

          <AWSHeader>Summary</AWSHeader>

          <SummaryContent>
            <SummaryItem>
              Provider
              <div style={{ marginTop: 10 }}>teleport.lol</div>
            </SummaryItem>
            <SummaryItem>
              Provider Type
              <div style={{ marginTop: 10 }}>OpenID Connect</div>
            </SummaryItem>
            <SummaryItem>
              Creation Time
              <div style={{ marginTop: 10 }}>1 minute ago</div>
            </SummaryItem>
          </SummaryContent>

          <Flex justifyContent="space-between">
            <Box width="48%">
              <AWSHeader>
                Audiences <AWSHeaderCount>(1)</AWSHeaderCount>
              </AWSHeader>
            </Box>

            <Box width="48%">
              <AWSHeader>
                Thumbprints <AWSHeaderCount>(1)</AWSHeaderCount>
              </AWSHeader>
            </Box>
          </Flex>
        </Content>
      </Page>
    </AWSWrapper>
  );
}
