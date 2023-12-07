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

import React, { useState } from 'react';
import { ButtonSecondary, Text, Box, LabelInput } from 'design';
import Select from 'shared/components/Select';

import cfg from 'teleport/config';
import ReAuthenticate from 'teleport/components/ReAuthenticate';
import { openNewTab } from 'teleport/lib/util';
import {
  useConnectionDiagnostic,
  Header,
  ActionButtons,
  HeaderSubtitle,
  ConnectionDiagnosticResult,
  StyledBox,
} from 'teleport/Discover/Shared';
import { sortNodeLogins } from 'teleport/services/nodes';

import { NodeMeta } from '../../useDiscover';

import type { Option } from 'shared/components/Select';
import type { AgentStepProps } from '../../types';
import type { MfaAuthnResponse } from 'teleport/services/mfa';

export function TestConnection(props: AgentStepProps) {
  const {
    runConnectionDiagnostic,
    attempt,
    diagnosis,
    nextStep,
    prevStep,
    canTestConnection,
    showMfaDialog,
    cancelMfaDialog,
  } = useConnectionDiagnostic();
  const node = (props.agentMeta as NodeMeta).node;
  const logins = sortNodeLogins(node.sshLogins);

  function startSshSession(login: string) {
    const url = cfg.getSshConnectRoute({
      clusterId: node.clusterId,
      serverId: node.id,
      login,
    });

    openNewTab(url);
  }

  function testConnection(login: string, mfaResponse?: MfaAuthnResponse) {
    runConnectionDiagnostic(
      {
        resourceKind: 'node',
        resourceName: props.agentMeta.resourceName,
        sshPrincipal: login,
        sshNodeOS: props.resourceSpec.platform,
      },
      mfaResponse
    );
  }

  const usernameOpts = logins.map(l => ({ value: l, label: l }));
  // There will always be one login, as the user cannot proceed
  // the step that requires users to have at least one login.
  const [selectedOpt, setSelectedOpt] = useState(usernameOpts[0]);

  return (
    <Box>
      {showMfaDialog && (
        <ReAuthenticate
          onMfaResponse={res => testConnection(selectedOpt.value, res)}
          onClose={cancelMfaDialog}
        />
      )}
      <Header>Test Connection</Header>
      <HeaderSubtitle>
        Optionally verify that you can successfully connect to the server you
        just added.
      </HeaderSubtitle>
      <StyledBox mb={5}>
        <Text bold>Step 1</Text>
        <Text typography="subtitle1" mb={3}>
          Pick the OS user to test
        </Text>
        <Box width="320px">
          <LabelInput>Select Login</LabelInput>
          <Select
            value={selectedOpt}
            options={usernameOpts}
            onChange={(o: Option) => setSelectedOpt(o)}
            isDisabled={attempt.status === 'processing'}
          />
        </Box>
      </StyledBox>
      <ConnectionDiagnosticResult
        attempt={attempt}
        diagnosis={diagnosis}
        canTestConnection={canTestConnection}
        testConnection={() => testConnection(selectedOpt.value)}
        stepNumber={2}
        stepDescription="Verify that the server is accessible"
      />
      <StyledBox>
        <Text bold>Step 3</Text>
        <Text typography="subtitle1" mb={3}>
          Connect to the server
        </Text>
        <ButtonSecondary
          width="200px"
          onClick={() => startSshSession(selectedOpt.value)}
        >
          Start Session
        </ButtonSecondary>
      </StyledBox>
      <ActionButtons onProceed={nextStep} lastStep={true} onPrev={prevStep} />
    </Box>
  );
}
