/*
Copyright 2023 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import React from 'react';
import {
  Alert,
  Box,
  ButtonPrimary,
  Flex,
  Label,
  Link,
  MenuItem,
  Text,
  ButtonSecondary,
} from 'design';
import styled, { css } from 'styled-components';
import { Transition } from 'react-transition-group';

import { makeLabelTag } from 'teleport/components/formatters';
import { MenuIcon } from 'shared/components/MenuAction';
import { CircleCheck, Laptop, Moon, Warning } from 'design/Icon';
import Indicator from 'design/Indicator';

import {
  AgentProcessError,
  CurrentAction,
  NodeWaitJoinTimeout,
  useConnectMyComputerContext,
} from 'teleterm/ui/ConnectMyComputer';
import { assertUnreachable } from 'teleterm/ui/utils';
import { codeOrSignal } from 'teleterm/ui/utils/process';
import { connectToServer } from 'teleterm/ui/services/workspacesService';
import { useAppContext } from 'teleterm/ui/appContextProvider';
import { useWorkspaceContext } from 'teleterm/ui/Documents';

import { useAgentProperties } from '../useAgentProperties';
import { Logs } from '../Logs';
import { CompatibilityError, useVersions } from '../CompatibilityPromise';
import {
  shouldShowAgentUpgradeSuggestion,
  UpgradeAgentSuggestion,
} from '../UpgradeAgentSuggestion';

import type * as tsh from 'teleterm/services/tshd/types';
import type { IconProps } from 'design/Icon/Icon';

interface DocumentConnectMyComputerStatusProps {
  closeDocument?(): void;
}

// TODO(gzdunek): Rename to `Status`
export function DocumentConnectMyComputerStatus(
  props: DocumentConnectMyComputerStatusProps
) {
  const ctx = useAppContext();
  const {
    currentAction,
    agentNode,
    downloadAndStartAgent,
    killAgent,
    isAgentConfiguredAttempt,
    markAgentAsNotConfigured,
    removeAgent,
    agentCompatibility,
  } = useConnectMyComputerContext();
  const { rootClusterUri } = useWorkspaceContext();
  const { roleName, systemUsername, hostname } = useAgentProperties();
  const { proxyVersion, appVersion, isLocalBuild } = useVersions();
  const isAgentIncompatible = agentCompatibility === 'incompatible';
  const isAgentIncompatibleOrUnknown =
    agentCompatibility === 'incompatible' || agentCompatibility === 'unknown';

  const prettyCurrentAction = prettifyCurrentAction(currentAction);

  function replaceWithSetup(): void {
    markAgentAsNotConfigured();
  }

  function startSshSession(): void {
    connectToServer(
      ctx,
      { uri: agentNode.uri, hostname, login: systemUsername },
      { origin: 'resource_table' }
    );
  }

  async function removeAgentAndClose(): Promise<void> {
    const [, error] = await removeAgent();
    if (error) {
      return;
    }
    props.closeDocument();
  }

  async function openAgentLogs(): Promise<void> {
    try {
      await ctx.mainProcessClient.openAgentLogsDirectory({ rootClusterUri });
    } catch (e) {
      ctx.notificationsService.notifyError({
        title: 'Failed to open agent logs directory',
        description: `${e.message}\n\nNote: the logs directory is created only after the agent process successfully spawns.`,
      });
    }
  }

  const isRunning =
    currentAction.kind === 'observe-process' &&
    currentAction.agentProcessState.status === 'running';
  const isKilling =
    currentAction.kind === 'kill' &&
    currentAction.attempt.status === 'processing';
  const isDownloading =
    currentAction.kind === 'download' &&
    currentAction.attempt.status === 'processing';
  const isStarting =
    currentAction.kind === 'start' &&
    currentAction.attempt.status === 'processing';
  const isRemoving =
    currentAction.kind === 'remove' &&
    currentAction.attempt.status === 'processing';
  const isRemoved =
    currentAction.kind === 'remove' &&
    currentAction.attempt.status === 'success';

  const showConnectAndStopAgentButtons = isRunning || isKilling;
  const disableConnectAndStopAgentButtons = isKilling;
  const disableStartAgentButton =
    isDownloading ||
    isStarting ||
    isRemoving ||
    isRemoved ||
    isAgentIncompatibleOrUnknown;

  return (
    <Box maxWidth="680px" mx="auto" mt="4" px="5" width="100%">
      {shouldShowAgentUpgradeSuggestion(proxyVersion, {
        appVersion,
        isLocalBuild,
      }) && (
        <UpgradeAgentSuggestion
          proxyVersion={proxyVersion}
          appVersion={appVersion}
        />
      )}
      {isAgentConfiguredAttempt.status === 'error' && (
        <Alert
          css={`
            display: block;
          `}
        >
          An error occurred while reading the agent config file:{' '}
          {isAgentConfiguredAttempt.statusText}. <br />
          You can try to{' '}
          <Link
            onClick={replaceWithSetup}
            css={`
              cursor: pointer;
            `}
          >
            run the setup
          </Link>{' '}
          again.
        </Alert>
      )}

      <Flex flexDirection="column" gap={3}>
        <Flex flexDirection="column" gap={1}>
          <Flex justifyContent="space-between">
            <Text
              typography="h3"
              css={`
                display: flex;
              `}
            >
              <Laptop mr={2} />
              {/** The node name can be changed, so it might be different from the system hostname. */}
              {agentNode?.hostname || hostname}
            </Text>
            <MenuIcon
              buttonIconProps={{
                css: css`
                  border-radius: ${props => props.theme.space[1]}px;
                  background: ${props => props.theme.colors.spotBackground[0]};
                `,
              }}
              menuProps={{
                anchorOrigin: {
                  vertical: 'bottom',
                  horizontal: 'right',
                },
                transformOrigin: {
                  vertical: 'top',
                  horizontal: 'right',
                },
              }}
            >
              <MenuItem onClick={openAgentLogs}>
                Open agent logs directory
              </MenuItem>
              <MenuItem onClick={removeAgentAndClose}>Remove agent</MenuItem>
            </MenuIcon>
          </Flex>

          <Transition
            in={!!agentNode}
            timeout={1_800}
            mountOnEnter
            unmountOnExit
          >
            {state => (
              <LabelsContainer gap={1} className={state}>
                {renderLabels(agentNode.labelsList)}
              </LabelsContainer>
            )}
          </Transition>
        </Flex>

        <Flex flexDirection="column" gap={2}>
          <Flex gap={1} display="flex" alignItems="center" minHeight="32px">
            {prettyCurrentAction.Icon && (
              <prettyCurrentAction.Icon size="medium" />
            )}
            {prettyCurrentAction.title}
            {showConnectAndStopAgentButtons && (
              <ButtonSecondary
                onClick={killAgent}
                disabled={disableConnectAndStopAgentButtons}
                ml={3}
              >
                Stop Agent
              </ButtonSecondary>
            )}
          </Flex>
          {prettyCurrentAction.error && (
            <Alert
              mb={0}
              css={`
                white-space: pre-wrap;
              `}
            >
              {prettyCurrentAction.error}
            </Alert>
          )}
          {prettyCurrentAction.logs && <Logs logs={prettyCurrentAction.logs} />}
        </Flex>

        <Flex flexDirection="column" gap={2}>
          {isAgentIncompatible ? (
            <CompatibilityError
              // Hide the alert if the current action has failed. downloadAgent and startAgent already
              // return an error message related to compatibility.
              //
              // Basically, we have to cover two use cases:
              //
              // * Auto start has failed due to compatibility promise, so the downloadAgent failed with
              // an error.
              // * Auto start wasn't enabled, so the current action has no errors, but the user should
              // not be able to start the agent due to compatibility issues.
              hideAlert={!!prettyCurrentAction.error}
            />
          ) : (
            <>
              {isRunning ? (
                <Text>
                  Any cluster user with the role <strong>{roleName}</strong> can
                  now access your computer as <strong>{systemUsername}</strong>.
                </Text>
              ) : (
                <Text>
                  Connecting your computer will allow any cluster user with the
                  role <strong>{roleName}</strong> to access it as an SSH
                  resource with the user <strong>{systemUsername}</strong>.
                </Text>
              )}
              {showConnectAndStopAgentButtons ? (
                <ButtonPrimary
                  block
                  disabled={disableConnectAndStopAgentButtons}
                  onClick={startSshSession}
                  size="large"
                >
                  Connect
                </ButtonPrimary>
              ) : (
                <ButtonPrimary
                  block
                  disabled={disableStartAgentButton}
                  onClick={downloadAndStartAgent}
                  size="large"
                  data-testid="start-agent"
                >
                  Start Agent
                </ButtonPrimary>
              )}
            </>
          )}
        </Flex>
      </Flex>
    </Box>
  );
}

function renderLabels(labelsList: tsh.Label[]): JSX.Element[] {
  const labels = labelsList.map(makeLabelTag);
  return labels.map(label => (
    <Label key={label} kind="secondary">
      {label}
    </Label>
  ));
}

function prettifyCurrentAction(currentAction: CurrentAction): {
  Icon: React.FC<IconProps>;
  title: string;
  error?: string;
  logs?: string;
} {
  const noop = {
    Icon: StyledIndicator,
    title: '',
  };

  switch (currentAction.kind) {
    case 'download': {
      switch (currentAction.attempt.status) {
        case '':
        case 'processing': {
          // TODO(gzdunek) add progress
          return {
            Icon: StyledIndicator,
            title: 'Checking agent version',
          };
        }
        case 'error': {
          return {
            Icon: StyledWarning,
            title: 'Failed to verify agent binary',
            error: currentAction.attempt.statusText,
          };
        }
        case 'success': {
          return noop; // noop, not used, at this point it should be start processing.
        }
        default: {
          return assertUnreachable(currentAction.attempt);
        }
      }
    }
    case 'start': {
      switch (currentAction.attempt.status) {
        case '':
        case 'processing': {
          return {
            Icon: StyledIndicator,
            title: 'Starting',
          };
        }
        case 'error': {
          if (currentAction.attempt.error instanceof NodeWaitJoinTimeout) {
            return {
              Icon: StyledWarning,
              title: 'Failed to start agent',
              error:
                'The agent did not join the cluster within the timeout window.',
              logs: currentAction.attempt.error.logs,
            };
          }

          if (!(currentAction.attempt.error instanceof AgentProcessError)) {
            return {
              Icon: StyledWarning,
              title: 'Failed to start agent',
              error: currentAction.attempt.statusText,
            };
          }

          if (currentAction.agentProcessState.status === 'error') {
            return {
              Icon: StyledWarning,
              title:
                'Failed to start agent – an error occurred while spawning the agent process',
              error: currentAction.agentProcessState.message,
            };
          }

          if (currentAction.agentProcessState.status === 'exited') {
            const { code, signal } = currentAction.agentProcessState;
            return {
              Icon: StyledWarning,
              title: `Failed to start agent - the agent process quit unexpectedly with ${codeOrSignal(
                code,
                signal
              )}`,
              logs: currentAction.agentProcessState.logs,
            };
          }
          break;
        }
        case 'success': {
          return noop; // noop, not used, at this point it should be observe-process running.
        }
        default: {
          return assertUnreachable(currentAction.attempt);
        }
      }
      break;
    }
    case 'observe-process': {
      switch (currentAction.agentProcessState.status) {
        case 'not-started': {
          return {
            Icon: Moon,
            title: 'Agent not running',
          };
        }
        case 'running': {
          return {
            Icon: props => <CircleCheck {...props} color="success" />,
            title: 'Agent running',
          };
        }
        case 'exited': {
          const { code, signal, exitedSuccessfully } =
            currentAction.agentProcessState;

          if (exitedSuccessfully) {
            return {
              Icon: Moon,
              title: 'Agent not running',
            };
          } else {
            return {
              Icon: StyledWarning,
              title: `Agent process exited with ${codeOrSignal(code, signal)}`,
              logs: currentAction.agentProcessState.logs,
            };
          }
        }
        case 'error': {
          // TODO(ravicious): This can happen only just before killing the process. 'error' should
          // not be considered a separate process state. See the comment above the 'error' status
          // definition.
          return {
            Icon: StyledWarning,
            title: 'An error occurred to agent process',
            error: currentAction.agentProcessState.message,
          };
        }
        default: {
          return assertUnreachable(currentAction.agentProcessState);
        }
      }
    }
    case 'kill': {
      switch (currentAction.attempt.status) {
        case '':
        case 'processing': {
          return {
            Icon: StyledIndicator,
            title: 'Stopping',
          };
        }
        case 'error': {
          return {
            Icon: StyledWarning,
            title: 'Failed to stop agent',
            error: currentAction.attempt.statusText,
          };
        }
        case 'success': {
          return noop; // noop, not used, at this point it should be observe-process exited.
        }
        default: {
          return assertUnreachable(currentAction.attempt);
        }
      }
    }
    case 'remove': {
      switch (currentAction.attempt.status) {
        case '':
        case 'processing': {
          return {
            Icon: StyledIndicator,
            title: 'Removing',
          };
        }
        case 'error': {
          return {
            Icon: StyledWarning,
            title: 'Failed to remove agent',
            error: currentAction.attempt.statusText,
          };
        }
        case 'success': {
          return {
            Icon: CircleCheck,
            title: 'Agent removed',
            error: currentAction.attempt.statusText,
          };
        }
        default: {
          return assertUnreachable(currentAction.attempt);
        }
      }
    }
  }
}

const StyledWarning = styled(Warning).attrs({
  color: 'error.main',
})``;

const StyledIndicator = styled(Indicator).attrs({ delay: 'none' })`
  color: inherit;
  display: inline-flex;
`;

const LabelsContainer = styled(Flex)`
  &.entering {
    animation-duration: 1.8s;
    animation-name: lineInserted;
    animation-timing-function: ease-in;
    overflow: hidden;
    animation-fill-mode: forwards;
    // We don't know the height of labels, so we animate max-height instead of height
    @keyframes lineInserted {
      from {
        max-height: 0;
      }
      to {
        max-height: 100%;
      }
    }
  }
`;
