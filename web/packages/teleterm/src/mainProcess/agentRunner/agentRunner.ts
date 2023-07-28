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

import { spawn, ChildProcess } from 'node:child_process';
import os from 'node:os';

import Logger from 'teleterm/logger';
import { RootClusterUri } from 'teleterm/ui/uri';

import { generateAgentConfigPaths } from '../createAgentConfigFile';
import { AgentProcessState, RuntimeSettings } from '../types';
import { terminateWithTimeout } from '../terminateWithTimeout';

const MAX_STDERR_LINES = 10;

export class AgentRunner {
  private logger = new Logger('AgentRunner');
  private agentProcesses = new Map<RootClusterUri, ChildProcess>();

  constructor(
    private settings: RuntimeSettings,
    private sendProcessState: (
      rootClusterUri: RootClusterUri,
      state: AgentProcessState
    ) => void
  ) {}

  /**
   * Starts a new agent process.
   * If an existing process exists for the given root cluster, the old one will be killed.
   */
  async start(rootClusterUri: RootClusterUri): Promise<ChildProcess> {
    if (this.agentProcesses.has(rootClusterUri)) {
      await this.kill(rootClusterUri);
      this.logger.warn(`Killed agent process for ${rootClusterUri}`);
    }

    const { agentBinaryPath } = this.settings;
    const { configFile } = generateAgentConfigPaths(
      this.settings,
      rootClusterUri
    );

    const args = [
      'start',
      `--config=${configFile}`,
      this.settings.isLocalBuild && '--skip-version-check',
    ].filter(Boolean);

    this.logger.info(
      `Starting agent from ${agentBinaryPath} with arguments ${args.join(' ')}`
    );

    const agentProcess = spawn(agentBinaryPath, args, {
      windowsHide: true,
    });

    this.addListeners(rootClusterUri, agentProcess);
    this.agentProcesses.set(rootClusterUri, agentProcess);

    return agentProcess;
  }

  async kill(rootClusterUri: RootClusterUri): Promise<void> {
    await terminateWithTimeout(this.agentProcesses.get(rootClusterUri));
    this.agentProcesses.delete(rootClusterUri);
  }

  async killAll(): Promise<void> {
    const processes = Array.from(this.agentProcesses.entries());
    await Promise.all(
      processes.map(async ([rootClusterUri, agent]) => {
        await terminateWithTimeout(agent);
        this.agentProcesses.delete(rootClusterUri);
      })
    );
  }

  private addListeners(
    rootClusterUri: RootClusterUri,
    process: ChildProcess
  ): void {
    // Teleport logs output to stderr.
    let stderrOutput = '';
    process.stderr.setEncoding('utf-8');
    process.stderr.on('data', error => {
      stderrOutput += error;
      stderrOutput = limitProcessOutputLines(stderrOutput);
    });

    const spawnHandler = () => {
      this.sendProcessState(rootClusterUri, {
        status: 'running',
      });
    };

    const errorHandler = (error: Error) => {
      process.off('spawn', spawnHandler);

      this.sendProcessState(rootClusterUri, {
        status: 'error',
        message: `${error}`,
      });
    };

    const exitHandler = (
      code: number | null,
      signal: NodeJS.Signals | null
    ) => {
      // Remove handlers when the process exits.
      process.off('error', errorHandler);
      process.off('spawn', spawnHandler);

      this.sendProcessState(rootClusterUri, {
        status: 'exited',
        code,
        signal,
        stackTrace: signal !== 'SIGTERM' ? stderrOutput : undefined,
      });
    };

    process.once('spawn', spawnHandler);
    process.once('error', errorHandler);
    process.once('exit', exitHandler);
  }
}

function limitProcessOutputLines(output: string): string {
  return output.split(os.EOL).slice(-MAX_STDERR_LINES).join(os.EOL);
}
