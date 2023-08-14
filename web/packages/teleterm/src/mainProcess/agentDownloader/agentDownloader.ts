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

import { pipeline } from 'node:stream/promises';
import { createReadStream } from 'node:fs';
import { rm, mkdtemp } from 'node:fs/promises';
import { join } from 'node:path';
import { createUnzip } from 'node:zlib';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

import { extract } from 'tar-fs';

import { compareSemVers } from 'shared/utils/semVer';

import Logger from 'teleterm/logger';

import { RuntimeSettings } from '../types';

import type { IFileDownloader } from './fileDownloader';

const TELEPORT_CDN_ADDRESS = 'https://cdn.teleport.dev';
const TELEPORT_RELEASES_ADDRESS = 'https://rlz.teleport.sh/teleport?page=0';
const logger = new Logger('agentDownloader');

interface AgentBinary {
  version: string;
  platform: string;
  arch: string;
}

/**
 * Downloads and unpacks the agent binary, if it has not already been downloaded.
 *
 * The agent version to download is taken from settings.appVersion if settings.isLocalBuild is false.
 * If it isn't, we fetch the latest available stable version of the agent.
 * CONNECT_CMC_AGENT_VERSION is available as an escape hatch for cases where we want to fetch a different version.
 */
export async function downloadAgent(
  fileDownloader: IFileDownloader,
  settings: RuntimeSettings,
  env: Record<string, any>
): Promise<void> {
  const version = await calculateAgentVersion(settings, env);

  if (
    await isCorrectAgentVersionAlreadyDownloaded(
      settings.agentBinaryPath,
      version
    )
  ) {
    logger.info(`Agent v${version} is already downloaded. Skipping.`);
    return;
  }

  const tarballName = createAgentTarballName({
    arch: settings.arch,
    platform: settings.platform,
    version,
  });
  const url = `${TELEPORT_CDN_ADDRESS}/${tarballName}`;

  const agentTempDirectory = await mkdtemp(
    join(settings.tempDataDir, 'connect-my-computer-')
  );
  await fileDownloader.run(url, agentTempDirectory);
  const tarballPath = join(agentTempDirectory, tarballName);
  await unpack(tarballPath, settings.sessionDataDir);
  await rm(agentTempDirectory, { recursive: true });

  logger.info(`Downloaded agent v${version}.`);
}

async function calculateAgentVersion(
  settings: RuntimeSettings,
  env: Record<string, any>
): Promise<string> {
  if (!settings.isLocalBuild) {
    return settings.appVersion;
  }
  if (env.CONNECT_CMC_AGENT_VERSION) {
    return env.CONNECT_CMC_AGENT_VERSION;
  }
  return await fetchLatestTeleportRelease();
}

/**
 * Takes the first page of teleport releases (30 items) and looks for the highest version.
 * We don't have a way to simply take the latest tag.
 */
async function fetchLatestTeleportRelease(): Promise<string> {
  const response = await fetch(TELEPORT_RELEASES_ADDRESS);
  if (!response.ok) {
    throw new Error(
      `Failed to fetch ${TELEPORT_RELEASES_ADDRESS}. Status code: ${response.status}.`
    );
  }
  const teleportVersions = (
    (await response.json()) as {
      version: string;
    }[]
  ).map(r => r.version);

  // get the last element
  const latest = teleportVersions.sort(compareSemVers)?.at(-1);
  if (latest) {
    return latest;
  }
  throw new Error('Failed to read the latest teleport release.');
}

/**
 * Generates following binary names:
 * teleport-v<version>-linux-arm64-bin.tar.gz
 * teleport-v<version>-linux-amd64-bin.tar.gz
 * teleport-v<version>-darwin-arm64-bin.tar.gz
 * teleport-v<version>-darwin-amd64-bin.tar.gz
 */
function createAgentTarballName(params: AgentBinary): string {
  const arch = params.arch === 'x64' ? 'amd64' : params.arch;
  return `teleport-v${params.version}-${params.platform}-${arch}-bin.tar.gz`;
}

async function isCorrectAgentVersionAlreadyDownloaded(
  agentBinaryPath: string,
  neededVersion: string
): Promise<boolean> {
  const asyncExecFile = promisify(execFile);
  try {
    const agentVersion = await asyncExecFile(
      agentBinaryPath,
      ['version', '--raw'],
      {
        timeout: 10_000, // 10 seconds
      }
    );
    return agentVersion.stdout.trim() === neededVersion;
  } catch (e) {
    // When the agent is being downloaded for the first time, the binary does not yet exist.
    if (e.code !== 'ENOENT') {
      throw e;
    }
    return false;
  }
}

function unpack(sourceFile: string, targetDirectory: string): Promise<void> {
  return pipeline(
    createReadStream(sourceFile),
    createUnzip(),
    extract(targetDirectory, {
      ignore: (_, headers) => {
        // Keep only the teleport binary
        return headers.name !== 'teleport/teleport';
      },
    })
  );
}
