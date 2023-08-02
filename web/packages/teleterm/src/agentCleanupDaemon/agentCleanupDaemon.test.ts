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

import childProcess from 'node:child_process';
import path from 'node:path';
import process from 'node:process';

// inheritStdio makes it so that processes spawned during the test will inherit stdio of the process
// running the tests. Useful for debugging.
const inheritStdio = false;

describe('agentCleanupDaemon', () => {
  test.each([
    {
      name: 'terminates the agent if the parent gets terminated',
      parentArgs: [],
    },
    {
      name: 'terminates the agent if the parent gets terminated before the cleanup daemon is fully set up',
      parentArgs: ['sendPidsImmediately'],
    },
    {
      name: 'follows up SIGTERM with SIGKILL in case SIGTERM did not cause the agent to terminate',
      parentArgs: ['sendPidsWhenReady', 'ignoreSigterm'],
    },
  ])('$name', async ({ parentArgs }) => {
    await cleanupPids(async addPidToCleanup => {
      const parent = childProcess.fork(
        path.join(__dirname, 'parentTestProcess.mjs'),
        parentArgs,
        { stdio: (inheritStdio && 'inherit') || 'pipe' }
      );
      addPidToCleanup(parent.pid);

      // parentTestProcess sends PIDs only after it gets a message from both childTestProcess and
      // agentCleanupDaemon. This way we know that both children are actually up and running.
      //
      // Otherwise we might end up killing the parent before the agent cleanup daemon was set up.
      //
      // If sendPidsImmediately is passed as the first arg to the parent process, the PIDs are sent
      // immediately after spawning the children, without waiting for messages.
      const pidsPromise = waitForMessage(parent);
      await expect(pidsPromise).resolves.toMatchObject({
        agentCleanupDaemon: expect.any(Number),
        agent: expect.any(Number),
      });
      const pids = await pidsPromise;
      addPidToCleanup(pids['agent']);
      addPidToCleanup(pids['agentCleanupDaemon']);

      // Make sure that both children are still running.
      expect(isRunning(pids['agent'])).toBe(true);
      expect(isRunning(pids['agentCleanupDaemon'])).toBe(true);

      // Verify that killing the parent results in the eventual termination of both children.
      expect(parent.kill('SIGKILL')).toBe(true);
      await expectPidToEventuallyTerminate(pids['agent']);
      await expectPidToEventuallyTerminate(pids['agentCleanupDaemon']);
    });
  });

  it('exits early if the agent is not running at the start', async () => {
    await cleanupPids(async addPidToCleanup => {
      const parent = childProcess.fork(
        path.join(__dirname, 'parentTestProcess.mjs'),
        ['sendPidsImmediately'],
        { stdio: (inheritStdio && 'inherit') || 'pipe' }
      );
      addPidToCleanup(parent.pid);

      const pidsPromise = waitForMessage(parent);
      await expect(pidsPromise).resolves.toMatchObject({
        agentCleanupDaemon: expect.any(Number),
        agent: expect.any(Number),
      });
      const pids = await pidsPromise;
      addPidToCleanup(pids['agent']);
      addPidToCleanup(pids['agentCleanupDaemon']);

      // Make sure that both children are still running.
      expect(isRunning(pids['agent'])).toBe(true);
      expect(isRunning(pids['agentCleanupDaemon'])).toBe(true);

      // Kill the agent before the daemon is set up.
      expect(process.kill(pids['agent'], 'SIGKILL')).toBe(true);

      await expectPidToEventuallyTerminate(pids['agentCleanupDaemon']);
    });
  });

  it('exits on SIGTERM and keeps the agent running', async () => {
    await cleanupPids(async addPidToCleanup => {
      const parent = childProcess.fork(
        path.join(__dirname, 'parentTestProcess.mjs'),
        [],
        { stdio: (inheritStdio && 'inherit') || 'pipe' }
      );
      addPidToCleanup(parent.pid);

      const pidsPromise = waitForMessage(parent);
      await expect(pidsPromise).resolves.toMatchObject({
        agentCleanupDaemon: expect.any(Number),
        agent: expect.any(Number),
      });
      const pids = await pidsPromise;
      addPidToCleanup(pids['agent']);
      addPidToCleanup(pids['agentCleanupDaemon']);

      // Make sure that both children are still running.
      expect(isRunning(pids['agent'])).toBe(true);
      expect(isRunning(pids['agentCleanupDaemon'])).toBe(true);

      // Verify that SIGTERM makes the cleanup daemon terminate.
      expect(process.kill(pids['agentCleanupDaemon'], 'SIGTERM')).toBe(true);
      await expectPidToEventuallyTerminate(pids['agentCleanupDaemon']);

      // Verify that the cleanup daemon doesn't kill the agent when the cleanup daemon receives
      // SIGTERM.
      expect(isRunning(pids['agent'])).toBe(true);
    });
  });
});

describe('isRunning', () => {
  it('reports the status of a process', async () => {
    await cleanupPids(async addPidToCleanup => {
      const child = childProcess.fork(
        path.join(__dirname, 'agentTestProcess.mjs')
      );
      addPidToCleanup(child.pid);

      expect(isRunning(child.pid)).toBe(true);

      child.kill('SIGKILL');
      await expectPidToEventuallyTerminate(child.pid);

      expect(isRunning(child.pid)).toBe(false);
    });
  });
});

const waitForMessage = (process: childProcess.ChildProcess) =>
  new Promise(resolve => {
    process.once('message', resolve);
  });

const expectPidToEventuallyTerminate = async (pid: number) =>
  expect(() => !isRunning(pid)).toEventuallyBeTrue({
    waitFor: 2000,
    tick: 10,
  });

/**
 * isRunning determines whether a process with the given PID is running by sending a special zero
 * signal, as described in process.kill docs.
 *
 * https://nodejs.org/docs/latest-v18.x/api/process.html#processkillpid-signal
 */
const isRunning = (pid: number) => {
  try {
    return process.kill(pid, 0);
  } catch (error) {
    if (error.code === 'ESRCH') {
      return false;
    }

    throw error;
  }
};

const cleanupPids = async (
  func: (addPidToCleanup: (pid: number) => void) => void | Promise<void>
): Promise<void> => {
  const pidsToCleanup = [];
  const addPidToCleanup = (pid: number) => {
    pidsToCleanup.push(pid);
  };

  try {
    await func(addPidToCleanup);
  } finally {
    for (const pid of pidsToCleanup) {
      try {
        process.kill(pid, 'SIGKILL');
      } catch {
        // Ignore errors resulting from the process not existing.
      }
    }
  }
};
