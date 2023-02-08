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

import { MockAppContext } from 'teleterm/ui/fixtures/mocks';
import Logger, { NullService } from 'teleterm/logger';

import { retryWithRelogin } from './retryWithRelogin';

beforeAll(() => {
  Logger.init(new NullService());
});

const makeRetryableError = () => new Error('ssh: handshake failed');

it('returns the result of actionToRetry if no error is thrown', async () => {
  const expectedReturnValue = Symbol('expectedReturnValue');
  const actionToRetry = jest.fn().mockResolvedValue(expectedReturnValue);

  const actualReturnValue = await retryWithRelogin(
    undefined,
    '',
    '',
    actionToRetry
  );

  expect(actionToRetry).toHaveBeenCalledTimes(1);
  expect(actualReturnValue).toEqual(expectedReturnValue);
});

it("returns the error coming from actionToRetry if it's not retryable", async () => {
  const expectedError = Symbol('non-retryable error');
  const actionToRetry = jest.fn().mockRejectedValue(expectedError);

  const actualError = retryWithRelogin(
    undefined,
    'doc-uri',
    '/clusters/foo/servers/bar',
    actionToRetry
  );

  await expect(actualError).rejects.toEqual(expectedError);

  expect(actionToRetry).toHaveBeenCalledTimes(1);
});

it('opens the login modal window and calls actionToRetry again on successful relogin if the error is retryable', async () => {
  const appContext = new MockAppContext();

  jest
    .spyOn(appContext.workspacesService, 'isDocumentActive')
    .mockImplementation(() => true);

  // Immediately resolve the login promise.
  jest
    .spyOn(appContext.modalsService, 'openClusterConnectDialog')
    .mockImplementation(({ onSuccess }) => onSuccess(''));

  const expectedReturnValue = Symbol('expectedReturnValue');
  const actionToRetry = jest
    .fn()
    .mockRejectedValueOnce(makeRetryableError())
    .mockResolvedValueOnce(expectedReturnValue);

  const actualReturnValue = await retryWithRelogin(
    appContext,
    'doc-uri',
    '/clusters/foo/servers/bar',
    actionToRetry
  );

  const openClusterConnectDialogSpy =
    appContext.modalsService.openClusterConnectDialog;
  expect(openClusterConnectDialogSpy).toHaveBeenCalledTimes(1);
  expect(openClusterConnectDialogSpy).toHaveBeenCalledWith(
    expect.objectContaining({ clusterUri: '/clusters/foo' })
  );

  expect(actionToRetry).toHaveBeenCalledTimes(2);
  expect(actualReturnValue).toEqual(expectedReturnValue);
});

it("returns the original retryable error if the document is no longer active, doesn't open the modal and doesn't call actionToRetry again", async () => {
  const appContext = new MockAppContext();

  jest
    .spyOn(appContext.workspacesService, 'isDocumentActive')
    .mockImplementation(() => false);

  jest
    .spyOn(appContext.modalsService, 'openClusterConnectDialog')
    .mockImplementation(() => {
      throw new Error('Modal was opened');
    });

  const expectedError = makeRetryableError();
  const actionToRetry = jest.fn().mockRejectedValue(expectedError);

  const actualError = retryWithRelogin(
    appContext,
    'doc-uri',
    '/clusters/foo/servers/bar',
    actionToRetry
  );

  await expect(actualError).rejects.toEqual(expectedError);

  expect(actionToRetry).toHaveBeenCalledTimes(1);
  expect(
    appContext.modalsService.openClusterConnectDialog
  ).not.toHaveBeenCalled();
});

// This covers situations where the cert was refreshed externally, for example through tsh login.
it('calls actionToRetry again if relogin attempt was canceled', async () => {
  const appContext = new MockAppContext();

  jest
    .spyOn(appContext.workspacesService, 'isDocumentActive')
    .mockImplementation(() => true);

  jest
    .spyOn(appContext.modalsService, 'openClusterConnectDialog')
    .mockImplementation(({ onCancel }) => onCancel());

  const expectedReturnValue = Symbol('expectedReturnValue');
  const actionToRetry = jest
    .fn()
    .mockRejectedValueOnce(makeRetryableError())
    .mockResolvedValueOnce(expectedReturnValue);

  const actualReturnValue = await retryWithRelogin(
    appContext,
    'doc-uri',
    '/clusters/foo/servers/bar',
    actionToRetry
  );

  expect(actionToRetry).toHaveBeenCalledTimes(2);
  expect(actualReturnValue).toEqual(expectedReturnValue);
});
