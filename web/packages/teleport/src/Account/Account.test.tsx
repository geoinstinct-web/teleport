/**
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
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

import { render, screen, waitFor } from 'design/utils/testing';
import { within } from '@testing-library/react';

import userEvent from '@testing-library/user-event';

import { ContextProvider } from 'teleport';
import TeleportContext from 'teleport/teleportContext';

import { AccountPage as Account } from 'teleport/Account/Account';
import cfg from 'teleport/config';
import { createTeleportContext } from 'teleport/mocks/contexts';
import { PasswordState } from 'teleport/services/user';
import auth from 'teleport/services/auth/auth';

const defaultAuthType = cfg.auth.second_factor;
const defaultPasswordless = cfg.auth.allowPasswordless;

afterEach(() => {
  jest.clearAllMocks();
  cfg.auth.second_factor = defaultAuthType;
  cfg.auth.allowPasswordless = defaultPasswordless;
});

async function renderComponent(ctx: TeleportContext) {
  render(
    <ContextProvider ctx={ctx}>
      <Account />
    </ContextProvider>
  );
  await waitFor(() => {
    // We can't use getAllByTestId('indicator') directly, because it's
    // unreliable: the indicators are displayed only after a default timeout
    // passes to minimize UI disruptions. That's why we need to make use of
    // their wrappers to indicate whether they are visible or not.
    for (const iwr of screen.getAllByTestId('indicator-wrapper')) {
      expect(iwr).not.toBeVisible();
    }
  });
}

// Note: the "off" and "otp" cases don't make sense with passwordless turned
// on (the auth server wouldn't start in this configuration), but we're still
// testing them for completeness.
test.each`
  mfa           | pwdless  | pkEnabled | mfaEnabled
  ${'on'}       | ${true}  | ${true}   | ${true}
  ${'on'}       | ${false} | ${false}  | ${true}
  ${'optional'} | ${true}  | ${true}   | ${true}
  ${'optional'} | ${false} | ${false}  | ${true}
  ${'otp'}      | ${false} | ${false}  | ${true}
  ${'otp'}      | ${true}  | ${true}   | ${true}
  ${'webauthn'} | ${true}  | ${true}   | ${true}
  ${'webauthn'} | ${false} | ${false}  | ${true}
  ${'off'}      | ${false} | ${false}  | ${false}
  ${'off'}      | ${true}  | ${true}   | ${false}
`(
  'passkey + mfa button state: 2fa($mfa) with pwdless($pwdless) => passkey($pkEnabled) mfa($mfaEnabled)',
  async ({ mfa, pwdless, pkEnabled, mfaEnabled }) => {
    const ctx = createTeleportContext();
    jest.spyOn(ctx.mfaService, 'fetchDevices').mockResolvedValue([]);
    cfg.auth.second_factor = mfa;
    cfg.auth.allowPasswordless = pwdless;

    await renderComponent(ctx);

    // If btns are disabled, the disabled attr has a value of empty string.
    // If btns are not disabled, the disabled attr is null (not defined).

    // eslint-disable-next-line jest-dom/prefer-to-have-attribute
    expect(screen.getByText(/add a passkey/i).getAttribute('disabled')).toBe(
      pkEnabled ? null : ''
    );

    // eslint-disable-next-line jest-dom/prefer-to-have-attribute
    expect(screen.getByText(/add mfa/i).getAttribute('disabled')).toBe(
      mfaEnabled ? null : ''
    );
  }
);

const onePasskey = [
  {
    id: '1',
    description: 'Hardware Key',
    name: 'touch_id',
    registeredDate: new Date(1628799417000),
    lastUsedDate: new Date(1628799417000),
    type: 'webauthn',
    usage: 'passwordless',
  },
];

test.each`
  pwdless  | passkeys      | state
  ${true}  | ${onePasskey} | ${/^active$/}
  ${true}  | ${[]}         | ${null}
  ${false} | ${onePasskey} | ${/^inactive$/}
  ${false} | ${[]}         | ${null}
`(
  "Passkey state pill: passwordless=$pwdless, $passkeys.length passkey(s) => state='$state'",
  async ({ pwdless, passkeys, state }) => {
    const ctx = createTeleportContext();
    jest.spyOn(ctx.mfaService, 'fetchDevices').mockResolvedValue(passkeys);
    cfg.auth.second_factor = 'on';
    cfg.auth.allowPasswordless = pwdless;

    await renderComponent(ctx);

    const statePill = screen.queryByTestId('passwordless-state-pill');
    if (state) {
      // Note: every alternative approach is even more complicated.
      // eslint-disable-next-line jest/no-conditional-expect
      expect(statePill).toHaveTextContent(state);
    } else {
      // eslint-disable-next-line jest/no-conditional-expect
      expect(statePill).not.toBeInTheDocument();
    }
  }
);

const oneMfaMethod = [
  {
    id: '1',
    description: 'Hardware Key',
    name: 'touch_id',
    registeredDate: new Date(1628799417000),
    lastUsedDate: new Date(1628799417000),
    type: 'webauthn',
    usage: 'mfa',
  },
];

test.each`
  mfa      | methods         | state
  ${'on'}  | ${oneMfaMethod} | ${/^active$/}
  ${'on'}  | ${[]}           | ${/^inactive$/}
  ${'off'} | ${oneMfaMethod} | ${/^inactive$/}
  ${'off'} | ${[]}           | ${/^inactive$/}
`(
  "MFA state pill: mfa=$mfa, $methods.length MFA method(s) => state='$state'",
  async ({ mfa, methods, state }) => {
    const ctx = createTeleportContext();
    jest.spyOn(ctx.mfaService, 'fetchDevices').mockResolvedValue(methods);
    cfg.auth.second_factor = mfa;

    await renderComponent(ctx);

    expect(screen.getByTestId('mfa-state-pill')).toHaveTextContent(state);
  }
);

test.each`
  passwordState                               | state
  ${PasswordState.PASSWORD_STATE_UNSPECIFIED} | ${/^$/}
  ${PasswordState.PASSWORD_STATE_UNSET}       | ${/^inactive$/}
  ${PasswordState.PASSWORD_STATE_SET}         | ${/^active$/}
`(
  "Password state $passwordState => state='$state'",
  async ({ passwordState, state }) => {
    const ctx = createTeleportContext();
    ctx.storeUser.setState({ passwordState });
    jest.spyOn(ctx.mfaService, 'fetchDevices').mockResolvedValue([]);

    await renderComponent(ctx);

    expect(screen.getByTestId('password-state-pill')).toHaveTextContent(state);
  }
);

test('password change', async () => {
  const user = userEvent.setup();
  const ctx = createTeleportContext();
  ctx.storeUser.setState({ passwordState: PasswordState.PASSWORD_STATE_UNSET });
  jest.spyOn(ctx.mfaService, 'fetchDevices').mockResolvedValue([]);
  jest.spyOn(auth, 'changePassword').mockResolvedValueOnce(undefined);

  await renderComponent(ctx);
  expect(screen.getByTestId('password-state-pill')).toHaveTextContent(
    'inactive'
  );

  // Change the password
  await user.click(screen.getByRole('button', { name: 'Change Password' }));
  await user.type(screen.getByLabelText('Current Password'), 'old-password');
  await user.type(screen.getByLabelText('New Password'), 'asdfasdfasdfasdf');
  await user.type(
    screen.getByLabelText('Confirm Password'),
    'asdfasdfasdfasdf'
  );
  await user.click(screen.getByRole('button', { name: 'Save Changes' }));

  // EXpect the dialog to disappear, and the state pill to change value.
  expect(screen.queryByLabelText('New Password')).not.toBeInTheDocument();
  expect(screen.getByTestId('password-state-pill')).toHaveTextContent('active');
});

test('loading state', async () => {
  const ctx = createTeleportContext();
  jest
    .spyOn(ctx.mfaService, 'fetchDevices')
    .mockReturnValue(new Promise(() => {})); // Never resolve
  cfg.auth.second_factor = 'on';
  cfg.auth.allowPasswordless = true;

  render(
    <ContextProvider ctx={ctx}>
      <Account />
    </ContextProvider>
  );

  expect(
    within(screen.getByTestId('passkey-list')).getByTestId('indicator-wrapper')
  ).toBeVisible();
  expect(
    within(screen.getByTestId('mfa-list')).getByTestId('indicator-wrapper')
  ).toBeVisible();
  expect(screen.getByText(/add a passkey/i)).toBeDisabled();
  expect(screen.getByText(/add mfa/i)).toBeDisabled();
  expect(
    screen.queryByTestId('passwordless-state-pill')
  ).not.toBeInTheDocument();
  expect(screen.getByTestId('mfa-state-pill')).toBeEmptyDOMElement();
});
