/**
 * Copyright 2020-2022 Gravitational, Inc.
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

import React from 'react';
import { render, fireEvent, screen, waitFor } from 'design/utils/testing';

import auth from 'teleport/services/auth/auth';
import history from 'teleport/services/history';
import cfg from 'teleport/config';

import Login from './Login';

beforeEach(() => {
  jest.restoreAllMocks();
  jest.spyOn(history, 'push').mockImplementation();
  jest.spyOn(history, 'getRedirectParam').mockImplementation(() => '/');
});

test('basic rendering', () => {
  render(<Login />);

  // test rendering of logo and title
  expect(screen.getByRole('img')).toBeInTheDocument();
  expect(screen.getByText(/sign in to teleport/i)).toBeInTheDocument();
});

test('login with redirect', async () => {
  jest.spyOn(auth, 'login').mockResolvedValue(null);

  render(<Login />);

  // fill form
  const username = screen.getByPlaceholderText(/username/i);
  const password = screen.getByPlaceholderText(/password/i);
  fireEvent.change(username, { target: { value: 'username' } });
  fireEvent.change(password, { target: { value: '123' } });

  // test login and redirect
  fireEvent.click(screen.getByText('Sign In'));
  await waitFor(() => {
    expect(auth.login).toHaveBeenCalledWith('username', '123', '');
  });
  expect(history.push).toHaveBeenCalledWith('http://localhost/web', true);
});

test('login with SSO', () => {
  jest.spyOn(cfg, 'getAuth2faType').mockImplementation(() => 'otp');
  jest.spyOn(cfg, 'getPrimaryAuthType').mockImplementation(() => 'sso');
  jest.spyOn(cfg, 'getAuthProviders').mockImplementation(() => [
    {
      displayName: 'With GitHub',
      type: 'github',
      name: 'github',
      url: '/github/login/web?redirect_url=:redirect?connector_id=:providerName',
    },
  ]);

  render(<Login />);

  // test login pathways
  fireEvent.click(screen.getByText('With GitHub'));
  expect(history.push).toHaveBeenCalledWith(
    'http://localhost/github/login/web?redirect_url=http:%2F%2Flocalhost%2Fwebconnector_id=github',
    true
  );
});

describe('test MOTD', () => {
  test('show motd only if motd is set', async () => {
    // default login form
    const { unmount } = render(<Login />);
    expect(screen.getByPlaceholderText(/username/i)).toBeInTheDocument();
    expect(
      screen.queryByText('Welcome to cluster, your activity will be recorded.')
    ).not.toBeInTheDocument();
    unmount();

    // now set motd
    jest
      .spyOn(cfg, 'getMotd')
      .mockImplementation(
        () => 'Welcome to cluster, your activity will be recorded.'
      );

    render(<Login />);

    expect(
      screen.getByText('Welcome to cluster, your activity will be recorded.')
    ).toBeInTheDocument();
    expect(screen.queryByPlaceholderText(/username/i)).not.toBeInTheDocument();
  });

  test('show login form after modt acknowledge', async () => {
    jest
      .spyOn(cfg, 'getMotd')
      .mockImplementation(
        () => 'Welcome to cluster, your activity will be recorded.'
      );
    render(<Login />);
    expect(
      screen.getByText('Welcome to cluster, your activity will be recorded.')
    ).toBeInTheDocument();

    fireEvent.click(screen.getByText('Acknowledge'));
    expect(screen.getByPlaceholderText(/username/i)).toBeInTheDocument();
  });

  test('skip motd if login initiated from headless auth', async () => {
    jest
      .spyOn(cfg, 'getMotd')
      .mockImplementation(
        () => 'Welcome to cluster, your activity will be recorded.'
      );
    jest
      .spyOn(history, 'getRedirectParam')
      .mockReturnValue(
        'https://teleport.example.com/web/headless/5c5c1f73-ac5c-52ee-bc9e-0353094dcb4a'
      );

    render(<Login />);

    expect(
      screen.queryByText('Welcome to cluster, your activity will be recorded.')
    ).not.toBeInTheDocument();
  });
});
