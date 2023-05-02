/**
 * Copyright 2020 Gravitational, Inc.
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

import { render } from 'design/utils/testing';

import {
  SupportOSS,
  SupportCloud,
  SupportEnterprise,
  SupportWithCTA,
} from './Support.story';

test('support OSS', () => {
  const { container } = render(<SupportOSS />);
  expect(container.firstChild).toMatchSnapshot();
});

test('support Cloud', () => {
  const { container } = render(<SupportCloud />);
  expect(container.firstChild).toMatchSnapshot();
});

test('support Enterprise', () => {
  const { container } = render(<SupportEnterprise />);
  expect(container.firstChild).toMatchSnapshot();
});

test('support Enterprise with CTA', () => {
  const { container } = render(<SupportWithCTA />);
  expect(container.firstChild).toMatchSnapshot();
});
