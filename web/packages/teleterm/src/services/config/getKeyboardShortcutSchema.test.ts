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

import { z, ZodError } from 'zod';

import {
  getKeyboardShortcutSchema,
  invalidModifierIssue,
  invalidKeyCodeIssue,
  duplicateModifierIssue,
  missingModifierIssue,
} from './getKeyboardShortcutSchema';

const schema = z.object({
  'keymap.tab1': getKeyboardShortcutSchema('darwin'),
});

function getZodError(issue: any): z.ZodError {
  return new ZodError([
    {
      ...issue,
      path: ['keymap.tab1'],
    },
  ]);
}

test('multi-parts accelerator is parsed correctly', () => {
  const parsed = schema.parse({ 'keymap.tab1': 'Cmd+Shift+1' });
  expect(parsed).toStrictEqual({ 'keymap.tab1': 'Cmd+Shift+1' });
});

test('single-part accelerator is allowed for function keys', () => {
  const parsed = schema.parse({ 'keymap.tab1': 'F1' });
  expect(parsed).toStrictEqual({ 'keymap.tab1': 'F1' });
});

test('single-part accelerator is not allowed for non-function keys', () => {
  const parse = () => schema.parse({ 'keymap.tab1': '1' });
  expect(parse).toThrow(getZodError(missingModifierIssue('1')));
});

test('accelerator parts are sorted in the correct order', () => {
  const parsed = schema.parse({ 'keymap.tab1': 'Shift+1+Cmd' });
  expect(parsed).toStrictEqual({ 'keymap.tab1': 'Cmd+Shift+1' });
});

test('accelerator with whitespaces is parsed correctly', () => {
  const parsed = schema.parse({ 'keymap.tab1': ' Shift + 1 + Cmd ' });
  expect(parsed).toStrictEqual({ 'keymap.tab1': 'Cmd+Shift+1' });
});

test('empty accelerator is allowed', () => {
  const parsed = schema.parse({ 'keymap.tab1': '' });
  expect(parsed).toStrictEqual({ 'keymap.tab1': '' });
});

test('lowercase single characters are allowed and converted to uppercase', () => {
  const parsed = schema.parse({ 'keymap.tab1': 'Shift+Cmd+a' });
  expect(parsed).toStrictEqual({ 'keymap.tab1': 'Cmd+Shift+A' });
});

test('parsing fails when incorrect physical key is passed', () => {
  const parse = () => schema.parse({ 'keymap.tab1': 'Shift+12' });
  expect(parse).toThrow(getZodError(invalidKeyCodeIssue('12')));
});

test('parsing fails when multiple key codes are passed', () => {
  const parse = () => schema.parse({ 'keymap.tab1': 'Shift+Space+Tab' });
  expect(parse).toThrow(getZodError(invalidModifierIssue(['Space'])));
});

test('parsing fails when only modifiers are passed', () => {
  const parse = () => schema.parse({ 'keymap.tab1': 'Cmd+Shift' });
  expect(parse).toThrow(getZodError(invalidKeyCodeIssue('Shift')));
});

test('parsing fails when duplicate modifiers are passed', () => {
  const parse = () => schema.parse({ 'keymap.tab1': 'Cmd+I+Cmd' });
  expect(parse).toThrow(getZodError(duplicateModifierIssue()));
});
