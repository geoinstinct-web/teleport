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

import { QuickSshLoginPicker, QuickServerPicker } from './quickPickers';

// Jest doesn't let us selectively automock classes. See https://github.com/facebook/jest/issues/11995
//
// So instead for now we just mock all classes in the module and then do `jest.requireActual` when
// we need to have the actual class when writing tests for it.
jest.mock('./quickPickers');

afterEach(() => {
  jest.restoreAllMocks();
});

test("tsh ssh picker returns unknown command if it's missing the first positional arg", () => {
  const QuickSshLoginPickerMock = QuickSshLoginPicker as jest.MockedClass<
    typeof QuickSshLoginPicker
  >;
  const QuickServerPickerMock = QuickServerPicker as jest.MockedClass<
    typeof QuickServerPicker
  >;
  const ActualQuickTshSshPicker =
    jest.requireActual('./quickPickers').QuickTshSshPicker;

  const picker = new ActualQuickTshSshPicker(
    new QuickSshLoginPickerMock(undefined, undefined),
    new QuickServerPickerMock(undefined, undefined)
  );

  const emptyInput = picker.getAutocompleteResult('', 0);
  expect(emptyInput.command).toEqual({ kind: 'command.unknown' });

  const whitespace = picker.getAutocompleteResult(' ', 0);
  expect(whitespace.command).toEqual({ kind: 'command.unknown' });
});

test('tsh ssh picker returns unknown command if the input includes any additional flags', () => {
  const QuickSshLoginPickerMock = QuickSshLoginPicker as jest.MockedClass<
    typeof QuickSshLoginPicker
  >;
  const QuickServerPickerMock = QuickServerPicker as jest.MockedClass<
    typeof QuickServerPicker
  >;
  const ActualQuickTshSshPicker =
    jest.requireActual('./quickPickers').QuickTshSshPicker;

  const picker = new ActualQuickTshSshPicker(
    new QuickSshLoginPickerMock(undefined, undefined),
    new QuickServerPickerMock(undefined, undefined)
  );

  const fullFlagBefore = picker.getAutocompleteResult('--foo user@node', 0);
  expect(fullFlagBefore.command).toEqual({ kind: 'command.unknown' });

  const shortFlagBefore = picker.getAutocompleteResult('-p 22 user@node', 0);
  expect(shortFlagBefore.command).toEqual({ kind: 'command.unknown' });

  const commandAfter = picker.getAutocompleteResult('user@node ls', 0);
  expect(commandAfter.command).toEqual({ kind: 'command.unknown' });
});
