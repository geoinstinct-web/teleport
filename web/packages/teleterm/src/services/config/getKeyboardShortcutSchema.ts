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

import { z } from 'zod';

import { Platform } from 'teleterm/mainProcess/types';

export function invalidKeyCodeIssue(wrongKeyCode: string): z.IssueData {
  return {
    code: z.ZodIssueCode.custom,
    message: `"${wrongKeyCode}" cannot be used as a key code.`,
  };
}

export function invalidModifierIssue(
  wrongModifiers: string[],
  validModifiers: string[]
): z.IssueData {
  const formatList = (items: string[]) =>
    `${items.map(m => `"${m}"`).join(', ')}`;
  return {
    code: z.ZodIssueCode.custom,
    message: `${formatList(
      wrongModifiers
    )} cannot be used as a modifier. Valid modifiers are: ${formatList(
      validModifiers
    )}.`,
  };
}

export function duplicateModifierIssue(): z.IssueData {
  return {
    code: z.ZodIssueCode.custom,
    message: `Duplicate modifier found.`,
  };
}

export function missingModifierIssue(keyCode: string): z.IssueData {
  return {
    code: z.ZodIssueCode.custom,
    message: `"${keyCode}" must be used together with a modifier.`,
  };
}

export function getKeyboardShortcutSchema(platform: Platform) {
  const allowedModifiers = getSupportedModifiers(platform);

  return z
    .string()
    .transform(s => s.trim().split(/\s?\+\s?/))
    .transform(putModifiersFirst(allowedModifiers))
    .superRefine(validateKeyCodeAndModifiers(allowedModifiers))
    .transform(adjustCasing)
    .transform(s => s.join('+'));
}

function putModifiersFirst(
  allowedModifiers: string[]
): (tokens: string[]) => string[] {
  return tokens =>
    tokens.sort((a, b) => {
      if (allowedModifiers.indexOf(a) === -1) {
        return 1;
      }
      if (allowedModifiers.indexOf(b) === -1) {
        return -1;
      }
      return allowedModifiers.indexOf(a) - allowedModifiers.indexOf(b);
    });
}

/** Currently, works only for single characters.
 * An accelerator string is compared to a string generated from event properties
 * (so it should be case-insensitive too).
 * But what is more important, this string is used also for tooltips.
 * If we allow "CTRL+SHIFT+PAGEUP" then we cannot display it as "Ctrl+Shift+PageUp".
 */
function adjustCasing(tokens: string[]): string[] {
  return tokens.map(token => {
    if (token.length === 1) {
      return token.toUpperCase();
    }
    return token;
  });
}

function validateKeyCodeAndModifiers(
  allowedModifiers: string[]
): (tokens: string[], ctx: z.RefinementCtx) => void {
  return (tokens, ctx) => {
    // empty accelerator disables the shortcut
    if (tokens.join('') === '') {
      return z.NEVER;
    }

    const [keyCode, ...modifiers] = [...tokens].reverse();

    const keyCodeUppercase =
      keyCode.length === 1 // letters
        ? keyCode.toUpperCase()
        : keyCode;
    if (!ALLOWED_KEY_CODES.includes(keyCodeUppercase)) {
      ctx.addIssue(invalidKeyCodeIssue(keyCode));
    }

    if (modifiers.length !== new Set(modifiers).size) {
      ctx.addIssue(duplicateModifierIssue());
    }

    const invalidModifiers = modifiers.filter(
      modifier => !allowedModifiers.includes(modifier)
    );
    if (invalidModifiers.length) {
      ctx.addIssue(
        invalidModifierIssue(
          Array.from(new Set(invalidModifiers)),
          allowedModifiers
        )
      );
    }

    if (!FUNCTION_KEYS.includes(keyCode) && !modifiers.length) {
      ctx.addIssue(missingModifierIssue(keyCode));
    }
  };
}

/** Returns allowed modifiers for a given platform in the correct order. */
function getSupportedModifiers(platform: Platform): string[] {
  switch (platform) {
    case 'win32':
    case 'linux':
      return ['Ctrl', 'Alt', 'Shift'];
    case 'darwin':
      return ['Cmd', 'Ctrl', 'Option', 'Shift'];
  }
}

function generateRange(start: number, end: number): string[] {
  return new Array(end - start + 1)
    .fill(undefined)
    .map((_, i) => (i + start).toString());
}

const FUNCTION_KEYS = generateRange(1, 24).map(key => `F${key}`);

// subset of https://github.com/electron/electron/blob/49df19214ea3abaf0ad91adf3d374cba32abd521/docs/api/accelerator.md#available-key-codes
const ALLOWED_KEY_CODES = [
  ...generateRange(0, 9), // 0-9 range
  ...FUNCTION_KEYS,
  'A',
  'B',
  'C',
  'D',
  'E',
  'F',
  'G',
  'H',
  'I',
  'J',
  'K',
  'L',
  'M',
  'N',
  'O',
  'P',
  'Q',
  'R',
  'S',
  'T',
  'U',
  'V',
  'W',
  'X',
  'Y',
  'Z',
  'Space',
  'Tab',
  'CapsLock',
  'NumLock',
  'ScrollLock',
  'Backspace',
  'Delete',
  'Insert',
  'Enter',
  'Up',
  'Down',
  'Left',
  'Right',
  'Home',
  'End',
  'PageUp',
  'PageDown',
  'Escape',
  ',',
  '.',
  '/',
  '\\',
  '`',
  '-',
  '=',
  ';',
  "'",
  '[',
  ']',
];
