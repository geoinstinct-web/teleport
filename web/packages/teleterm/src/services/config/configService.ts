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

import { FileStorage } from 'teleterm/services/fileStorage';
import { Platform } from 'teleterm/mainProcess/types';

import { createConfigStore } from './configStore';

const createAppConfigSchema = (platform: Platform) => {
  const defaultKeymap = getDefaultKeymap(platform);
  const defaultTerminalFont = getDefaultTerminalFont(platform);

  // Important: all keys except 'usageReporting.enabled' are currently not
  // configurable by the user. Before we let the user configure them,
  // we need to set up some actual validation, so that for example
  // arbitrary CSS cannot be injected into the app through font settings.
  //
  // However, we want them to be in the config schema, so we included
  // them here, but we do not read their value from the stored config.
  return z.object({
    'usageReporting.enabled': z.boolean().default(false),
    'keymap.tab1': omitStoredConfigValue(
      z.string().default(defaultKeymap['tab1'])
    ),
    'keymap.tab2': omitStoredConfigValue(
      z.string().default(defaultKeymap['tab2'])
    ),
    'keymap.tab3': omitStoredConfigValue(
      z.string().default(defaultKeymap['tab3'])
    ),
    'keymap.tab4': omitStoredConfigValue(
      z.string().default(defaultKeymap['tab4'])
    ),
    'keymap.tab5': omitStoredConfigValue(
      z.string().default(defaultKeymap['tab5'])
    ),
    'keymap.tab6': omitStoredConfigValue(
      z.string().default(defaultKeymap['tab6'])
    ),
    'keymap.tab7': omitStoredConfigValue(
      z.string().default(defaultKeymap['tab7'])
    ),
    'keymap.tab8': omitStoredConfigValue(
      z.string().default(defaultKeymap['tab8'])
    ),
    'keymap.tab9': omitStoredConfigValue(
      z.string().default(defaultKeymap['tab9'])
    ),
    'keymap.closeTab': omitStoredConfigValue(
      z.string().default(defaultKeymap['closeTab'])
    ),
    'keymap.newTab': omitStoredConfigValue(
      z.string().default(defaultKeymap['newTab'])
    ),
    'keymap.previousTab': omitStoredConfigValue(
      z.string().default(defaultKeymap['previousTab'])
    ),
    'keymap.nextTab': omitStoredConfigValue(
      z.string().default(defaultKeymap['nextTab'])
    ),
    'keymap.openConnections': omitStoredConfigValue(
      z.string().default(defaultKeymap['openConnections'])
    ),
    'keymap.openClusters': omitStoredConfigValue(
      z.string().default(defaultKeymap['openClusters'])
    ),
    'keymap.openProfiles': omitStoredConfigValue(
      z.string().default(defaultKeymap['openProfiles'])
    ),
    'keymap.openQuickInput': omitStoredConfigValue(
      z.string().default(defaultKeymap['openQuickInput'])
    ),
    /**
     * This value can be provided by the user and is unsanitized. This means that it cannot be directly interpolated
     * in a styled component or used in CSS, as it may inject malicious CSS code.
     * Before using it, sanitize it with `CSS.escape` or pass it as a `style` prop.
     * Read more https://frontarm.com/james-k-nelson/how-can-i-use-css-in-js-securely/.
     */
    'terminal.fontFamily': z.string().default(defaultTerminalFont),
    'terminal.fontSize': z.number().int().min(1).max(256).default(15),
  });
};

const omitStoredConfigValue = <T>(schema: z.ZodType<T>) =>
  z.preprocess(() => undefined, schema);

export type AppConfig = z.infer<ReturnType<typeof createAppConfigSchema>>;

/**
 * Modifier keys must be defined in the following order:
 * Command-Control-Option-Shift for macOS
 * Ctrl-Alt-Shift for other platforms
 */
export type KeyboardShortcutAction =
  | 'tab1'
  | 'tab2'
  | 'tab3'
  | 'tab4'
  | 'tab5'
  | 'tab6'
  | 'tab7'
  | 'tab8'
  | 'tab9'
  | 'closeTab'
  | 'newTab'
  | 'previousTab'
  | 'nextTab'
  | 'openQuickInput'
  | 'openConnections'
  | 'openClusters'
  | 'openProfiles';

const getDefaultKeymap = (platform: Platform) => {
  switch (platform) {
    case 'win32':
      return {
        tab1: 'Ctrl+1',
        tab2: 'Ctrl+2',
        tab3: 'Ctrl+3',
        tab4: 'Ctrl+4',
        tab5: 'Ctrl+5',
        tab6: 'Ctrl+6',
        tab7: 'Ctrl+7',
        tab8: 'Ctrl+8',
        tab9: 'Ctrl+9',
        closeTab: 'Ctrl+W',
        newTab: 'Ctrl+T',
        previousTab: 'Ctrl+Shift+Tab',
        nextTab: 'Ctrl+Tab',
        openQuickInput: 'Ctrl+K',
        openConnections: 'Ctrl+P',
        openClusters: 'Ctrl+E',
        openProfiles: 'Ctrl+I',
      };
    case 'linux':
      return {
        tab1: 'Alt+1',
        tab2: 'Alt+2',
        tab3: 'Alt+3',
        tab4: 'Alt+4',
        tab5: 'Alt+5',
        tab6: 'Alt+6',
        tab7: 'Alt+7',
        tab8: 'Alt+8',
        tab9: 'Alt+9',
        closeTab: 'Ctrl+W',
        newTab: 'Ctrl+T',
        previousTab: 'Ctrl+Shift+Tab',
        nextTab: 'Ctrl+Tab',
        openQuickInput: 'Ctrl+K',
        openConnections: 'Ctrl+P',
        openClusters: 'Ctrl+E',
        openProfiles: 'Ctrl+I',
      };
    case 'darwin':
      return {
        tab1: 'Command+1',
        tab2: 'Command+2',
        tab3: 'Command+3',
        tab4: 'Command+4',
        tab5: 'Command+5',
        tab6: 'Command+6',
        tab7: 'Command+7',
        tab8: 'Command+8',
        tab9: 'Command+9',
        closeTab: 'Command+W',
        newTab: 'Command+T',
        previousTab: 'Control+Shift+Tab',
        nextTab: 'Control+Tab',
        openQuickInput: 'Command+K',
        openConnections: 'Command+P',
        openClusters: 'Command+E',
        openProfiles: 'Command+I',
      };
  }
};

function getDefaultTerminalFont(platform: Platform) {
  switch (platform) {
    case 'win32':
      return "'Consolas', 'Courier New', monospace";
    case 'linux':
      return "'Droid Sans Mono', 'Courier New', monospace, 'Droid Sans Fallback'";
    case 'darwin':
      return "Menlo, Monaco, 'Courier New', monospace";
  }
}

export function createConfigService(
  appConfigFileStorage: FileStorage,
  platform: Platform
) {
  return createConfigStore(
    createAppConfigSchema(platform),
    appConfigFileStorage
  );
}

export type ConfigService = ReturnType<typeof createConfigService>;
