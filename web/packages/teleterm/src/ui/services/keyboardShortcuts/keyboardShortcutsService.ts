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

import { Platform } from 'teleterm/mainProcess/types';
import {
  KeyboardShortcutsConfig,
  KeyboardShortcutType,
  ConfigService,
} from 'teleterm/services/config';

import {
  KeyboardShortcutEvent,
  KeyboardShortcutEventSubscriber,
} from './types';

export class KeyboardShortcutsService {
  private eventsSubscribers = new Set<KeyboardShortcutEventSubscriber>();
  private keysToShortcuts = new Map<string, KeyboardShortcutType>();

  constructor(
    private platform: Platform,
    private configService: ConfigService
  ) {
    const config = this.configService.get();
    this.recalculateKeysToShortcuts(config.keyboardShortcuts);
    this.attachKeydownHandler();
  }

  subscribeToEvents(subscriber: KeyboardShortcutEventSubscriber): void {
    this.eventsSubscribers.add(subscriber);
  }

  unsubscribeFromEvents(subscriber: KeyboardShortcutEventSubscriber): void {
    this.eventsSubscribers.delete(subscriber);
  }

  private attachKeydownHandler(): void {
    const handleKeydown = (event: KeyboardEvent): void => {
      const shortcutType = this.getShortcut(event);
      if (!shortcutType) {
        return;
      }

      event.preventDefault();
      event.stopPropagation();
      this.notifyEventsSubscribers({ type: shortcutType });
    };

    window.addEventListener('keydown', handleKeydown, {
      capture: true,
    });
  }

  private getShortcut(event: KeyboardEvent): KeyboardShortcutType | undefined {
    const getEventKey = () =>
      event.key.length === 1 ? event.key.toUpperCase() : event.key;

    const key = [...this.getPlatformModifierKeys(event), getEventKey()]
      .filter(Boolean)
      .join('-');

    return this.keysToShortcuts.get(key);
  }

  private getPlatformModifierKeys(event: KeyboardEvent): string[] {
    switch (this.platform) {
      case 'darwin':
        return [
          event.metaKey && 'Command',
          event.ctrlKey && 'Control',
          event.altKey && 'Option',
          event.shiftKey && 'Shift',
        ];
      default:
        return [
          event.ctrlKey && 'Ctrl',
          event.altKey && 'Alt',
          event.shiftKey && 'Shift',
        ];
    }
  }

  /**
   * Inverts shortcuts-keys pairs to allow accessing shortcut by a key
   */
  private recalculateKeysToShortcuts(
    toInvert: Partial<KeyboardShortcutsConfig>
  ): void {
    this.keysToShortcuts.clear();
    Object.entries(toInvert).forEach(([shortcutType, key]) => {
      this.keysToShortcuts.set(key, shortcutType as KeyboardShortcutType);
    });
  }

  private notifyEventsSubscribers(event: KeyboardShortcutEvent): void {
    this.eventsSubscribers.forEach(subscriber => subscriber(event));
  }
}
